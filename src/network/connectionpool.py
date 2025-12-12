"""
`BMConnectionPool` class definition
"""
import errno
import logging
import re
import socket
import sys
import time
import random
import threading
import queue

from network import asyncore_pollchoose as asyncore
from network import knownnodes
import protocol
import state
from bmconfigparser import config
from .connectionchooser import chooseConnection
from .node import Peer
from .proxy import Proxy
from .tcp import (
    bootstrap, Socks4aBMConnection, Socks5BMConnection,
    TCPConnection, TCPServer)
from .udp import UDPSocket

logger = logging.getLogger('default')


def _ends_with(s, tail):
    try:
        return s.endswith(tail)
    except:
        return s.decode("utf-8", "replace").endswith(tail)


class ThreadSafeDict(dict):
    """Thread-safe dictionary for connection storage"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._lock = threading.RLock()
    
    def __setitem__(self, key, value):
        with self._lock:
            super().__setitem__(key, value)
    
    def __delitem__(self, key):
        with self._lock:
            if key in self:
                super().__delitem__(key)
    
    def __getitem__(self, key):
        with self._lock:
            return super().__getitem__(key)
    
    def get(self, key, default=None):
        with self._lock:
            return super().get(key, default)
    
    def pop(self, key, default=None):
        with self._lock:
            return super().pop(key, default)
    
    def values(self):
        """Thread-safe values() that returns a copy"""
        with self._lock:
            return list(super().values()).copy()
    
    def items(self):
        """Thread-safe items() that returns a copy"""
        with self._lock:
            return list(super().items()).copy()
    
    def keys(self):
        """Thread-safe keys() that returns a copy"""
        with self._lock:
            return list(super().keys()).copy()
    
    def snapshot(self):
        """Get a thread-safe snapshot as a regular dict"""
        with self._lock:
            return dict(self)
    
    def clear(self):
        with self._lock:
            super().clear()


class BMConnectionPool(object):
    """Pool of all existing connections - thread safe version"""
    # pylint: disable=too-many-instance-attributes

    trustedPeer = None
    """
    If the trustedpeer option is specified in keys.dat then this will
    contain a Peer which will be connected to instead of using the
    addresses advertised by other peers.

    The expected use case is where the user has a trusted server where
    they run a Bitmessage daemon permanently. If they then run a second
    instance of the client on a local machine periodically when they want
    to check for messages it will sync with the network a lot faster
    without compromising security.
    """

    def __init__(self):
        asyncore.set_rates(
            config.safeGetInt(
                "bitmessagesettings", "maxdownloadrate"),
            config.safeGetInt(
                "bitmessagesettings", "maxuploadrate")
        )
        # Use thread-safe dictionaries
        self.outboundConnections = ThreadSafeDict()
        self.inboundConnections = ThreadSafeDict()
        self.listeningSockets = ThreadSafeDict()
        self.udpSockets = ThreadSafeDict()
        self.streams = []
        self._lastSpawned = 0
        self._spawnWait = 2
        self._bootstrapped = False
        self._loop_lock = threading.RLock()
        self._connection_queue = queue.Queue()
        self._closing = False

        trustedPeer = config.safeGet(
            'bitmessagesettings', 'trustedpeer')
        try:
            if trustedPeer:
                host, port = trustedPeer.split(':')
                self.trustedPeer = Peer(host, int(port))
        except ValueError:
            sys.exit(
                'Bad trustedpeer config setting! It should be set as'
                ' trustedpeer=<hostname>:<portnumber>'
            )

    def __len__(self):
        """Thread-safe length calculation"""
        return len(self.outboundConnections) + len(self.inboundConnections)

    def connections(self):
        """
        Thread-safe shortcut for combined list of connections from
        `inboundConnections` and `outboundConnections` dicts
        """
        inbound = self.inboundConnections.values()
        outbound = self.outboundConnections.values()
        return inbound + outbound

    def establishedConnections(self):
        """Thread-safe list of connections having fullyEstablished == True"""
        established = []
        # Safe iteration over copies
        for conn in self.inboundConnections.values():
            try:
                if conn.fullyEstablished:
                    established.append(conn)
            except (AttributeError, RuntimeError):
                pass
        
        for conn in self.outboundConnections.values():
            try:
                if conn.fullyEstablished:
                    established.append(conn)
            except (AttributeError, RuntimeError):
                pass
        
        return established

    def connectToStream(self, streamNumber):
        """Connect to a bitmessage stream"""
        with threading.Lock():
            if streamNumber not in self.streams:
                self.streams.append(streamNumber)

    def getConnectionByAddr(self, addr):
        """
        Return an (existing) connection object based on a `Peer` object
        (IP and port)
        """
        # Try inbound connections first
        conn = self.inboundConnections.get(addr)
        if conn:
            return conn
        
        # Try by host only
        if hasattr(addr, 'host'):
            conn = self.inboundConnections.get(addr.host)
            if conn:
                return conn
        
        # Try outbound connections
        conn = self.outboundConnections.get(addr)
        if conn:
            return conn
        
        # Try UDP sockets
        if hasattr(addr, 'host'):
            conn = self.udpSockets.get(addr.host)
            if conn:
                return conn
        
        raise KeyError(f"No connection found for {addr}")

    def isAlreadyConnected(self, nodeid):
        """Thread-safe check if we're already connected to this peer"""
        # Check inbound connections
        for conn in self.inboundConnections.values():
            try:
                if hasattr(conn, 'nodeid') and conn.nodeid == nodeid:
                    return True
            except (AttributeError, RuntimeError):
                continue
        
        # Check outbound connections
        for conn in self.outboundConnections.values():
            try:
                if hasattr(conn, 'nodeid') and conn.nodeid == nodeid:
                    return True
            except (AttributeError, RuntimeError):
                continue
        
        return False

    def addConnection(self, connection):
        """Thread-safe addition of a connection object to our internal dict"""
        if self._closing:
            return
            
        if isinstance(connection, UDPSocket):
            if hasattr(connection, 'listening') and hasattr(connection.listening, 'host'):
                self.udpSockets[connection.listening.host] = connection
            return
            
        if connection.isOutbound:
            if hasattr(connection, 'destination'):
                self.outboundConnections[connection.destination] = connection
        else:
            if hasattr(connection, 'destination'):
                if hasattr(connection.destination, 'host'):
                    # Store by full address
                    self.inboundConnections[connection.destination] = connection

    def removeConnection(self, connection):
        """Thread-safe removal of a connection from our internal dict"""
        if isinstance(connection, UDPSocket):
            if hasattr(connection, 'listening') and hasattr(connection.listening, 'host'):
                self.udpSockets.pop(connection.listening.host, None)
                
        elif isinstance(connection, TCPServer):
            if hasattr(connection, 'destination'):
                self.listeningSockets.pop(connection.destination, None)
                
        elif hasattr(connection, 'isOutbound') and connection.isOutbound:
            if hasattr(connection, 'destination'):
                self.outboundConnections.pop(connection.destination, None)
                
        else:
            if hasattr(connection, 'destination'):
                # Try to remove by full address first
                self.inboundConnections.pop(connection.destination, None)
                # Also try by host if it exists
                if hasattr(connection.destination, 'host'):
                    self.inboundConnections.pop(connection.destination.host, None)
        
        # Close the connection
        try:
            if hasattr(connection, 'handle_close'):
                connection.handle_close()
        except Exception as e:
            logger.debug(f"Error closing connection: {e}")

    def safe_remove_connection(self, connection):
        """Queue connection removal for thread-safe processing"""
        self._connection_queue.put(('remove', connection))

    def safe_add_connection(self, connection):
        """Queue connection addition for thread-safe processing"""
        self._connection_queue.put(('add', connection))

    def process_connection_queue(self):
        """Process queued connection operations"""
        try:
            while not self._connection_queue.empty():
                try:
                    op, connection = self._connection_queue.get_nowait()
                    if op == 'add':
                        self.addConnection(connection)
                    elif op == 'remove':
                        self.removeConnection(connection)
                    self._connection_queue.task_done()
                except queue.Empty:
                    break
        except Exception as e:
            logger.debug(f"Error processing connection queue: {e}")

    @staticmethod
    def getListeningIP():
        """What IP are we supposed to be listening on?"""
        if _ends_with(config.safeGet(
                "bitmessagesettings", "onionhostname", ""), ".onion"):
            host = config.safeGet(
                "bitmessagesettings", "onionbindip")
        else:
            host = '127.0.0.1'
        if (
            config.safeGetBoolean("bitmessagesettings", "sockslisten")
            or config.safeGet("bitmessagesettings", "socksproxytype")
            == "none"
        ):
            host = config.get("network", "bind")
        return host

    def startListening(self, bind=None):
        """Open a listening socket and start accepting connections on it"""
        if bind is None:
            bind = self.getListeningIP()
        port = config.safeGetInt("bitmessagesettings", "port")
        try:
            ls = TCPServer(host=bind, port=port)
            self.listeningSockets[ls.destination] = ls
            logger.info(f"Started listening on {bind}:{port}")
        except Exception as e:
            logger.error(f"Failed to start listening on {bind}:{port}: {e}")

    def startUDPSocket(self, bind=None):
        """
        Open an UDP socket. Depending on settings, it can either only
        accept incoming UDP packets, or also be able to send them.
        """
        try:
            if bind is None:
                host = self.getListeningIP()
                udpSocket = UDPSocket(host=host, announcing=True)
            else:
                if bind is False:
                    udpSocket = UDPSocket(announcing=False)
                else:
                    udpSocket = UDPSocket(host=bind, announcing=True)
            
            if hasattr(udpSocket, 'listening') and hasattr(udpSocket.listening, 'host'):
                self.udpSockets[udpSocket.listening.host] = udpSocket
                logger.info(f"Started UDP socket on {udpSocket.listening.host}")
        except Exception as e:
            logger.error(f"Failed to start UDP socket: {e}")

    def startBootstrappers(self):
        """Run the process of resolving bootstrap hostnames"""
        proxy_type = config.safeGet(
            'bitmessagesettings', 'socksproxytype')
        hostname = None
        if not proxy_type or proxy_type == 'none':
            connection_base = TCPConnection
        elif proxy_type == 'SOCKS5':
            connection_base = Socks5BMConnection
            hostname = random.choice([  # nosec B311
                'quzwelsuziwqgpt2.onion', None
            ])
        elif proxy_type == 'SOCKS4a':
            connection_base = Socks4aBMConnection
        else:
            return

        bootstrapper = bootstrap(connection_base)
        if not hostname:
            port = random.choice([8080, 8444])  # nosec B311
            hostname = 'bootstrap%s.bitmessage.org' % port
        else:
            port = 8444
        
        try:
            self.addConnection(bootstrapper(hostname, port))
            logger.info(f"Started bootstrapper to {hostname}:{port}")
        except Exception as e:
            logger.error(f"Failed to start bootstrapper: {e}")

    def loop(self):
        """Main Connectionpool's loop - thread safe version"""
        with self._loop_lock:
            if self._closing:
                return
                
            # Process queued connection operations
            self.process_connection_queue()
            
            # defaults to empty loop if outbound connections are maxed
            spawnConnections = False
            acceptConnections = True
            if config.safeGetBoolean(
                    'bitmessagesettings', 'dontconnect'):
                acceptConnections = False
            elif config.safeGetBoolean(
                    'bitmessagesettings', 'sendoutgoingconnections'):
                spawnConnections = True
                
            socksproxytype = config.safeGet(
                'bitmessagesettings', 'socksproxytype', '')
            onionsocksproxytype = config.safeGet(
                'bitmessagesettings', 'onionsocksproxytype', '')
            if (
                socksproxytype[:5] == 'SOCKS'
                and not config.safeGetBoolean(
                    'bitmessagesettings', 'sockslisten')
                and '.onion' not in config.safeGet(
                    'bitmessagesettings', 'onionhostname', '')
            ):
                acceptConnections = False

            if spawnConnections:
                if not knownnodes.knownNodesActual:
                    self.startBootstrappers()
                    knownnodes.knownNodesActual = True
                    
                if not self._bootstrapped:
                    self._bootstrapped = True
                    Proxy.proxy = (
                        config.safeGet(
                            'bitmessagesettings', 'sockshostname'),
                        config.safeGetInt(
                            'bitmessagesettings', 'socksport')
                    )
                    try:
                        if not onionsocksproxytype.startswith("SOCKS"):
                            raise ValueError
                        Proxy.onion_proxy = (
                            config.safeGet(
                                'network', 'onionsockshostname', None),
                            config.safeGet(
                                'network', 'onionsocksport', None)
                        )
                    except ValueError:
                        Proxy.onion_proxy = None
                        
                # Thread-safe established count
                established = 0
                for conn in self.outboundConnections.values():
                    try:
                        if conn.connected and conn.fullyEstablished:
                            established += 1
                    except (AttributeError, RuntimeError):
                        pass
                
                pending = len(self.outboundConnections) - established
                max_outbound = config.safeGetInt(
                    'bitmessagesettings', 'maxoutboundconnections')
                
                if established < max_outbound:
                    for i in range(
                            state.maximumNumberOfHalfOpenConnections - pending):
                        try:
                            if not self.streams:
                                continue
                            stream = random.choice(self.streams)  # nosec B311
                            chosen = self.trustedPeer or chooseConnection(stream)
                        except (ValueError, IndexError):
                            continue
                        
                        # Thread-safe checks
                        if chosen in self.outboundConnections:
                            continue
                        if chosen.host in self.inboundConnections:
                            continue
                        if chosen in state.ownAddresses:
                            continue
                        
                        # Network group check
                        host_network_group = protocol.network_group(chosen.host)
                        same_group = False
                        for conn in self.outboundConnections.values():
                            try:
                                if host_network_group == conn.network_group:
                                    same_group = True
                                    if chosen.host == conn.destination.host:
                                        knownnodes.decreaseRating(chosen)
                                    break
                            except (AttributeError, RuntimeError):
                                continue
                                
                        if same_group:
                            continue

                        try:
                            if _ends_with(chosen.host, ".onion") and Proxy.onion_proxy:
                                if onionsocksproxytype == "SOCKS5":
                                    self.addConnection(Socks5BMConnection(chosen))
                                elif onionsocksproxytype == "SOCKS4a":
                                    self.addConnection(Socks4aBMConnection(chosen))
                            elif socksproxytype == "SOCKS5":
                                self.addConnection(Socks5BMConnection(chosen))
                            elif socksproxytype == "SOCKS4a":
                                self.addConnection(Socks4aBMConnection(chosen))
                            else:
                                self.addConnection(TCPConnection(chosen))
                        except socket.error as e:
                            if e.errno == errno.ENETUNREACH:
                                continue
                            logger.debug(f"Socket error connecting to {chosen}: {e}")

                        self._lastSpawned = time.time()
            else:
                # Close all outbound connections
                for conn in self.outboundConnections.values():
                    try:
                        conn.handle_close()
                    except Exception as e:
                        logger.debug(f"Error closing connection: {e}")

            if acceptConnections:
                if not self.listeningSockets:
                    if config.safeGet('network', 'bind') == '':
                        self.startListening()
                    else:
                        for bind in re.sub(
                            r'[^\w.]+', ' ',
                            config.safeGet('network', 'bind')
                        ).split():
                            self.startListening(bind)
                    logger.info('Listening for incoming connections.')
                    
                if not self.udpSockets:
                    if config.safeGet('network', 'bind') == '':
                        self.startUDPSocket()
                    else:
                        for bind in re.sub(
                            r'[^\w.]+', ' ',
                            config.safeGet('network', 'bind')
                        ).split():
                            self.startUDPSocket(bind)
                        self.startUDPSocket(False)
                    logger.info('Starting UDP socket(s).')
            else:
                if self.listeningSockets:
                    for conn in self.listeningSockets.values():
                        try:
                            conn.close_reason = "Stopping listening"
                            conn.accepting = conn.connecting = conn.connected = False
                        except Exception as e:
                            logger.debug(f"Error stopping listener: {e}")
                    logger.info('Stopped listening for incoming connections.')
                    
                if self.udpSockets:
                    for conn in self.udpSockets.values():
                        try:
                            conn.close_reason = "Stopping UDP socket"
                            conn.accepting = conn.connecting = conn.connected = False
                        except Exception as e:
                            logger.debug(f"Error stopping UDP socket: {e}")
                    logger.info('Stopped udp sockets.')

            loopTime = float(self._spawnWait)
            if self._lastSpawned < time.time() - self._spawnWait:
                loopTime = 2.0
                
            # Run asyncore loop with error handling
            try:
                asyncore.loop(timeout=loopTime, count=1000)
            except RuntimeError as e:
                if "dictionary changed size during iteration" in str(e):
                    logger.warning("Asyncore map iteration error, recovering...")
                    time.sleep(0.1)
                else:
                    raise

            # Check for timeouts and close connections
            reaper = []
            current_time = time.time()
            
            # Check all connections
            all_connections = (
                list(self.inboundConnections.values()) + 
                list(self.outboundConnections.values()) +
                list(self.listeningSockets.values()) + 
                list(self.udpSockets.values())
            )
            
            for conn in all_connections:
                try:
                    # Check if connection should be closed
                    if not (conn.accepting or conn.connecting or conn.connected):
                        reaper.append(conn)
                    elif hasattr(conn, 'state') and conn.state == "close":
                        reaper.append(conn)
                    elif hasattr(conn, 'fullyEstablished'):
                        minTx = current_time - 20
                        if conn.fullyEstablished:
                            minTx -= 300 - 20
                        if hasattr(conn, 'lastTx') and conn.lastTx < minTx:
                            if conn.fullyEstablished:
                                if hasattr(conn, 'append_write_buf'):
                                    conn.append_write_buf(protocol.CreatePacket(b'ping'))
                            else:
                                conn.close_reason = f"Timeout ({int(current_time - conn.lastTx)}s)"
                                if hasattr(conn, 'set_state'):
                                    conn.set_state("close")
                except (AttributeError, RuntimeError) as e:
                    logger.debug(f"Error checking connection: {e}")
                    reaper.append(conn)

            # Remove connections marked for removal
            for conn in reaper:
                try:
                    self.removeConnection(conn)
                except Exception as e:
                    logger.debug(f"Error removing connection: {e}")

    def close_all_connections(self):
        """Thread-safe closing of all connections"""
        self._closing = True
        
        # Close listening sockets
        for conn in self.listeningSockets.values():
            try:
                conn.close()
            except:
                pass
        
        # Close UDP sockets
        for conn in self.udpSockets.values():
            try:
                conn.close()
            except:
                pass
        
        # Close inbound connections
        for conn in self.inboundConnections.values():
            try:
                conn.close()
            except:
                pass
        
        # Close outbound connections
        for conn in self.outboundConnections.values():
            try:
                conn.close()
            except:
                pass
        
        # Clear all dictionaries
        self.listeningSockets.clear()
        self.udpSockets.clear()
        self.inboundConnections.clear()
        self.outboundConnections.clear()
        
        # Close all asyncore sockets as fallback
        try:
            asyncore.close_all()
        except:
            pass


pool = BMConnectionPool()
