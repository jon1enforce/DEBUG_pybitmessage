"""
`BMConnectionPool` class definition with comprehensive logging and error handling
"""
import errno
import logging
import re
import socket
import sys
import time
import random
from typing import Dict, List, Optional, Union

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


def _ends_with(s: Union[str, bytes], tail: str) -> bool:
    """
    Helper function to check if string/bytes ends with tail
    with proper encoding handling
    """
    try:
        logger.debug("DEBUG: Checking if %s ends with %s", s, tail)
        return s.endswith(tail)
    except (AttributeError, UnicodeDecodeError):
        try:
            decoded = s.decode("utf-8", "replace")
            logger.debug("DEBUG: Decoded string for endswith check: %s", decoded)
            return decoded.endswith(tail)
        except Exception as e:
            logger.error("ERROR: Failed to check string ending: %s", e)
            return False


class BMConnectionPool(object):
    """Pool of all existing connections with comprehensive management"""
    # pylint: disable=too-many-instance-attributes

    trustedPeer: Optional[Peer] = None
    """
    If the trustedpeer option is specified in keys.dat then this will
    contain a Peer which will be connected to instead of using the
    addresses advertised by other peers.
    """

    def __init__(self):
        """Initialize connection pool with configuration"""
        logger.debug("DEBUG: Initializing BMConnectionPool instance")
        
        try:
            max_download = config.safeGetInt("bitmessagesettings", "maxdownloadrate")
            max_upload = config.safeGetInt("bitmessagesettings", "maxuploadrate")
            logger.debug("DEBUG: Setting asyncore rates - download: %s, upload: %s", 
                        max_download, max_upload)
            asyncore.set_rates(max_download, max_upload)
        except Exception as e:
            logger.error("ERROR: Failed to set asyncore rates: %s", e)
            max_download = max_upload = 0  # Default values if config fails
        
        self.outboundConnections: Dict[Peer, TCPConnection] = {}
        self.inboundConnections: Dict[Union[Peer, str], TCPConnection] = {}
        self.listeningSockets: Dict[Peer, TCPServer] = {}
        self.udpSockets: Dict[str, UDPSocket] = {}
        self.streams: List[int] = []
        self._lastSpawned: float = 0
        self._spawnWait: int = 2
        self._bootstrapped: bool = False
        logger.debug("DEBUG: Initialized empty connection pools")

        try:
            trustedPeer = config.safeGet('bitmessagesettings', 'trustedpeer')
            if trustedPeer:
                logger.debug("DEBUG: Processing trustedpeer config: %s", trustedPeer)
                try:
                    host, port = trustedPeer.split(':')
                    self.trustedPeer = Peer(host, int(port))
                    logger.info("INFO: Set trusted peer: %s:%s", host, port)
                except ValueError as e:
                    logger.error("ERROR: Invalid trustedpeer format: %s - %s", trustedPeer, e)
                    sys.exit(
                        'Bad trustedpeer config setting! It should be set as'
                        ' trustedpeer=<hostname>:<portnumber>'
                    )
        except Exception as e:
            logger.error("ERROR: Failed to process trustedpeer config: %s", e)
            self.trustedPeer = None

    def __len__(self) -> int:
        """Return total number of connections"""
        total = len(self.outboundConnections) + len(self.inboundConnections)
        logger.debug("DEBUG: Total connections count - outbound: %d, inbound: %d, total: %d",
                    len(self.outboundConnections), len(self.inboundConnections), total)
        return total

    def connections(self) -> List[TCPConnection]:
        """
        Return combined list of connections from inbound and outbound dicts
        """
        connections = list(self.inboundConnections.values()) + list(self.outboundConnections.values())
        logger.debug("DEBUG: Getting all connections - inbound: %d, outbound: %d, total: %d",
                    len(self.inboundConnections), len(self.outboundConnections), len(connections))
        return connections

    def establishedConnections(self) -> List[TCPConnection]:
        """Return list of fully established connections"""
        established = [x for x in self.connections() if x.fullyEstablished]
        logger.debug("DEBUG: Established connections count: %d", len(established))
        return established

    def connectToStream(self, streamNumber: int) -> None:
        """Add a stream number to the list of streams we're connected to"""
        if streamNumber not in self.streams:
            self.streams.append(streamNumber)
            logger.info("INFO: Added stream %d to active streams", streamNumber)
        else:
            logger.debug("DEBUG: Stream %d already in active streams", streamNumber)

    def getConnectionByAddr(self, addr: Peer) -> Union[TCPConnection, UDPSocket]:
        """
        Return an existing connection object based on a Peer object
        Raises KeyError if not found
        """
        logger.debug("DEBUG: Looking up connection by address: %s:%d", addr.host, addr.port)
        
        try:
            conn = self.inboundConnections[addr]
            logger.debug("DEBUG: Found inbound connection by full address")
            return conn
        except KeyError:
            logger.debug("DEBUG: No inbound connection by full address")
            pass
        
        try:
            conn = self.inboundConnections[addr.host]
            logger.debug("DEBUG: Found inbound connection by host only")
            return conn
        except (KeyError, AttributeError):
            logger.debug("DEBUG: No inbound connection by host only")
            pass
        
        try:
            conn = self.outboundConnections[addr]
            logger.debug("DEBUG: Found outbound connection by full address")
            return conn
        except KeyError:
            logger.debug("DEBUG: No outbound connection by full address")
            pass
        
        try:
            conn = self.udpSockets[addr.host]
            logger.debug("DEBUG: Found UDP socket by host")
            return conn
        except (KeyError, AttributeError):
            logger.debug("DEBUG: No UDP socket found by host")
            pass
        
        logger.warning("WARNING: No connection found for address %s:%d", addr.host, addr.port)
        raise KeyError(f"No connection found for {addr.host}:{addr.port}")

    def isAlreadyConnected(self, nodeid: str) -> bool:
        """Check if we're already connected to a peer with given nodeid"""
        logger.debug("DEBUG: Checking connection to nodeid: %s", nodeid)
        
        for conn in self.connections():
            try:
                if nodeid == conn.nodeid:
                    logger.debug("DEBUG: Found existing connection to nodeid %s", nodeid)
                    return True
            except AttributeError:
                logger.debug("DEBUG: Connection %s has no nodeid attribute", conn)
                continue
        
        logger.debug("DEBUG: No existing connection to nodeid %s found", nodeid)
        return False

    def addConnection(self, connection: Union[TCPConnection, UDPSocket, TCPServer]) -> None:
        """Add a connection object to the appropriate internal dict"""
        logger.debug("DEBUG: Adding connection of type %s", type(connection).__name__)
        
        try:
            if isinstance(connection, UDPSocket):
                logger.info("INFO: Adding UDP socket for %s", connection.listening.host)
                self.udpSockets[connection.listening.host] = connection
                return
            
            if connection.isOutbound:
                logger.info("INFO: Adding outbound connection to %s:%d",
                           connection.destination.host, connection.destination.port)
                self.outboundConnections[connection.destination] = connection
            else:
                if connection.destination.host in self.inboundConnections:
                    logger.info("INFO: Adding inbound connection by destination %s:%d",
                               connection.destination.host, connection.destination.port)
                    self.inboundConnections[connection.destination] = connection
                else:
                    logger.info("INFO: Adding inbound connection by host %s",
                               connection.destination.host)
                    self.inboundConnections[connection.destination.host] = connection
        except Exception as e:
            logger.error("ERROR: Failed to add connection: %s", e)
            raise

    def removeConnection(self, connection: Union[TCPConnection, UDPSocket, TCPServer]) -> None:
        """Remove a connection from our internal dicts and close it"""
        logger.debug("DEBUG: Removing connection of type %s", type(connection).__name__)
        
        try:
            if isinstance(connection, UDPSocket):
                logger.info("INFO: Removing UDP socket for %s", connection.listening.host)
                try:
                    del self.udpSockets[connection.listening.host]
                except KeyError:
                    logger.warning("WARNING: UDP socket not found in udpSockets")
            
            elif isinstance(connection, TCPServer):
                logger.info("INFO: Removing TCP server for %s:%d",
                          connection.destination.host, connection.destination.port)
                try:
                    del self.listeningSockets[Peer(
                        connection.destination.host, connection.destination.port)]
                except KeyError:
                    logger.warning("WARNING: TCPServer not found in listeningSockets")
            
            elif connection.isOutbound:
                logger.info("INFO: Removing outbound connection to %s:%d",
                          connection.destination.host, connection.destination.port)
                try:
                    del self.outboundConnections[connection.destination]
                except KeyError:
                    logger.warning("WARNING: Outbound connection not found in pool")
            
            else:
                logger.info("INFO: Removing inbound connection from %s:%d",
                          connection.destination.host, connection.destination.port)
                try:
                    del self.inboundConnections[connection.destination]
                except KeyError:
                    try:
                        del self.inboundConnections[connection.destination.host]
                    except KeyError:
                        logger.warning("WARNING: Inbound connection not found in pool")
            
            logger.debug("DEBUG: Closing connection")
            connection.handle_close()
        except Exception as e:
            logger.error("ERROR: Failed to remove connection: %s", e)
            raise

    @staticmethod
    def getListeningIP() -> str:
        """Determine which IP we should listen on based on configuration"""
        try:
            onionhost = config.safeGet("bitmessagesettings", "onionhostname", "")
            logger.debug("DEBUG: Onion hostname: %s", onionhost)
            
            if _ends_with(onionhost, ".onion"):
                host = config.safeGet("bitmessagesettings", "onionbindip")
                logger.info("INFO: Using onion bind IP: %s", host)
            else:
                host = '127.0.0.1'
                logger.debug("DEBUG: Using default localhost IP")
            
            if (config.safeGetBoolean("bitmessagesettings", "sockslisten") or 
                config.safeGet("bitmessagesettings", "socksproxytype") == "none"):
                host = config.get("network", "bind")
                logger.info("INFO: Using network bind IP: %s", host)
            
            return host
        except Exception as e:
            logger.error("ERROR: Failed to determine listening IP: %s", e)
            return '127.0.0.1'  # Fallback to localhost

    def startListening(self, bind: Optional[str] = None) -> None:
        """Open a listening socket and start accepting connections"""
        try:
            if bind is None:
                bind = self.getListeningIP()
            
            port = config.safeGetInt("bitmessagesettings", "port")
            logger.info("INFO: Starting listening socket on %s:%d", bind, port)
            
            try:
                ls = TCPServer(host=bind, port=port)
                self.listeningSockets[ls.destination] = ls
                logger.info("INFO: Successfully started listening on %s:%d", bind, port)
            except socket.error as e:
                logger.error("ERROR: Failed to start listening socket: %s", e)
                if e.errno == errno.EADDRINUSE:
                    logger.error("ERROR: Port %d is already in use", port)
                raise
        except Exception as e:
            logger.error("ERROR: Failed to start listening socket: %s", e)
            raise

    def startUDPSocket(self, bind: Optional[Union[str, bool]] = None) -> None:
        """
        Open an UDP socket. Depending on settings, it can either only
        accept incoming UDP packets, or also be able to send them.
        """
        try:
            if bind is None:
                host = self.getListeningIP()
                logger.info("INFO: Starting UDP socket on %s (announcing)", host)
                udpSocket = UDPSocket(host=host, announcing=True)
            else:
                if bind is False:
                    logger.info("INFO: Starting UDP socket (non-announcing)")
                    udpSocket = UDPSocket(announcing=False)
                else:
                    logger.info("INFO: Starting UDP socket on %s (announcing)", bind)
                    udpSocket = UDPSocket(host=bind, announcing=True)
            
            self.udpSockets[udpSocket.listening.host] = udpSocket
            logger.info("INFO: UDP socket started successfully on %s", 
                       udpSocket.listening.host)
        except Exception as e:
            logger.error("ERROR: Failed to start UDP socket: %s", e)
            raise

    def startBootstrappers(self) -> None:
        """Run the process of resolving bootstrap hostnames"""
        logger.info("INFO: Starting bootstrappers")
        
        try:
            proxy_type = config.safeGet('bitmessagesettings', 'socksproxytype')
            logger.debug("DEBUG: Proxy type: %s", proxy_type)
            
            hostname = None
            if not proxy_type or proxy_type == 'none':
                connection_base = TCPConnection
                logger.debug("DEBUG: Using direct TCP connection")
            elif proxy_type == 'SOCKS5':
                connection_base = Socks5BMConnection
                hostname = random.choice(['quzwelsuziwqgpt2.onion', None])  # nosec B311
                logger.debug("DEBUG: Using SOCKS5 proxy with hostname: %s", hostname)
            elif proxy_type == 'SOCKS4a':
                connection_base = Socks4aBMConnection
                logger.debug("DEBUG: Using SOCKS4a proxy")
            else:
                logger.error("ERROR: Invalid proxy type: %s", proxy_type)
                return

            bootstrapper = bootstrap(connection_base)
            if not hostname:
                port = random.choice([8080, 8444])  # nosec B311
                hostname = 'bootstrap%s.bitmessage.org' % port
                logger.debug("DEBUG: Using bootstrap hostname: %s", hostname)
            else:
                port = 8444
                logger.debug("DEBUG: Using fixed port: %d", port)
            
            self.addConnection(bootstrapper(hostname, port))
            logger.info("INFO: Added bootstrapper connection to %s:%d", hostname, port)
        except Exception as e:
            logger.error("ERROR: Failed to start bootstrappers: %s", e)
            raise

    def loop(self) -> None:  # pylint: disable=too-many-branches,too-many-statements
        """Main Connectionpool's loop with comprehensive logging"""
        logger.debug("DEBUG: Starting main connection pool loop")
        
        try:
            spawnConnections = False
            acceptConnections = True
            
            logger.debug("DEBUG: Checking network configuration...")
            logger.debug("DEBUG: dontconnect: %s", 
                        config.safeGetBoolean('bitmessagesettings', 'dontconnect'))
            logger.debug("DEBUG: sendoutgoingconnections: %s",
                        config.safeGetBoolean('bitmessagesettings', 'sendoutgoingconnections'))
            logger.debug("DEBUG: socksproxytype: %s",
                        config.safeGet('bitmessagesettings', 'socksproxytype', ''))
            
            if config.safeGetBoolean('bitmessagesettings', 'dontconnect'):
                logger.info("INFO: Networking disabled by dontconnect setting")
            elif not config.safeGetBoolean('bitmessagesettings', 'sendoutgoingconnections'):
                logger.info("INFO: Outgoing connections disabled by sendoutgoingconnections setting")

            socksproxytype = config.safeGet('bitmessagesettings', 'socksproxytype', '')
            onionsocksproxytype = config.safeGet('bitmessagesettings', 'onionsocksproxytype', '')
            if (socksproxytype[:5] == 'SOCKS' and 
                not config.safeGetBoolean('bitmessagesettings', 'sockslisten') and 
                '.onion' not in config.safeGet('bitmessagesettings', 'onionhostname', '')):
                acceptConnections = False
                logger.info("INFO: SOCKS proxy detected - not accepting connections")

            if spawnConnections:
                if not knownnodes.knownNodesActual:
                    logger.info("INFO: No known nodes - starting bootstrappers")
                    self.startBootstrappers()
                    knownnodes.knownNodesActual = True

                if not self._bootstrapped:
                    logger.info("INFO: First bootstrapping")
                    self._bootstrapped = True
                    Proxy.proxy = (
                        config.safeGet('bitmessagesettings', 'sockshostname'),
                        config.safeGetInt('bitmessagesettings', 'socksport')
                    )
                    logger.info("INFO: Set main proxy: %s:%d", Proxy.proxy[0], Proxy.proxy[1])
                    
                    try:
                        if not onionsocksproxytype.startswith("SOCKS"):
                            raise ValueError("Invalid onion proxy type")
                        Proxy.onion_proxy = (
                            config.safeGet('network', 'onionsockshostname', None),
                            config.safeGet('network', 'onionsocksport', None)
                        )
                        logger.info("INFO: Set onion proxy: %s:%s", 
                                  Proxy.onion_proxy[0], Proxy.onion_proxy[1])
                    except ValueError as e:
                        Proxy.onion_proxy = None
                        logger.debug("DEBUG: No valid onion proxy configured: %s", e)

                established = sum(1 for c in self.outboundConnections.values() 
                                if (c.connected and c.fullyEstablished))
                pending = len(self.outboundConnections) - established
                logger.info("INFO: Connection stats - established: %d, pending: %d", 
                           established, pending)

                if established < config.safeGetInt('bitmessagesettings', 'maxoutboundconnections'):
                    logger.info("INFO: Need more connections (current: %d, max: %d)", 
                              established, config.safeGetInt('bitmessagesettings', 'maxoutboundconnections'))
                    
                    for i in range(state.maximumNumberOfHalfOpenConnections - pending):
                        try:
                            chosen = self.trustedPeer or chooseConnection(random.choice(self.streams))  # nosec B311
                            logger.debug("DEBUG: Chosen connection: %s:%d", chosen.host, chosen.port)
                        except (ValueError, IndexError) as e:
                            logger.debug("DEBUG: No valid connection chosen: %s", e)
                            continue

                        if chosen in self.outboundConnections:
                            logger.debug("DEBUG: Already connected to chosen outbound")
                            continue
                        if chosen.host in self.inboundConnections:
                            logger.debug("DEBUG: Already connected to chosen inbound")
                            continue
                        if chosen in state.ownAddresses:
                            logger.debug("DEBUG: Chosen connection is self")
                            continue

                        host_network_group = protocol.network_group(chosen.host)
                        same_group = False
                        for j in self.outboundConnections.values():
                            if host_network_group == j.network_group:
                                same_group = True
                                if chosen.host == j.destination.host:
                                    knownnodes.decreaseRating(chosen)
                                    logger.debug("DEBUG: Decreased rating for duplicate host")
                                break
                        if same_group:
                            logger.debug("DEBUG: Same network group - skipping")
                            continue

                        try:
                            if _ends_with(chosen.host, ".onion") and Proxy.onion_proxy:
                                logger.debug("DEBUG: Creating onion connection")
                                if onionsocksproxytype == "SOCKS5":
                                    self.addConnection(Socks5BMConnection(chosen))
                                elif onionsocksproxytype == "SOCKS4a":
                                    self.addConnection(Socks4aBMConnection(chosen))
                            elif socksproxytype == "SOCKS5":
                                logger.debug("DEBUG: Creating SOCKS5 connection")
                                self.addConnection(Socks5BMConnection(chosen))
                            elif socksproxytype == "SOCKS4a":
                                logger.debug("DEBUG: Creating SOCKS4a connection")
                                self.addConnection(Socks4aBMConnection(chosen))
                            else:
                                logger.debug("DEBUG: Creating direct TCP connection")
                                self.addConnection(TCPConnection(chosen))
                        except socket.error as e:
                            if e.errno == errno.ENETUNREACH:
                                logger.warning("WARNING: Network unreachable: %s", e)
                                continue
                            raise

                        self._lastSpawned = time.time()
                        logger.debug("DEBUG: Updated last spawned time: %s", self._lastSpawned)
            else:
                logger.info("INFO: Closing all outbound connections")
                for conn in self.outboundConnections.values():
                    try:
                        conn.handle_close()
                    except Exception as e:
                        logger.error("ERROR: Failed to close connection: %s", e)

            if acceptConnections:
                if not self.listeningSockets:
                    if config.safeGet('network', 'bind') == '':
                        logger.info("INFO: Starting default listening socket")
                        self.startListening()
                    else:
                        binds = re.sub(r'[^\w.]+', ' ', config.safeGet('network', 'bind')).split()
                        logger.info("INFO: Starting listening sockets on: %s", binds)
                        for bind in binds:
                            try:
                                self.startListening(bind)
                            except Exception as e:
                                logger.error("ERROR: Failed to start listening on %s: %s", bind, e)
                                continue
                    logger.info('INFO: Listening for incoming connections.')

                if not self.udpSockets:
                    if config.safeGet('network', 'bind') == '':
                        logger.info("INFO: Starting default UDP socket")
                        self.startUDPSocket()
                    else:
                        binds = re.sub(r'[^\w.]+', ' ', config.safeGet('network', 'bind')).split()
                        logger.info("INFO: Starting UDP sockets on: %s", binds)
                        for bind in binds:
                            try:
                                self.startUDPSocket(bind)
                            except Exception as e:
                                logger.error("ERROR: Failed to start UDP socket on %s: %s", bind, e)
                                continue
                        try:
                            self.startUDPSocket(False)
                        except Exception as e:
                            logger.error("ERROR: Failed to start non-announcing UDP socket: %s", e)
                    logger.info('INFO: UDP socket(s) started.')
            else:
                if self.listeningSockets:
                    logger.info("INFO: Closing listening sockets")
                    for ls in self.listeningSockets.values():
                        try:
                            ls.close_reason = "Stopping listening"
                            ls.accepting = ls.connecting = ls.connected = False
                        except Exception as e:
                            logger.error("ERROR: Failed to close listening socket: %s", e)
                    logger.info('INFO: Stopped listening for incoming connections.')
                if self.udpSockets:
                    logger.info("INFO: Closing UDP sockets")
                    for udp in self.udpSockets.values():
                        try:
                            udp.close_reason = "Stopping UDP socket"
                            udp.accepting = udp.connecting = udp.connected = False
                        except Exception as e:
                            logger.error("ERROR: Failed to close UDP socket: %s", e)
                    logger.info('INFO: Stopped UDP sockets.')

            loopTime = float(self._spawnWait)
            if self._lastSpawned < time.time() - self._spawnWait:
                loopTime = 2.0
            logger.debug("DEBUG: Running asyncore loop with timeout: %.1f", loopTime)
            asyncore.loop(timeout=loopTime, count=1000)

            reaper = []
            minTx = time.time() - 20
            logger.debug("DEBUG: Checking for stale connections (minTx: %s)", minTx)
            
            for conn in self.connections():
                try:
                    conn_minTx = minTx
                    if conn.fullyEstablished:
                        conn_minTx -= 300 - 20
                        logger.debug("DEBUG: Connection %s is fully established", conn)
                    
                    if conn.lastTx < conn_minTx:
                        if conn.fullyEstablished:
                            logger.debug("DEBUG: Sending ping to connection %s", conn)
                            conn.append_write_buf(protocol.CreatePacket(b'ping'))
                        else:
                            timeout = time.time() - conn.lastTx
                            conn.close_reason = "Timeout (%is)" % timeout
                            conn.set_state("close")
                            logger.debug("DEBUG: Timing out connection %s (lastTx: %s)", 
                                       conn, conn.lastTx)
                except Exception as e:
                    logger.error("ERROR: Failed to check connection %s: %s", conn, e)

            for item in (self.connections() + list(self.listeningSockets.values()) + 
                        list(self.udpSockets.values())):
                try:
                    if not (item.accepting or item.connecting or item.connected):
                        logger.debug("DEBUG: Adding to reaper: %s", item)
                        reaper.append(item)
                    else:
                        try:
                            if item.state == "close":
                                logger.debug("DEBUG: Adding closed connection to reaper: %s", item)
                                reaper.append(item)
                        except AttributeError:
                            pass
                except Exception as e:
                    logger.error("ERROR: Failed to process item %s for reaping: %s", item, e)

            logger.info("INFO: Reaping %d connections/sockets", len(reaper))
            for item in reaper:
                try:
                    self.removeConnection(item)
                except Exception as e:
                    logger.error("ERROR: Failed to reap connection %s: %s", item, e)

        except Exception as e:
            logger.critical("CRITICAL: Error in connection pool loop: %s", e)
            raise


# Global connection pool instance
pool = BMConnectionPool()
