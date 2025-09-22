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

# Statt direkter socket Aufrufe, verwende helpers
from .helpers import resolve_hostname, get_socket_family, is_openbsd, openbsd_socket_compat

def _ends_with(s, tail):
    try:
        result = s.endswith(tail)
    except:
        # OpenBSD-kompatible Lösung
        try:
            result = s.decode("utf-8", "replace").endswith(tail)
        except (UnicodeDecodeError, AttributeError):
            result = str(s).endswith(tail)
    logger.debug("DEBUG: _ends_with check - string: %s, tail: %s, result: %s", s, tail, result)
    return result

class BMConnectionPool(object):
    """Pool of all existing connections"""
    # pylint: disable=too-many-instance-attributes

    trustedPeer = None

    def __init__(self):
        logger.debug("DEBUG: Initializing BMConnectionPool")
        max_download = config.safeGetInt("bitmessagesettings", "maxdownloadrate")
        max_upload = config.safeGetInt("bitmessagesettings", "maxuploadrate")
        logger.debug("DEBUG: Setting asyncore rates - download: %s, upload: %s", max_download, max_upload)
        asyncore.set_rates(max_download, max_upload)
        
        self.outboundConnections = {}
        self.inboundConnections = {}
        self.listeningSockets = {}
        self.udpSockets = {}
        self.streams = []
        self._lastSpawned = 0
        self._spawnWait = 2
        self._bootstrapped = False
        logger.debug("DEBUG: Initialized empty connection pools")

        trustedPeer = config.safeGet('bitmessagesettings', 'trustedpeer')
        try:
            if trustedPeer:
                host, port = trustedPeer.split(':')
                self.trustedPeer = Peer(host, int(port))
                logger.debug("DEBUG: Set trusted peer: %s:%s", host, port)
        except ValueError:
            logger.error("DEBUG: Invalid trustedpeer config: %s", trustedPeer)
            sys.exit(
                'Bad trustedpeer config setting! It should be set as'
                ' trustedpeer=<hostname>:<portnumber>'
            )

    def __len__(self):
        total = len(self.outboundConnections) + len(self.inboundConnections)
        logger.debug("DEBUG: Total connections count: %s", total)
        return total

    def connections(self):
        connections = list(self.inboundConnections.values()) + list(self.outboundConnections.values())
        logger.debug("DEBUG: Getting all connections - count: %s", len(connections))
        return connections

    def establishedConnections(self):
        established = [x for x in self.connections() if x.fullyEstablished]
        logger.debug("DEBUG: Getting established connections - count: %s", len(established))
        return established

    def connectToStream(self, streamNumber):
        logger.debug("DEBUG: Adding stream %s to streams list", streamNumber)
        self.streams.append(streamNumber)

    def getConnectionByAddr(self, addr):
        logger.debug("DEBUG: Looking up connection by address: %s", addr)
        try:
            conn = self.inboundConnections[addr]
            logger.debug("DEBUG: Found inbound connection by addr")
            return conn
        except KeyError:
            pass
        try:
            conn = self.inboundConnections[addr.host]
            logger.debug("DEBUG: Found inbound connection by host")
            return conn
        except (KeyError, AttributeError):
            pass
        try:
            conn = self.outboundConnections[addr]
            logger.debug("DEBUG: Found outbound connection by addr")
            return conn
        except KeyError:
            pass
        try:
            conn = self.udpSockets[addr.host]
            logger.debug("DEBUG: Found UDP socket by host")
            return conn
        except (KeyError, AttributeError):
            pass
        logger.debug("DEBUG: No connection found for address")
        raise KeyError

    def isAlreadyConnected(self, nodeid):
        logger.debug("DEBUG: Checking if already connected to node: %s", nodeid)
        for i in self.connections():
            try:
                if nodeid == i.nodeid:
                    logger.debug("DEBUG: Found existing connection to node")
                    return True
            except AttributeError:
                pass
        logger.debug("DEBUG: No existing connection to node found")
        return False

    def addConnection(self, connection):
        logger.debug("DEBUG: Adding connection: %s", connection)
        if isinstance(connection, UDPSocket):
            logger.debug("DEBUG: Skipping UDP socket addition")
            return
        if connection.isOutbound:
            logger.debug("DEBUG: Adding outbound connection")
            self.outboundConnections[connection.destination] = connection
        else:
            if connection.destination.host in self.inboundConnections:
                logger.debug("DEBUG: Adding inbound connection by destination")
                self.inboundConnections[connection.destination] = connection
            else:
                logger.debug("DEBUG: Adding inbound connection by host")
                self.inboundConnections[connection.destination.host] = connection
        logger.debug("DEBUG: Connection added successfully")

    def removeConnection(self, connection):
        logger.debug("DEBUG: Removing connection: %s", connection)
        if isinstance(connection, UDPSocket):
            logger.debug("DEBUG: Removing UDP socket")
            del self.udpSockets[connection.listening.host]
        elif isinstance(connection, TCPServer):
            logger.debug("DEBUG: Removing TCP server")
            del self.listeningSockets[Peer(
                connection.destination.host, connection.destination.port)]
        elif connection.isOutbound:
            logger.debug("DEBUG: Removing outbound connection")
            try:
                del self.outboundConnections[connection.destination]
            except KeyError:
                logger.debug("DEBUG: Outbound connection not found in pool")
                pass
        else:
            logger.debug("DEBUG: Removing inbound connection")
            try:
                del self.inboundConnections[connection.destination]
            except KeyError:
                try:
                    del self.inboundConnections[connection.destination.host]
                except KeyError:
                    logger.debug("DEBUG: Inbound connection not found in pool")
                    pass
        logger.debug("DEBUG: Closing connection")
        connection.handle_close()

    @staticmethod
    def getListeningIP():
        onionhost = config.safeGet("bitmessagesettings", "onionhostname", "")
        if _ends_with(onionhost, ".onion"):
            host = config.safeGet("bitmessagesettings", "onionbindip")
            logger.debug("DEBUG: Using onion bind IP: %s", host)
        else:
            host = '127.0.0.1'
            logger.debug("DEBUG: Using default localhost IP")
        
        if (config.safeGetBoolean("bitmessagesettings", "sockslisten") or 
            config.safeGet("bitmessagesettings", "socksproxytype") == "none"):
            host = config.get("network", "bind")
            logger.debug("DEBUG: Using network bind IP: %s", host)
        return host

    def startListening(self, bind=None):
        if bind is None:
            bind = self.getListeningIP()
        port = config.safeGetInt("bitmessagesettings", "port")
        logger.debug("DEBUG: Starting listening socket on %s:%s", bind, port)
        ls = TCPServer(host=bind, port=port)
        self.listeningSockets[ls.destination] = ls
        logger.debug("DEBUG: Listening socket started successfully")

    def startUDPSocket(self, bind=None):
        if bind is None:
            host = self.getListeningIP()
            logger.debug("DEBUG: Starting UDP socket on %s (announcing)", host)
            udpSocket = UDPSocket(host=host, announcing=True)
        else:
            if bind is False:
                logger.debug("DEBUG: Starting UDP socket (non-announcing)")
                udpSocket = UDPSocket(announcing=False)
            else:
                logger.debug("DEBUG: Starting UDP socket on %s (announcing)", bind)
                udpSocket = UDPSocket(host=bind, announcing=True)
        self.udpSockets[udpSocket.listening.host] = udpSocket
        logger.debug("DEBUG: UDP socket started successfully")

    def startBootstrappers(self):
        """Run the process of resolving bootstrap hostnames"""
        logger.debug("DEBUG: ===== STARTING BOOTSTRAPPERS =====")
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
            logger.error("DEBUG: Invalid proxy type: %s", proxy_type)
            return

        bootstrapper = bootstrap(connection_base)
        logger.debug("DEBUG: Bootstrapper class created: %s", bootstrapper)
        
        if not hostname:
            port = random.choice([8080, 8444])  # nosec B311
            hostname = 'bootstrap%s.bitmessage.org' % port
            logger.debug("DEBUG: Selected bootstrap hostname: %s", hostname)
        else:
            port = 8444
            logger.debug("DEBUG: Using fixed port: %s", port)
        
        # DNS Resolution testen
        try:
            resolved_ip = socket.gethostbyname(hostname)
            logger.debug("DEBUG: DNS Resolution successful: %s -> %s", hostname, resolved_ip)
        except Exception as e:
            logger.error("DEBUG: DNS Resolution failed for %s: %s", hostname, e)
            return
        
        logger.debug("DEBUG: Creating bootstrapper instance with hostname: %s, port: %s", hostname, port)
        try:
            bootstrap_instance = bootstrapper(hostname, port)
            logger.debug("DEBUG: Bootstrapper instance created: %s", bootstrap_instance)
            self.addConnection(bootstrap_instance)
            logger.debug("DEBUG: ===== BOOTSTRAPPER SUCCESSFULLY ADDED =====")
        except Exception as e:
            logger.error("DEBUG: Failed to create bootstrapper: %s", e)
            logger.debug("DEBUG: ===== BOOTSTRAPPER FAILED =====")

    def loop(self):  # pylint: disable=too-many-branches,too-many-statements
        """Main Connectionpool's loop"""
        logger.debug("DEBUG: ===== STARTING CONNECTION POOL LOOP =====")
        
        spawnConnections = False
        acceptConnections = True
        
        # Config checks
        dontconnect = config.safeGetBoolean('bitmessagesettings', 'dontconnect')
        sendoutgoing = config.safeGetBoolean('bitmessagesettings', 'sendoutgoingconnections')
        socksproxytype = config.safeGet('bitmessagesettings', 'socksproxytype', '')
        onionsocksproxytype = config.safeGet('bitmessagesettings', 'onionsocksproxytype', '')
        
        logger.debug("DEBUG: Config - dontconnect: %s, sendoutgoing: %s, socksproxy: %s", 
                   dontconnect, sendoutgoing, socksproxytype)
        
        if dontconnect:
            acceptConnections = False
            logger.debug("DEBUG: dontconnect=True - not accepting connections")
        elif sendoutgoing:
            spawnConnections = True
            logger.debug("DEBUG: sendoutgoingconnections=True - spawning connections")

        if (socksproxytype[:5] == 'SOCKS' and 
            not config.safeGetBoolean('bitmessagesettings', 'sockslisten') and 
            '.onion' not in config.safeGet('bitmessagesettings', 'onionhostname', '')):
            acceptConnections = False
            logger.debug("DEBUG: SOCKS proxy detected - not accepting connections")

        # CRITICAL: Bootstrap Logic
        if spawnConnections:
            logger.debug("DEBUG: Spawn connections is TRUE")
            
            if not knownnodes.knownNodesActual:
                logger.debug("DEBUG: knownNodesActual is FALSE - starting bootstrappers")
                self.startBootstrappers()
                knownnodes.knownNodesActual = True
                logger.debug("DEBUG: Set knownNodesActual to TRUE")
            else:
                logger.debug("DEBUG: knownNodesActual is already TRUE")

            if not self._bootstrapped:
                logger.debug("DEBUG: ===== FIRST BOOTSTRAPPING INITIATED =====")
                self._bootstrapped = True
                
                # Proxy configuration
                Proxy.proxy = (
                    config.safeGet('bitmessagesettings', 'sockshostname'),
                    config.safeGetInt('bitmessagesettings', 'socksport')
                )
                logger.debug("DEBUG: Set main proxy: %s:%s", Proxy.proxy[0], Proxy.proxy[1])
                
                try:
                    if not onionsocksproxytype.startswith("SOCKS"):
                        raise ValueError
                    Proxy.onion_proxy = (
                        config.safeGet('network', 'onionsockshostname', None),
                        config.safeGet('network', 'onionsocksport', None)
                    )
                    logger.debug("DEBUG: Set onion proxy: %s:%s", 
                               Proxy.onion_proxy[0], Proxy.onion_proxy[1])
                except ValueError:
                    Proxy.onion_proxy = None
                    logger.debug("DEBUG: No valid onion proxy configured")
            else:
                logger.debug("DEBUG: Already bootstrapped: %s", self._bootstrapped)

            # Connection statistics
            established = sum(1 for c in self.outboundConnections.values() 
                            if (c.connected and c.fullyEstablished))
            pending = len(self.outboundConnections) - established
            max_outbound = config.safeGetInt('bitmessagesettings', 'maxoutboundconnections')
            
            logger.debug("DEBUG: Connection stats - established: %s, pending: %s, max_outbound: %s", 
                       established, pending, max_outbound)

            if established < max_outbound:
                logger.debug("DEBUG: Need more connections (current: %s < max: %s)", established, max_outbound)
                
                for i in range(state.maximumNumberOfHalfOpenConnections - pending):
                    logger.debug("DEBUG: Attempting to create connection %s/%s", 
                               i + 1, state.maximumNumberOfHalfOpenConnections - pending)
                    
                    try:
                        if self.trustedPeer:
                            chosen = self.trustedPeer
                            logger.debug("DEBUG: Using trusted peer: %s", chosen)
                        else:
                            if not self.streams:
                                logger.debug("DEBUG: No streams available, adding stream 1")
                                self.streams.append(1)
                            stream = random.choice(self.streams)  # nosec B311
                            logger.debug("DEBUG: Selected stream: %s", stream)
                            chosen = chooseConnection(stream)
                            logger.debug("DEBUG: Chosen connection: %s", chosen)
                    except ValueError as e:
                        logger.debug("DEBUG: No valid connection chosen: %s", e)
                        continue
                    except Exception as e:
                        logger.error("DEBUG: Error choosing connection: %s", e)
                        continue

                    if chosen in self.outboundConnections:
                        logger.debug("DEBUG: Already connected to chosen outbound: %s", chosen)
                        continue
                    if chosen.host in self.inboundConnections:
                        logger.debug("DEBUG: Already connected to chosen inbound: %s", chosen)
                        continue
                    if chosen in state.ownAddresses:
                        logger.debug("DEBUG: Chosen connection is self: %s", chosen)
                        continue

                    # Network group check
                    host_network_group = protocol.network_group(chosen.host)
                    same_group = False
                    for j in self.outboundConnections.values():
                        if host_network_group == j.network_group:
                            same_group = True
                            if chosen.host == j.destination.host:
                                knownnodes.decreaseRating(chosen)
                                logger.debug("DEBUG: Decreased rating for duplicate host: %s", chosen.host)
                            break
                    if same_group:
                        logger.debug("DEBUG: Same network group - skipping: %s", chosen.host)
                        continue

                    # Create connection
                    try:
                        if _ends_with(chosen.host, ".onion") and Proxy.onion_proxy:
                            logger.debug("DEBUG: Creating onion connection to: %s", chosen)
                            if onionsocksproxytype == "SOCKS5":
                                conn = Socks5BMConnection(chosen)
                            elif onionsocksproxytype == "SOCKS4a":
                                conn = Socks4aBMConnection(chosen)
                            else:
                                logger.error("DEBUG: Invalid onion proxy type: %s", onionsocksproxytype)
                                continue
                        elif socksproxytype == "SOCKS5":
                            logger.debug("DEBUG: Creating SOCKS5 connection to: %s", chosen)
                            conn = Socks5BMConnection(chosen)
                        elif socksproxytype == "SOCKS4a":
                            logger.debug("DEBUG: Creating SOCKS4a connection to: %s", chosen)
                            conn = Socks4aBMConnection(chosen)
                        else:
                            logger.debug("DEBUG: Creating direct TCP connection to: %s", chosen)
                            conn = TCPConnection(chosen)
                        
                        self.addConnection(conn)
                        logger.debug("DEBUG: Successfully added connection: %s", conn)
                        
                    except socket.error as e:
                        if e.errno == errno.ENETUNREACH:
                            logger.debug("DEBUG: Network unreachable error for: %s", chosen)
                        else:
                            logger.error("DEBUG: Socket error for %s: %s", chosen, e)
                        continue
                    except Exception as e:
                        logger.error("DEBUG: Error creating connection to %s: %s", chosen, e)
                        continue

                    self._lastSpawned = time.time()
                    logger.debug("DEBUG: Updated last spawned time: %s", self._lastSpawned)
        else:
            logger.debug("DEBUG: Spawn connections is FALSE - closing outbound connections")
            for i in self.outboundConnections.values():
                i.handle_close()

        # Listening sockets
        if acceptConnections:
            logger.debug("DEBUG: Accept connections is TRUE")
            if not self.listeningSockets:
                bind_config = config.safeGet('network', 'bind')
                logger.debug("DEBUG: Network bind config: '%s'", bind_config)
                
                if bind_config == '':
                    logger.debug("DEBUG: Starting default listening socket")
                    self.startListening()
                else:
                    binds = re.sub(r'[^\w.]+', ' ', bind_config).split()
                    logger.debug("DEBUG: Starting listening sockets on: %s", binds)
                    for bind in binds:
                        self.startListening(bind)
                logger.info('Listening for incoming connections.')
            else:
                logger.debug("DEBUG: Listening sockets already exist: %s", len(self.listeningSockets))

            if not self.udpSockets:
                bind_config = config.safeGet('network', 'bind')
                if bind_config == '':
                    logger.debug("DEBUG: Starting default UDP socket")
                    self.startUDPSocket()
                else:
                    binds = re.sub(r'[^\w.]+', ' ', bind_config).split()
                    logger.debug("DEBUG: Starting UDP sockets on: %s", binds)
                    for bind in binds:
                        self.startUDPSocket(bind)
                    self.startUDPSocket(False)
                logger.info('Starting UDP socket(s).')
            else:
                logger.debug("DEBUG: UDP sockets already exist: %s", len(self.udpSockets))
        else:
            logger.debug("DEBUG: Accept connections is FALSE")
            if self.listeningSockets:
                logger.debug("DEBUG: Closing listening sockets")
                for i in self.listeningSockets.values():
                    i.close_reason = "Stopping listening"
                    i.accepting = i.connecting = i.connected = False
                logger.info('Stopped listening for incoming connections.')
            if self.udpSockets:
                logger.debug("DEBUG: Closing UDP sockets")
                for i in self.udpSockets.values():
                    i.close_reason = "Stopping UDP socket"
                    i.accepting = i.connecting = i.connected = False
                logger.info('Stopped udp sockets.')

        # Asyncore loop
        loopTime = float(self._spawnWait)
        if self._lastSpawned < time.time() - self._spawnWait:
            loopTime = 2.0
        logger.debug("DEBUG: Running asyncore loop with timeout: %s", loopTime)
        asyncore.loop(timeout=loopTime, count=1000)

        # Connection maintenance
        reaper = []
        minTx = time.time() - 20
        logger.debug("DEBUG: Checking for stale connections (minTx: %s)", minTx)
        
        for i in self.connections():
            conn_minTx = minTx
            if i.fullyEstablished:
                conn_minTx -= 300 - 20
                logger.debug("DEBUG: Connection %s is fully established", i)
            
            if i.lastTx < conn_minTx:
                if i.fullyEstablished:
                    logger.debug("DEBUG: Sending ping to connection %s", i)
                    i.append_write_buf(protocol.CreatePacket(b'ping'))
                else:
                    timeout = time.time() - i.lastTx
                    i.close_reason = "Timeout (%is)" % timeout
                    i.set_state("close")
                    logger.debug("DEBUG: Timing out connection %s (lastTx: %s)", i, i.lastTx)

        for i in (self.connections() + list(self.listeningSockets.values()) + list(self.udpSockets.values())):
            if not (i.accepting or i.connecting or i.connected):
                logger.debug("DEBUG: Adding to reaper: %s", i)
                reaper.append(i)
            else:
                try:
                    if i.state == "close":
                        logger.debug("DEBUG: Adding closed connection to reaper: %s", i)
                        reaper.append(i)
                except AttributeError:
                    pass

        logger.debug("DEBUG: Reaping %s connections", len(reaper))
        for i in reaper:
            self.removeConnection(i)
        
        logger.debug("DEBUG: ===== CONNECTION POOL LOOP COMPLETED =====")


pool = BMConnectionPool()
