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
# Beispiel-Ersetzung in connectionchooser.py
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
        """
        Shortcut for combined list of connections from
        `inboundConnections` and `outboundConnections` dicts
        """
        connections = list(self.inboundConnections.values()) + list(self.outboundConnections.values())
        logger.debug("DEBUG: Getting all connections - count: %s", len(connections))
        return connections

    def establishedConnections(self):
        """Shortcut for list of connections having fullyEstablished == True"""
        established = [x for x in self.connections() if x.fullyEstablished]
        logger.debug("DEBUG: Getting established connections - count: %s", len(established))
        return established

    def connectToStream(self, streamNumber):
        """Connect to a bitmessage stream"""
        logger.debug("DEBUG: Adding stream %s to streams list", streamNumber)
        self.streams.append(streamNumber)

    def getConnectionByAddr(self, addr):
        """
        Return an (existing) connection object based on a `Peer` object
        (IP and port)
        """
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
        """Check if we're already connected to this peer"""
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
        """Add a connection object to our internal dict"""
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
        """Remove a connection from our internal dict"""
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
        """What IP are we supposed to be listening on?"""
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
        """Open a listening socket and start accepting connections on it"""
        if bind is None:
            bind = self.getListeningIP()
        port = config.safeGetInt("bitmessagesettings", "port")
        logger.debug("DEBUG: Starting listening socket on %s:%s", bind, port)
        ls = TCPServer(host=bind, port=port)
        self.listeningSockets[ls.destination] = ls
        logger.debug("DEBUG: Listening socket started successfully")

    def startUDPSocket(self, bind=None):
        """
        Open an UDP socket. Depending on settings, it can either only
        accept incoming UDP packets, or also be able to send them.
        """
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
        logger.debug("DEBUG: Starting bootstrappers")
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
        if not hostname:
            port = random.choice([8080, 8444])  # nosec B311
            hostname = 'bootstrap%s.bitmessage.org' % port
            logger.debug("DEBUG: Using bootstrap hostname: %s", hostname)
        else:
            port = 8444
            logger.debug("DEBUG: Using fixed port: %s", port)
        
        self.addConnection(bootstrapper(hostname, port))
        logger.debug("DEBUG: Bootstrapper connection added")

    def loop(self):  # pylint: disable=too-many-branches,too-many-statements
        """Main Connectionpool's loop"""
        logger.debug("DEBUG: Starting main connection pool loop")
        
        spawnConnections = False
        acceptConnections = True
        if config.safeGetBoolean('bitmessagesettings', 'dontconnect'):
            acceptConnections = False
            logger.debug("DEBUG: dontconnect=True - not accepting connections")
        elif config.safeGetBoolean('bitmessagesettings', 'sendoutgoingconnections'):
            spawnConnections = True
            logger.debug("DEBUG: sendoutgoingconnections=True - spawning connections")

        socksproxytype = config.safeGet('bitmessagesettings', 'socksproxytype', '')
        onionsocksproxytype = config.safeGet('bitmessagesettings', 'onionsocksproxytype', '')
        if (socksproxytype[:5] == 'SOCKS' and 
            not config.safeGetBoolean('bitmessagesettings', 'sockslisten') and 
            '.onion' not in config.safeGet('bitmessagesettings', 'onionhostname', '')):
            acceptConnections = False
            logger.debug("DEBUG: SOCKS proxy detected - not accepting connections")

        if spawnConnections:
            if not knownnodes.knownNodesActual:
                logger.debug("DEBUG: No known nodes - starting bootstrappers")
                self.startBootstrappers()
                knownnodes.knownNodesActual = True

            if not self._bootstrapped:
                logger.debug("DEBUG: First bootstrapping")
                self._bootstrapped = True
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

            established = sum(1 for c in self.outboundConnections.values() 
                            if (c.connected and c.fullyEstablished))
            pending = len(self.outboundConnections) - established
            logger.debug("DEBUG: Connection stats - established: %s, pending: %s", established, pending)

            if established < config.safeGetInt('bitmessagesettings', 'maxoutboundconnections'):
                logger.debug("DEBUG: Need more connections (current: %s, max: %s)", 
                           established, config.safeGetInt('bitmessagesettings', 'maxoutboundconnections'))
                
                for i in range(state.maximumNumberOfHalfOpenConnections - pending):
                    try:
                        chosen = self.trustedPeer or chooseConnection(random.choice(self.streams))  # nosec B311
                        logger.debug("DEBUG: Chosen connection: %s", chosen)
                    except ValueError:
                        logger.debug("DEBUG: No valid connection chosen")
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
                            logger.debug("DEBUG: Network unreachable error")
                            continue

                    self._lastSpawned = time.time()
                    logger.debug("DEBUG: Updated last spawned time: %s", self._lastSpawned)
        else:
            logger.debug("DEBUG: Closing all outbound connections")
            for i in self.outboundConnections.values():
                i.handle_close()

        if acceptConnections:
            if not self.listeningSockets:
                if config.safeGet('network', 'bind') == '':
                    logger.debug("DEBUG: Starting default listening socket")
                    self.startListening()
                else:
                    binds = re.sub(r'[^\w.]+', ' ', config.safeGet('network', 'bind')).split()
                    logger.debug("DEBUG: Starting listening sockets on: %s", binds)
                    for bind in binds:
                        self.startListening(bind)
                logger.info('Listening for incoming connections.')

            if not self.udpSockets:
                if config.safeGet('network', 'bind') == '':
                    logger.debug("DEBUG: Starting default UDP socket")
                    self.startUDPSocket()
                else:
                    binds = re.sub(r'[^\w.]+', ' ', config.safeGet('network', 'bind')).split()
                    logger.debug("DEBUG: Starting UDP sockets on: %s", binds)
                    for bind in binds:
                        self.startUDPSocket(bind)
                    self.startUDPSocket(False)
                logger.info('Starting UDP socket(s).')
        else:
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

        loopTime = float(self._spawnWait)
        if self._lastSpawned < time.time() - self._spawnWait:
            loopTime = 2.0
        logger.debug("DEBUG: Running asyncore loop with timeout: %s", loopTime)
        asyncore.loop(timeout=loopTime, count=1000)

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


pool = BMConnectionPool()
