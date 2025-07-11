"""
TCP protocol handler
"""
# pylint: disable=too-many-ancestors

import logging
import math
import random
import socket
import time
import six

# magic imports!
import addresses
import l10n
import protocol
import state
import network.connectionpool  # use long name to address recursive import
from bmconfigparser import config
from highlevelcrypto import randomBytes
from network import dandelion_ins, invQueue, receiveDataQueue
from queues import UISignalQueue
from tr import _translate

from network import asyncore_pollchoose as asyncore
from network import knownnodes
from network.advanceddispatcher import AdvancedDispatcher
from network.bmproto import BMProto
from network.objectracker import ObjectTracker
from network.socks4a import Socks4aConnection
from network.socks5 import Socks5Connection
from network.tls import TLSDispatcher
from .node import Peer


logger = logging.getLogger('default')


maximumAgeOfNodesThatIAdvertiseToOthers = 10800  #: Equals three hours
maximumTimeOffsetWrongCount = 3  #: Connections with wrong time offset


def _ends_with(s, tail):
    try:
        return s.endswith(tail)
    except:
        return s.decode("utf-8", "replace").endswith(tail)

class TCPConnection(BMProto, TLSDispatcher):
    # pylint: disable=too-many-instance-attributes
    """
    .. todo:: Look to understand and/or fix the non-parent-init-called
    """

    def __init__(self, address=None, sock=None):
        logger.debug("DEBUG: Initializing TCPConnection with address: %s, sock: %s", address, sock)
        BMProto.__init__(self, address=address, sock=sock)
        self.verackReceived = False
        self.verackSent = False
        self.streams = [0]
        self.fullyEstablished = False
        self.skipUntil = 0
        
        if address is None and sock is not None:
            try:
                self.destination = Peer(*sock.getpeername())
                logger.debug("DEBUG: Inbound connection from %s", self.destination)
                self.isOutbound = False
                TLSDispatcher.__init__(self, sock, server_side=True)
                self.connectedAt = time.time()
                logger.debug(
                    'DEBUG: Received inbound connection from %s:%i at %s',
                    self.destination.host, self.destination.port, self.connectedAt)
                self.nodeid = randomBytes(8)
                logger.debug("DEBUG: Generated nodeid: %s", self.nodeid)
            except socket.error as e:
                logger.error("DEBUG: Error getting peer name in TCPConnection: %s", e)
                raise
        elif address is not None and sock is not None:
            TLSDispatcher.__init__(self, sock, server_side=False)
            self.isOutbound = True
            logger.debug(
                'DEBUG: Outbound proxy connection to %s:%i',
                self.destination.host, self.destination.port)
        else:
            self.destination = address
            self.isOutbound = True
            socket_family = socket.AF_INET6 if ":" in address.host else socket.AF_INET
            logger.debug("DEBUG: Creating new socket with family: %s", socket_family)
            try:
                self.create_socket(socket_family, socket.SOCK_STREAM)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                TLSDispatcher.__init__(self, sock, server_side=False)
                logger.debug(
                    'DEBUG: Connecting to %s:%i',
                    self.destination.host, self.destination.port)
                self.connect(self.destination)
            except socket.error as e:
                logger.error("DEBUG: Error creating socket in TCPConnection: %s", e)
                raise
            
        try:
            self.local = (
                protocol.checkIPAddress(
                    protocol.encodeHost(self.destination.host), True)
                and not protocol.checkSocksIP(self.destination.host)
            )
            logger.debug("DEBUG: Local connection check: %s, host: %s", 
                       self.local, self.destination.host)
        except socket.error as e:
            logger.debug("DEBUG: Socket error during local check: %s", e)
            pass
            
        self.network_group = protocol.network_group(self.destination.host)
        logger.debug("DEBUG: Network group: %s for host %s", 
                   self.network_group, self.destination.host)
        
        ObjectTracker.__init__(self)  # pylint: disable=non-parent-init-called
        self.bm_proto_reset()
        self.set_state("bm_header", expectBytes=protocol.Header.size)
        logger.debug("DEBUG: TCPConnection initialization complete for %s:%i", 
                   self.destination.host, self.destination.port)

    def antiIntersectionDelay(self, initial=False):
        """
        This is a defense against the so called intersection attacks.
        """
        logger.debug("DEBUG: Calculating antiIntersectionDelay (initial: %s)", initial)
        max_known_nodes = max(
            len(knownnodes.knownNodes[x]) for x in knownnodes.knownNodes)
        delay = math.ceil(math.log(max_known_nodes + 2, 20)) * (
            0.2 + invQueue.queueCount / 2.0)
            
        logger.debug("DEBUG: Calculated delay: %.2f seconds (max_known_nodes: %d, invQueue: %d)", 
                   delay, max_known_nodes, invQueue.queueCount)
        
        if delay > 0:
            if initial:
                self.skipUntil = self.connectedAt + delay
                if self.skipUntil > time.time():
                    logger.debug(
                        'DEBUG: Initial skipping processing getdata for %.2fs (until %s)',
                        self.skipUntil - time.time(), self.skipUntil)
            else:
                logger.debug(
                    'DEBUG: Skipping processing getdata due to missing object for %.2fs', delay)
                self.skipUntil = time.time() + delay

    def checkTimeOffsetNotification(self):
        """
        Check if we have connected to too many nodes which have too high
        time offset from us
        """
        logger.debug("DEBUG: Checking time offset notification. Current wrong count: %d", 
                   BMProto.timeOffsetWrongCount)
        if BMProto.timeOffsetWrongCount > maximumTimeOffsetWrongCount and not self.fullyEstablished:
            logger.debug("DEBUG: Too many wrong time offsets (%d > %d), showing warning", 
                       BMProto.timeOffsetWrongCount, maximumTimeOffsetWrongCount)
            UISignalQueue.put((
                'updateStatusBar',
                _translate(
                    "MainWindow",
                    "The time on your computer, {0}, may be wrong. "
                    "Please verify your settings."
                ).format(l10n.formatTimestamp())))

    def state_connection_fully_established(self):
        """
        State after the bitmessage protocol handshake is completed
        """
        logger.debug("DEBUG: Connection fully established with %s:%i", 
                   self.destination.host, self.destination.port)
        self.set_connection_fully_established()
        self.set_state("bm_header")
        self.bm_proto_reset()
        return True

    def set_connection_fully_established(self):
        """Initiate inventory synchronisation."""
        logger.debug("DEBUG: Setting connection as fully established with %s:%i", 
                   self.destination.host, self.destination.port)
        if not self.isOutbound and not self.local:
            state.clientHasReceivedIncomingConnections = True
            UISignalQueue.put(('setStatusIcon', 'green'))
            logger.debug("DEBUG: Updated status icon to green for incoming connection")
            
        UISignalQueue.put((
            'updateNetworkStatusTab', (self.isOutbound, True, self.destination)
        ))
        logger.debug("DEBUG: Updated network status tab for %s:%i", 
                   self.destination.host, self.destination.port)
        
        self.antiIntersectionDelay(True)
        self.fullyEstablished = True
        
        if self.isOutbound or not self.local and not state.socksIP:
            logger.debug("DEBUG: Updating known nodes for %s:%i (streams: %s)", 
                       self.destination.host, self.destination.port, self.streams)
            knownnodes.increaseRating(self.destination)
            knownnodes.addKnownNode(
                self.streams, self.destination, time.time())
            dandelion_ins.maybeAddStem(self, invQueue)
            
        self.sendAddr()
        self.sendBigInv()
        logger.debug("DEBUG: Sent addr and bigInv messages to %s:%i", 
                   self.destination.host, self.destination.port)

    def sendAddr(self) -> None:
        """Send address message with detailed logging"""
        logger.debug("TCP_PROTOCOL| Preparing addr message for %s:%i", 
                    self.destination.host, self.destination.port)
        
        try:
            maxAddrCount = config.safeGetInt(
                "bitmessagesettings", "maxaddrperstreamsend", 500)
            templist = []
            addrs = {}
            
            for stream in self.streams:
                with knownnodes.knownNodesLock:
                    for n, s in enumerate((stream, stream * 2, stream * 2 + 1)):
                        nodes = knownnodes.knownNodes.get(s)
                        if not nodes:
                            logger.debug("TCP_KNOWNNODES| No nodes for stream %s", s)
                            continue
                            
                        filtered = [
                            (k, v) for k, v in six.iteritems(nodes)
                            if v["lastseen"] > int(time.time()) - maximumAgeOfNodesThatIAdvertiseToOthers
                            and v["rating"] >= 0 and not _ends_with(k.host, '.onion')
                        ]
                        elemCount = min(
                            len(filtered),
                            maxAddrCount / 2 if n else maxAddrCount)
                        addrs[s] = random.sample(filtered, elemCount)
                        logger.debug("TCP_KNOWNNODES| Selected %d nodes for stream %s", 
                                   elemCount, s)
                        
            for substream in addrs:
                for peer, params in addrs[substream]:
                    templist.append((substream, peer, params["lastseen"]))
                    logger.debug("TCP_KNOWNNODES| Adding peer %s:%i (stream: %s, lastseen: %s)", 
                               peer.host, peer.port, substream, params["lastseen"])
                    
            if templist:
                logger.info("TCP_PROTOCOL| Sending %d addr entries to %s:%i", 
                          len(templist), self.destination.host, self.destination.port)
                self.append_write_buf(protocol.assembleAddrMessage(templist))
            else:
                logger.debug("TCP_PROTOCOL| No addr entries to send")
                
        except Exception as e:
            logger.error("TCP_ERROR| Error sending addr message: %s", e, exc_info=True)
            raise
    def sendBigInv(self):
        """
        Send hashes of all inventory objects, chunked as the protocol has
        a per-command limit.
        """
        logger.debug("DEBUG: Preparing to send bigInv message to %s:%i", 
                   self.destination.host, self.destination.port)
        
        def sendChunk():
            """Send one chunk of inv entries in one command"""
            if objectCount == 0:
                logger.debug("DEBUG: No objects to send in this chunk")
                return
            logger.debug(
                'DEBUG: Sending inv message with %i objects to %s:%i', 
                objectCount, self.destination.host, self.destination.port)
            self.append_write_buf(protocol.CreatePacket(
                b'inv', addresses.encodeVarint(objectCount) + payload))

        bigInvList = {}
        for stream in self.streams:
            with self.objectsNewToThemLock:
                for objHash in state.Inventory.unexpired_hashes_by_stream(stream):
                    if dandelion_ins.hasHash(objHash):
                        logger.debug("DEBUG: Skipping stem object %s", objHash)
                        continue
                    bigInvList[objHash] = 0
                    logger.debug("DEBUG: Adding object %s to bigInv list for stream %s", 
                               objHash, stream)
                    
        objectCount = 0
        payload = b''
        
        for obj_hash, _ in bigInvList.items():
            payload += obj_hash
            objectCount += 1
            logger.debug("DEBUG: Added object %s to payload (count: %d)", 
                       obj_hash, objectCount)

            if objectCount >= protocol.MAX_OBJECT_COUNT - 1:
                logger.debug("DEBUG: Sending full chunk of %d objects", objectCount)
                sendChunk()
                payload = b''
                objectCount = 0

        sendChunk()
        logger.debug("DEBUG: Finished sending bigInv message to %s:%i", 
                   self.destination.host, self.destination.port)

    def handle_connect(self):
        """Callback for TCP connection being established."""
        logger.debug("DEBUG: Handling TCP connection to %s:%i", 
                   self.destination.host, self.destination.port)
        try:
            AdvancedDispatcher.handle_connect(self)
        except socket.error as e:
            if e.errno in asyncore._DISCONNECTED:
                logger.debug(
                    'DEBUG: %s:%i: Connection failed: %s',
                    self.destination.host, self.destination.port, e)
                return
                
        self.nodeid = randomBytes(8)
        logger.debug("DEBUG: Generated new nodeid: %s for %s:%i", 
                   self.nodeid, self.destination.host, self.destination.port)
        
        self.append_write_buf(
            protocol.assembleVersionMessage(
                self.destination.host, self.destination.port,
                network.connectionpool.pool.streams, dandelion_ins.enabled,
                False, nodeid=self.nodeid))
        self.connectedAt = time.time()
        receiveDataQueue.put(self.destination)
        logger.debug("DEBUG: Sent version message and queued destination %s:%i at %s", 
                   self.destination.host, self.destination.port, self.connectedAt)

    def handle_read(self):
        """Callback for reading from a socket"""
        logger.debug("DEBUG: Handling TCP read from %s:%i", 
                   self.destination.host, self.destination.port)
        TLSDispatcher.handle_read(self)
        receiveDataQueue.put(self.destination)
        logger.debug("DEBUG: Queued destination %s:%i after read", 
                   self.destination.host, self.destination.port)

    def handle_write(self):
        """Callback for writing to a socket"""
        logger.debug("DEBUG: Handling TCP write to %s:%i", 
                   self.destination.host, self.destination.port)
        TLSDispatcher.handle_write(self)

    def handle_close(self):
        """Callback for connection being closed."""
        logger.debug("DEBUG: Handling TCP connection close for %s:%i (fullyEstablished: %s)", 
                   self.destination.host, self.destination.port, self.fullyEstablished)
        host_is_global = self.isOutbound or not self.local and not state.socksIP
        logger.debug("DEBUG: host_is_global: %s, isOutbound: %s, local: %s, socksIP: %s", 
                   host_is_global, self.isOutbound, self.local, state.socksIP)
        
        if self.fullyEstablished:
            logger.debug("DEBUG: Connection was fully established")
            UISignalQueue.put((
                'updateNetworkStatusTab',
                (self.isOutbound, False, self.destination)
            ))
            if host_is_global:
                logger.debug("DEBUG: Updating known nodes on close for %s:%i", 
                           self.destination.host, self.destination.port)
                knownnodes.addKnownNode(
                    self.streams, self.destination, time.time())
                dandelion_ins.maybeRemoveStem(self)
        else:
            logger.debug("DEBUG: Connection was not fully established")
            self.checkTimeOffsetNotification()
            if host_is_global:
                logger.debug("DEBUG: Decreasing rating for failed connection to %s:%i", 
                           self.destination.host, self.destination.port)
                knownnodes.decreaseRating(self.destination)
                
        BMProto.handle_close(self)
        logger.debug("DEBUG: Connection close handling complete for %s:%i", 
                   self.destination.host, self.destination.port)


class Socks5BMConnection(Socks5Connection, TCPConnection):
    """SOCKS5 wrapper for TCP connections"""

    def __init__(self, address):
        logger.debug("DEBUG: Initializing Socks5BMConnection to %s:%i", 
                    address.host, address.port)
        Socks5Connection.__init__(self, address=address)
        TCPConnection.__init__(self, address=address, sock=self.socket)
        self.set_state("init")
        logger.debug("DEBUG: Socks5BMConnection initialized for %s:%i", 
                    address.host, address.port)

    def state_proxy_handshake_done(self):
        """
        State when SOCKS5 connection succeeds, we need to send a
        Bitmessage handshake to peer.
        """
        logger.debug("DEBUG: SOCKS5 handshake done, proceeding to BM handshake for %s:%i", 
                    self.destination.host, self.destination.port)
        Socks5Connection.state_proxy_handshake_done(self)
        self.nodeid = randomBytes(8)
        logger.debug("DEBUG: Generated nodeid: %s for %s:%i", 
                   self.nodeid, self.destination.host, self.destination.port)
        
        self.append_write_buf(
            protocol.assembleVersionMessage(
                self.destination.host, self.destination.port,
                network.connectionpool.pool.streams, dandelion_ins.enabled,
                False, nodeid=self.nodeid))
        self.set_state("bm_header", expectBytes=protocol.Header.size)
        logger.debug("DEBUG: Sent version message and set BM header state for %s:%i", 
                   self.destination.host, self.destination.port)
        return True


class Socks4aBMConnection(Socks4aConnection, TCPConnection):
    """SOCKS4a wrapper for TCP connections"""

    def __init__(self, address):
        logger.debug("DEBUG: Initializing Socks4aBMConnection to %s:%i", 
                    address.host, address.port)
        Socks4aConnection.__init__(self, address=address)
        TCPConnection.__init__(self, address=address, sock=self.socket)
        self.set_state("init")
        logger.debug("DEBUG: Socks4aBMConnection initialized for %s:%i", 
                    address.host, address.port)

    def state_proxy_handshake_done(self):
        """
        State when SOCKS4a connection succeeds, we need to send a
        Bitmessage handshake to peer.
        """
        logger.debug("DEBUG: SOCKS4a handshake done, proceeding to BM handshake for %s:%i", 
                    self.destination.host, self.destination.port)
        Socks4aConnection.state_proxy_handshake_done(self)
        self.nodeid = randomBytes(8)
        logger.debug("DEBUG: Generated nodeid: %s for %s:%i", 
                   self.nodeid, self.destination.host, self.destination.port)
        
        self.append_write_buf(
            protocol.assembleVersionMessage(
                self.destination.host, self.destination.port,
                network.connectionpool.pool.streams, dandelion_ins.enabled,
                False, nodeid=self.nodeid))
        self.set_state("bm_header", expectBytes=protocol.Header.size)
        logger.debug("DEBUG: Sent version message and set BM header state for %s:%i", 
                   self.destination.host, self.destination.port)
        return True


def bootstrap(connection_class):
    """Make bootstrapper class for connection type (connection_class)"""
    logger.debug("DEBUG: Creating bootstrapper for connection class: %s", connection_class)
    
    class Bootstrapper(connection_class):
        """Base class for bootstrappers"""
        _connection_base = connection_class

        def __init__(self, host, port):
            logger.debug("DEBUG: Initializing Bootstrapper to %s:%i", host, port)
            self._connection_base.__init__(self, Peer(host, port))
            self.close_reason = self._succeed = False
            logger.debug("DEBUG: Bootstrapper initialized for %s:%i", host, port)

        def bm_command_addr(self):
            """
            Got addr message - the bootstrap succeed.
            """
            logger.debug("DEBUG: Received addr message, bootstrap succeeded for %s:%i", 
                        self.destination.host, self.destination.port)
            BMProto.bm_command_addr(self)
            self._succeed = True
            self.close_reason = "Thanks for bootstrapping!"
            self.set_state("close")
            logger.debug("DEBUG: Set state to close for bootstrapper %s:%i", 
                        self.destination.host, self.destination.port)

    def set_connection_fully_established(self) -> None:
        """Mark connection as fully established with detailed logging"""
        logger.info("TCP_STATE| Connection fully established with %s:%i", 
                  self.destination.host, self.destination.port)
        
        try:
            if not self.isOutbound and not self.local:
                state.clientHasReceivedIncomingConnections = True
                UISignalQueue.put(('setStatusIcon', 'green'))
                logger.debug("TCP_UI| Updated status icon to green")
                
            UISignalQueue.put((
                'updateNetworkStatusTab', (self.isOutbound, True, self.destination)
            ))
            logger.debug("TCP_UI| Updated network status tab")
            
            self.antiIntersectionDelay(True)
            self.fullyEstablished = True
            
            if self.isOutbound or (not self.local and not state.socksIP):
                logger.debug("TCP_KNOWNNODES| Updating known nodes for %s:%i (streams: %s)", 
                           self.destination.host, self.destination.port, self.streams)
                knownnodes.increaseRating(self.destination)
                knownnodes.addKnownNode(self.streams, self.destination, time.time())
                dandelion_ins.maybeAddStem(self, invQueue)
                
            self.sendAddr()
            self.sendBigInv()
            logger.debug("TCP_PROTOCOL| Sent addr and bigInv messages")
            
        except Exception as e:
            logger.error("TCP_ERROR| Error establishing connection: %s", e, exc_info=True)
            raise


        def handle_close(self):
            """
            After closing the connection switch knownnodes.knownNodesActual
            back to False if the bootstrapper failed.
            """
            logger.debug("DEBUG: Bootstrapper closing for %s:%i, success: %s", 
                        self.destination.host, self.destination.port, self._succeed)
            BMProto.handle_close(self)
            if not self._succeed:
                knownnodes.knownNodesActual = False
                logger.debug("DEBUG: Marked knownNodes as not actual due to failed bootstrapper")


class TCPServer(AdvancedDispatcher):
    """TCP connection server for Bitmessage protocol"""

    def __init__(self, host='127.0.0.1', port=8444):
        logger.debug("DEBUG: Initializing TCPServer on %s:%i", host, port)
        if not hasattr(self, '_map'):
            AdvancedDispatcher.__init__(self)
            
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        
        for attempt in range(50):
            try:
                if attempt > 0:
                    logger.warning('DEBUG: Failed to bind on port %s, trying random port', port)
                    port = random.randint(32767, 65535)  # nosec B311
                self.bind((host, port))
                logger.debug("DEBUG: Successfully bound to %s:%i on attempt %d", host, port, attempt+1)
            except socket.error as e:
                if e.errno in (asyncore.EADDRINUSE, asyncore.WSAEADDRINUSE):
                    logger.debug("DEBUG: Port %i in use, retrying (attempt %d)", port, attempt+1)
                    continue
            else:
                if attempt > 0:
                    logger.warning('DEBUG: Setting port to %s', port)
                    config.set(
                        'bitmessagesettings', 'port', str(port))
                    config.save()
                break
                
        self.destination = Peer(host, port)
        self.bound = True
        self.listen(5)
        logger.debug("DEBUG: TCPServer initialized and listening on %s:%i", host, port)

    def is_bound(self):
        """Is the socket bound?"""
        try:
            result = self.bound
        except AttributeError:
            result = False
        logger.debug("DEBUG: is_bound check: %s", result)
        return result

    def handle_accept(self):
        """Incoming connection callback"""
        logger.debug("DEBUG: Handling incoming connection attempt")
        try:
            sock, addr = self.accept()
            logger.debug("DEBUG: Accepted connection from %s", addr)
        except (TypeError, IndexError) as e:
            logger.debug("DEBUG: Accept failed: %s", e)
            return

        state.ownAddresses[Peer(*sock.getsockname())] = True
        current_connections = len(network.connectionpool.pool)
        max_connections = config.safeGetInt('bitmessagesettings', 'maxtotalconnections') + \
                         config.safeGetInt('bitmessagesettings', 'maxbootstrapconnections') + 10
                         
        logger.debug("DEBUG: Current connections: %d, max: %d", current_connections, max_connections)
        
        if current_connections > max_connections:
            logger.warning("DEBUG: Server full (%d > %d), dropping connection from %s", 
                         current_connections, max_connections, addr)
            sock.close()
            return
            
        try:
            network.connectionpool.pool.addConnection(TCPConnection(sock=sock))
            logger.debug("DEBUG: Successfully added new connection from %s to pool", addr)
        except socket.error as e:
            logger.error("DEBUG: Error adding connection from %s to pool: %s", addr, e)
            pass
