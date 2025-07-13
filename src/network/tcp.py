"""
TCP protocol handler
"""
# pylint: disable=too-many-ancestors
import sys
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
    Enhanced TCP connection handler with OpenBSD-specific optimizations
    """
    
    def __init__(self, address=None, sock=None):
        logger.debug("DEBUG: Initializing TCPConnection with address: %s, sock: %s", address, sock)
        BMProto.__init__(self, address=address, sock=sock)
        self.verackReceived = False
        self.verackSent = False
        self.streams = [0]
        self.fullyEstablished = False
        self.skipUntil = 0
        self.openbsd_retry_count = 0
        self.last_connection_attempt = 0
        
        # OpenBSD-specific socket configuration
        if sys.platform.startswith('openbsd'):
            # Connection pacing parameters
            self.openbsd_min_retry_delay = 1.0  # Start with 1 second
            self.openbsd_max_retry_delay = 30.0  # Max 30 seconds delay
            self.openbsd_connection_timeout = 30  # Connection timeout in seconds
        
        if address is None and sock is not None:
            # Inbound connection handling
            self.destination = Peer(*sock.getpeername())
            self.isOutbound = False
            TLSDispatcher.__init__(self, sock, server_side=True)
            self.connectedAt = time.time()
            logger.debug('DEBUG: Received inbound connection from %s:%i', 
                        self.destination.host, self.destination.port)
            self.nodeid = randomBytes(8)
            logger.debug("DEBUG: Generated nodeid: %s", self.nodeid)
            
            # OpenBSD-specific inbound settings
            if sys.platform.startswith('openbsd'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                
        elif address is not None and sock is not None:
            # Outbound proxy connection
            TLSDispatcher.__init__(self, sock, server_side=False)
            self.isOutbound = True
            logger.debug('DEBUG: Outbound proxy connection to %s:%i',
                       self.destination.host, self.destination.port)
            
            # OpenBSD-specific proxy settings
            if sys.platform.startswith('openbsd'):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.settimeout(self.openbsd_connection_timeout)
        else:
            # New outbound connection
            self.destination = address
            self.isOutbound = True
            current_time = time.time()
            
            # OpenBSD connection rate limiting
            if sys.platform.startswith('openbsd'):
                elapsed = current_time - self.last_connection_attempt
                if elapsed < self.openbsd_min_retry_delay:
                    delay = min(
                        self.openbsd_min_retry_delay * (2 ** self.openbsd_retry_count),
                        self.openbsd_max_retry_delay
                    )
                    logger.debug("OpenBSD: Delaying connection attempt by %.1fs", delay)
                    time.sleep(delay)
                self.last_connection_attempt = current_time
            
            socket_family = socket.AF_INET6 if ":" in address.host else socket.AF_INET
            logger.debug("DEBUG: Creating new socket with family: %s", socket_family)
            self.create_socket(socket_family, socket.SOCK_STREAM)
            
            # OpenBSD-specific socket options
            if sys.platform.startswith('openbsd'):
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.socket.setsockopt(socket.IPPROTO_TCP, 0x10, 1)  # TCP_MD5SIG
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 15)
                if hasattr(socket, 'TCP_SYNCNT'):
                    self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_SYNCNT, 3)
                self.socket.settimeout(self.openbsd_connection_timeout)
            
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            TLSDispatcher.__init__(self, self.socket, server_side=False)
            logger.debug('DEBUG: Connecting to %s:%i', 
                       self.destination.host, self.destination.port)
            self.connect(self.destination)
        
        try:
            self.local = (
                protocol.checkIPAddress(
                    protocol.encodeHost(self.destination.host), True)
                and not protocol.checkSocksIP(self.destination.host)
            )
            logger.debug("DEBUG: Local connection check: %s", self.local)
        except socket.error as e:
            logger.debug("DEBUG: Socket error during local check: %s", e)
        
        self.network_group = protocol.network_group(self.destination.host)
        logger.debug("DEBUG: Network group: %s", self.network_group)
        
        ObjectTracker.__init__(self)
        self.bm_proto_reset()
        self.set_state("bm_header", expectBytes=protocol.Header.size)
        logger.debug("DEBUG: TCPConnection initialization complete")

    def antiIntersectionDelay(self, initial=False):
        """
        This is a defense against the so called intersection attacks.
        """
        logger.debug("DEBUG: Calculating antiIntersectionDelay (initial: %s)", initial)
        max_known_nodes = max(
            len(knownnodes.knownNodes[x]) for x in knownnodes.knownNodes)
        delay = math.ceil(math.log(max_known_nodes + 2, 20)) * (
            0.2 + invQueue.queueCount / 2.0)
            
        logger.debug("DEBUG: Calculated delay: %.2f seconds", delay)
        
        if delay > 0:
            if initial:
                self.skipUntil = self.connectedAt + delay
                if self.skipUntil > time.time():
                    logger.debug(
                        'DEBUG: Initial skipping processing getdata for %.2fs',
                        self.skipUntil - time.time())
            else:
                logger.debug(
                    'DEBUG: Skipping processing getdata due to missing object for %.2fs', delay)
                self.skipUntil = time.time() + delay

    def checkTimeOffsetNotification(self):
        """
        Check if we have connected to too many nodes which have too high
        time offset from us
        """
        logger.debug("DEBUG: Checking time offset notification")
        if BMProto.timeOffsetWrongCount > maximumTimeOffsetWrongCount and not self.fullyEstablished:
            logger.debug("DEBUG: Too many wrong time offsets, showing warning")
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
        logger.debug("DEBUG: Connection fully established")
        self.set_connection_fully_established()
        self.set_state("bm_header")
        self.bm_proto_reset()
        return True

    def set_connection_fully_established(self):
        """Initiate inventory synchronisation."""
        logger.debug("DEBUG: Setting connection as fully established")
        if not self.isOutbound and not self.local:
            state.clientHasReceivedIncomingConnections = True
            UISignalQueue.put(('setStatusIcon', 'green'))
            logger.debug("DEBUG: Updated status icon to green")
            
        UISignalQueue.put((
            'updateNetworkStatusTab', (self.isOutbound, True, self.destination)
        ))
        logger.debug("DEBUG: Updated network status tab")
        
        self.antiIntersectionDelay(True)
        self.fullyEstablished = True
        
        if self.isOutbound or not self.local and not state.socksIP:
            logger.debug("DEBUG: Updating known nodes for %s:%i", 
                        self.destination.host, self.destination.port)
            knownnodes.increaseRating(self.destination)
            knownnodes.addKnownNode(
                self.streams, self.destination, time.time())
            dandelion_ins.maybeAddStem(self, invQueue)
            
        self.sendAddr()
        self.sendBigInv()
        logger.debug("DEBUG: Sent addr and bigInv messages")

    def sendAddr(self):
        """Send a partial list of known addresses to peer."""
        logger.debug("DEBUG: Preparing to send addr message")
        maxAddrCount = config.safeGetInt(
            "bitmessagesettings", "maxaddrperstreamsend", 500)
            
        templist = []
        addrs = {}
        for stream in self.streams:
            with knownnodes.knownNodesLock:
                for n, s in enumerate((stream, stream * 2, stream * 2 + 1)):
                    nodes = knownnodes.knownNodes.get(s)
                    if not nodes:
                        logger.debug("DEBUG: No nodes for stream %s", s)
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
                    logger.debug("DEBUG: Selected %d nodes for stream %s", elemCount, s)
                    
        for substream in addrs:
            for peer, params in addrs[substream]:
                templist.append((substream, peer, params["lastseen"]))
                
        if templist:
            logger.debug("DEBUG: Sending %d addr entries", len(templist))
            self.append_write_buf(protocol.assembleAddrMessage(templist))

    def sendBigInv(self):
        """
        Send hashes of all inventory objects, chunked as the protocol has
        a per-command limit.
        """
        logger.debug("DEBUG: Preparing to send bigInv message")
        
        def sendChunk():
            """Send one chunk of inv entries in one command"""
            if objectCount == 0:
                logger.debug("DEBUG: No objects to send in this chunk")
                return
            logger.debug(
                'DEBUG: Sending inv message with %i objects', objectCount)
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
                    
        objectCount = 0
        payload = b''
        
        for obj_hash, _ in bigInvList.items():
            payload += obj_hash
            objectCount += 1

            if objectCount >= protocol.MAX_OBJECT_COUNT - 1:
                logger.debug("DEBUG: Sending full chunk of %d objects", objectCount)
                sendChunk()
                payload = b''
                objectCount = 0

        sendChunk()
        logger.debug("DEBUG: Finished sending bigInv message")

    def handle_connect(self):
        """Enhanced connection handler with OpenBSD optimizations"""
        if sys.platform.startswith('openbsd'):
            try:
                # Stabilize connection
                self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                time.sleep(0.1)  # Small delay for BSD stack
            except socket.error as e:
                logger.debug("OpenBSD: Socket option error: %s", e)
        
        try:
            AdvancedDispatcher.handle_connect(self)
            self.openbsd_retry_count = 0  # Reset on successful connection
        except socket.error as e:
            if e.errno in asyncore._DISCONNECTED:
                logger.debug('DEBUG: %s:%i: Connection failed: %s',
                           self.destination.host, self.destination.port, e)
                if sys.platform.startswith('openbsd'):
                    self.handle_openbsd_connection_failure()
                return
        
        self.nodeid = randomBytes(8)
        logger.debug("DEBUG: Generated new nodeid: %s", self.nodeid)
        
        self.append_write_buf(
            protocol.assembleVersionMessage(
                self.destination.host, self.destination.port,
                network.connectionpool.pool.streams, dandelion_ins.enabled,
                False, nodeid=self.nodeid))
        self.connectedAt = time.time()
        receiveDataQueue.put(self.destination)
        logger.debug("DEBUG: Sent version message and queued destination")

    def handle_openbsd_connection_failure(self):
        """OpenBSD-specific connection failure handling"""
        if not sys.platform.startswith('openbsd'):
            return
            
        self.openbsd_retry_count += 1
        delay = min(
            self.openbsd_min_retry_delay * (2 ** self.openbsd_retry_count),
            self.openbsd_max_retry_delay
        )
        logger.warning("OpenBSD: Connection failed, waiting %.1fs (attempt %d)", 
                      delay, self.openbsd_retry_count)
        
        # Clean up resources
        try:
            self.socket.close()
        except:
            pass
            
        time.sleep(delay)

    def handle_error(self):
        """Enhanced error handler for OpenBSD"""
        logger.debug("DEBUG: Handling TCP connection error")
        if sys.platform.startswith('openbsd'):
            self.handle_openbsd_connection_failure()
        super().handle_error()

    def handle_read(self):
        """Callback for reading from a socket"""
        logger.debug("DEBUG: Handling TCP read")
        TLSDispatcher.handle_read(self)
        receiveDataQueue.put(self.destination)
        logger.debug("DEBUG: Queued destination after read")

    def handle_write(self):
        """Callback for writing to a socket"""
        logger.debug("DEBUG: Handling TCP write")
        TLSDispatcher.handle_write(self)

    def handle_close(self):
        """Callback for connection being closed."""
        logger.debug("DEBUG: Handling TCP connection close")
        host_is_global = self.isOutbound or not self.local and not state.socksIP
        logger.debug("DEBUG: host_is_global: %s", host_is_global)
        
        if self.fullyEstablished:
            logger.debug("DEBUG: Connection was fully established")
            UISignalQueue.put((
                'updateNetworkStatusTab',
                (self.isOutbound, False, self.destination)
            ))
            if host_is_global:
                logger.debug("DEBUG: Updating known nodes on close")
                knownnodes.addKnownNode(
                    self.streams, self.destination, time.time())
                dandelion_ins.maybeRemoveStem(self)
        else:
            logger.debug("DEBUG: Connection was not fully established")
            self.checkTimeOffsetNotification()
            if host_is_global:
                logger.debug("DEBUG: Decreasing rating for failed connection")
                knownnodes.decreaseRating(self.destination)
                
        BMProto.handle_close(self)
        logger.debug("DEBUG: Connection close handling complete")


class Socks5BMConnection(Socks5Connection, TCPConnection):
    """SOCKS5 wrapper for TCP connections"""

    def __init__(self, address):
        logger.debug("DEBUG: Initializing Socks5BMConnection to %s:%i", 
                    address.host, address.port)
        Socks5Connection.__init__(self, address=address)
        TCPConnection.__init__(self, address=address, sock=self.socket)
        self.set_state("init")
        logger.debug("DEBUG: Socks5BMConnection initialized")

    def state_proxy_handshake_done(self):
        """
        State when SOCKS5 connection succeeds, we need to send a
        Bitmessage handshake to peer.
        """
        logger.debug("DEBUG: SOCKS5 handshake done, proceeding to BM handshake")
        Socks5Connection.state_proxy_handshake_done(self)
        self.nodeid = randomBytes(8)
        logger.debug("DEBUG: Generated nodeid: %s", self.nodeid)
        
        self.append_write_buf(
            protocol.assembleVersionMessage(
                self.destination.host, self.destination.port,
                network.connectionpool.pool.streams, dandelion_ins.enabled,
                False, nodeid=self.nodeid))
        self.set_state("bm_header", expectBytes=protocol.Header.size)
        logger.debug("DEBUG: Sent version message and set BM header state")
        return True


class Socks4aBMConnection(Socks4aConnection, TCPConnection):
    """SOCKS4a wrapper for TCP connections"""

    def __init__(self, address):
        logger.debug("DEBUG: Initializing Socks4aBMConnection to %s:%i", 
                    address.host, address.port)
        Socks4aConnection.__init__(self, address=address)
        TCPConnection.__init__(self, address=address, sock=self.socket)
        self.set_state("init")
        logger.debug("DEBUG: Socks4aBMConnection initialized")

    def state_proxy_handshake_done(self):
        """
        State when SOCKS4a connection succeeds, we need to send a
        Bitmessage handshake to peer.
        """
        logger.debug("DEBUG: SOCKS4a handshake done, proceeding to BM handshake")
        Socks4aConnection.state_proxy_handshake_done(self)
        self.nodeid = randomBytes(8)
        logger.debug("DEBUG: Generated nodeid: %s", self.nodeid)
        
        self.append_write_buf(
            protocol.assembleVersionMessage(
                self.destination.host, self.destination.port,
                network.connectionpool.pool.streams, dandelion_ins.enabled,
                False, nodeid=self.nodeid))
        self.set_state("bm_header", expectBytes=protocol.Header.size)
        logger.debug("DEBUG: Sent version message and set BM header state")
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
            logger.debug("DEBUG: Bootstrapper initialized")

        def bm_command_addr(self):
            """
            Got addr message - the bootstrap succeed.
            """
            logger.debug("DEBUG: Received addr message, bootstrap succeeded")
            BMProto.bm_command_addr(self)
            self._succeed = True
            self.close_reason = "Thanks for bootstrapping!"
            self.set_state("close")
            logger.debug("DEBUG: Set state to close")

        def set_connection_fully_established(self):
            """Only send addr here"""
            logger.debug("DEBUG: Bootstrapper connection established")
            self.fullyEstablished = True
            self.sendAddr()

        def handle_close(self):
            """
            After closing the connection switch knownnodes.knownNodesActual
            back to False if the bootstrapper failed.
            """
            logger.debug("DEBUG: Bootstrapper closing, success: %s", self._succeed)
            BMProto.handle_close(self)
            if not self._succeed:
                knownnodes.knownNodesActual = False
                logger.debug("DEBUG: Marked knownNodes as not actual")

    return Bootstrapper


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
                logger.debug("DEBUG: Successfully bound to %s:%i", host, port)
            except socket.error as e:
                if e.errno in (asyncore.EADDRINUSE, asyncore.WSAEADDRINUSE):
                    logger.debug("DEBUG: Port %i in use, retrying", port)
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
        logger.debug("DEBUG: TCPServer initialized and listening")

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
        logger.debug("DEBUG: Handling incoming connection")
        try:
            sock = self.accept()[0]
            logger.debug("DEBUG: Accepted connection from %s", sock.getpeername())
        except (TypeError, IndexError) as e:
            logger.debug("DEBUG: Accept failed: %s", e)
            return

        state.ownAddresses[Peer(*sock.getsockname())] = True
        current_connections = len(network.connectionpool.pool)
        max_connections = config.safeGetInt('bitmessagesettings', 'maxtotalconnections') + \
                         config.safeGetInt('bitmessagesettings', 'maxbootstrapconnections') + 10
                         
        logger.debug("DEBUG: Current connections: %d, max: %d", current_connections, max_connections)
        
        if current_connections > max_connections:
            logger.warning("DEBUG: Server full, dropping connection")
            sock.close()
            return
            
        try:
            network.connectionpool.pool.addConnection(TCPConnection(sock=sock))
            logger.debug("DEBUG: Successfully added new connection to pool")
        except socket.error as e:
            logger.debug("DEBUG: Error adding connection to pool: %s", e)
            pass
