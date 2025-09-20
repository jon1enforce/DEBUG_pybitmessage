"""
UDP protocol handler
"""
import logging
import socket
import time

# magic imports!
import protocol
import state
import network.connectionpool  # use long name to address recursive import

from network import receiveDataQueue
from .bmproto import BMProto
from .node import Peer
from .objectracker import ObjectTracker
from network.helpers import get_socket_family
from .helpers import is_openbsd, openbsd_socket_compat, get_socket_family
logger = logging.getLogger('default')


class UDPSocket(BMProto):  # pylint: disable=too-many-instance-attributes
    """Bitmessage protocol over UDP (class)"""
    port = 8444

    def __init__(self, host=None, sock=None, announcing=False):
        logger.debug("DEBUG: Initializing UDPSocket instance")
        # pylint: disable=bad-super-call
        super(BMProto, self).__init__(sock=sock)
        self.verackReceived = True
        self.verackSent = True
        # .. todo:: sort out streams
        self.streams = [1]
        self.fullyEstablished = True
        self.skipUntil = 0
        if sock is None:
            if host is None:
                host = ''
            socket_family = get_socket_family(host)
            logger.debug(f"DEBUG: Creating new UDP socket with family {socket_family}")
            self.create_socket(socket_family, socket.SOCK_DGRAM)
            self.set_socket_reuse()
            logger.info("Binding UDP socket to %s:%i", host, self.port)
            logger.debug(f"DEBUG: Socket bind details - host: {host}, port: {self.port}")
            self.socket.bind((host, self.port))
        else:
            logger.debug("DEBUG: Using provided socket")
            self.socket = sock
            self.set_socket_reuse()
        
        sockname = self.socket.getsockname()
        self.listening = Peer(*sockname)
        self.destination = Peer(*sockname)
        logger.debug(f"DEBUG: Socket listening on {self.listening}")
        
        ObjectTracker.__init__(self)
        self.connecting = False
        self.connected = True
        self.announcing = announcing
        logger.debug(f"DEBUG: Socket initialized - announcing: {announcing}")
        self.set_state("bm_header", expectBytes=protocol.Header.size)

    def set_socket_reuse(self):
        """Set socket reuse options"""
        logger.debug("DEBUG: Setting socket reuse options")
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # ✅ NUR auf OpenBSD anwenden
        if is_openbsd():
            try:
                # OpenBSD-spezifische Einstellungen
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except (AttributeError, socket.error, OSError):
                pass
        else:
            # Normale Einstellungen für andere Plattformen
            try:
                # SO_REUSEPORT ist nicht auf allen Plattformen verfügbar
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except (AttributeError, socket.error, OSError):
                logger.debug("DEBUG: SO_REUSEPORT not available on this platform")
                pass

    def bm_command_getdata(self):
        logger.debug("DEBUG: bm_command_getdata called (currently disabled)")
        return True

    def bm_command_inv(self):
        logger.debug("DEBUG: bm_command_inv called (currently disabled)")
        return True

    def bm_command_addr(self):
        logger.debug("DEBUG: Processing addr command")
        addresses = self._decode_addr()
        logger.debug(f"DEBUG: Decoded {len(addresses)} addresses")
        
        # only allow peer discovery from private IPs in order to avoid
        # attacks from random IPs on the internet
        if not self.local:
            logger.debug("DEBUG: Rejecting addr from non-local IP")
            return True
            
        remoteport = False
        for seenTime, stream, _, ip, port in addresses:
            decodedIP = protocol.checkIPAddress(ip)
            logger.debug(f"DEBUG: Processing address - IP: {ip}, port: {port}, stream: {stream}")
            
            if stream not in network.connectionpool.pool.streams:
                logger.debug("DEBUG: Stream not in our streams, skipping")
                continue
                
            if (seenTime < time.time() - protocol.MAX_TIME_OFFSET
                    or seenTime > time.time() + protocol.MAX_TIME_OFFSET):
                logger.debug("DEBUG: Timestamp out of allowed range, skipping")
                continue
                
            if decodedIP is False:
                # if the address isn't local, interpret it as
                # the host's own announcement
                remoteport = port
                logger.debug(f"DEBUG: Found remote port announcement: {remoteport}")
                
        if remoteport is False:
            logger.debug("DEBUG: No valid remote port found")
            return True
            
        logger.debug(
            "received peer discovery from %s:%i (port %i):",
            self.destination.host, self.destination.port, remoteport)
        state.discoveredPeers[Peer(self.destination.host, remoteport)] = \
            time.time()
        logger.debug(f"DEBUG: Added peer to discoveredPeers: {self.destination.host}:{remoteport}")
        return True

    def bm_command_portcheck(self):
        logger.debug("DEBUG: bm_command_portcheck called")
        return True

    def bm_command_ping(self):
        logger.debug("DEBUG: bm_command_ping called")
        return True

    def bm_command_pong(self):
        logger.debug("DEBUG: bm_command_pong called")
        return True

    def bm_command_verack(self):
        logger.debug("DEBUG: bm_command_verack called")
        return True

    def bm_command_version(self):
        logger.debug("DEBUG: bm_command_version called")
        return True

    def handle_connect(self):
        logger.debug("DEBUG: handle_connect called")
        return

    def writable(self):
        result = bool(self.write_buf)
        logger.debug(f"DEBUG: writable check - result: {result}")
        return result

    def readable(self):
        result = len(self.read_buf) < self._buf_len
        logger.debug(f"DEBUG: readable check - result: {result}, read_buf len: {len(self.read_buf)}, buf_len: {self._buf_len}")
        return result

    def handle_read(self):
        logger.debug("DEBUG: handle_read called")
        try:
            recdata, addr = self.socket.recvfrom(self._buf_len)
            logger.debug(f"DEBUG: Received {len(recdata)} bytes from {addr}")
        except (socket.error, OSError) as e:
            logger.error("socket error on recvfrom:", exc_info=True)
            logger.debug(f"DEBUG: Socket error in handle_read: {str(e)}")
            return

        self.destination = Peer(*addr)
        encodedAddr = protocol.encodeHost(addr[0])
        self.local = bool(protocol.checkIPAddress(encodedAddr, True))
        logger.debug(f"DEBUG: Received data from {addr}, local: {self.local}")
        
        # overwrite the old buffer to avoid mixing data and so that
        # self.local works correctly
        self.read_buf[0:] = recdata
        logger.debug(f"DEBUG: Updated read_buf length: {len(self.read_buf)}")
        
        self.bm_proto_reset()
        receiveDataQueue.put(self.listening)
        logger.debug("DEBUG: Added listening socket to receiveDataQueue")

    def handle_write(self):
        logger.debug(f"DEBUG: handle_write called, write_buf length: {len(self.write_buf)}")
        try:
            retval = self.socket.sendto(
                self.write_buf, ('<broadcast>', self.port))
            logger.debug(f"DEBUG: Sent {retval} bytes via broadcast")
        except (socket.error, OSError) as e:
            logger.error("socket error on sendto:", exc_info=True)
            logger.debug(f"DEBUG: Socket error in handle_write: {str(e)}")
            retval = len(self.write_buf)
            
        self.slice_write_buf(retval)
        logger.debug(f"DEBUG: Sliced write_buf, new length: {len(self.write_buf)}")
