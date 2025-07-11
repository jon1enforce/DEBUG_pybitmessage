"""
UDP protocol handler with comprehensive debugging
"""
import logging
import socket
import time
from typing import Optional, Tuple, Union

# magic imports!
import protocol
import state
import network.connectionpool  # use long name to address recursive import

from network import receiveDataQueue
from .bmproto import BMProto
from .node import Peer
from .objectracker import ObjectTracker


logger = logging.getLogger('default')


class UDPSocket(BMProto):  # pylint: disable=too-many-instance-attributes
    """Bitmessage protocol over UDP (class) with enhanced debugging"""
    port = 8444

    def __init__(self, host: Optional[str] = None, sock: Optional[socket.socket] = None, 
                 announcing: bool = False):
        """Initialize UDP socket with comprehensive debugging"""
        logger.debug("UDP_INIT| Initializing UDPSocket with host=%s, sock=%s, announcing=%s", 
                    host, sock, announcing)
        
        try:
            # pylint: disable=bad-super-call
            super(BMProto, self).__init__(sock=sock)
            self.verackReceived = True
            self.verackSent = True
            self.streams = [1]
            self.fullyEstablished = True
            self.skipUntil = 0
            
            if sock is None:
                socket_family = socket.AF_INET6 if host and ":" in host else socket.AF_INET
                logger.debug("UDP_SOCKET| Creating new UDP socket with family %s", socket_family)
                
                try:
                    self.create_socket(socket_family, socket.SOCK_DGRAM)
                    self.set_socket_reuse()
                    logger.info("UDP_BIND| Binding to %s:%i", host or '0.0.0.0', self.port)
                    
                    bind_host = host if host is not None and host != '' else '0.0.0.0'                    
                    self.socket.bind((bind_host, self.port))
                    logger.debug("UDP_SOCKET| Socket bind successful to %s:%i", bind_host, self.port)
                except socket.error as e:
                    logger.error("UDP_ERROR| Socket bind failed to %s:%i - %s", 
                                bind_host, self.port, e)
                    raise
            else:
                logger.debug("UDP_SOCKET| Using provided socket: %s", sock)
                self.socket = sock
                self.set_socket_reuse()
            
            try:
                sockname = self.socket.getsockname()
                self.listening = Peer(*sockname)
                self.destination = Peer(*sockname)
                logger.debug("UDP_SOCKET| Socket listening on %s:%i", 
                            self.listening.host, self.listening.port)
            except socket.error as e:
                logger.error("UDP_ERROR| Error getting socket name: %s", e)
                raise
            
            ObjectTracker.__init__(self)
            self.connecting = False
            self.connected = True
            self.announcing = announcing
            logger.debug("UDP_INIT| Initialization complete - announcing=%s, connected=%s", 
                        announcing, self.connected)
            self.set_state("bm_header", expectBytes=protocol.Header.size)
            
        except Exception as e:
            logger.error("UDP_CRITICAL| Initialization failed: %s", e, exc_info=True)
            raise

    def set_socket_reuse(self) -> None:
        """Set socket reuse options with detailed debugging"""
        logger.debug("UDP_SOCKET| Setting socket reuse options")
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            logger.debug("UDP_SOCKET| SO_BROADCAST set successfully")
            
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            logger.debug("UDP_SOCKET| SO_REUSEADDR set successfully")
            
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                logger.debug("UDP_SOCKET| SO_REUSEPORT set successfully")
            except AttributeError:
                logger.debug("UDP_SOCKET| SO_REUSEPORT not available on this platform")
                
        except socket.error as e:
            logger.error("UDP_ERROR| Error setting socket options: %s", e)
            raise

    def bm_command_addr(self) -> bool:
        """Handle addr command with detailed debugging"""
        logger.debug("UDP_CMD| Processing addr command from %s:%i", 
                   self.destination.host, self.destination.port)
        
        try:
            addresses = self._decode_addr()
            if not addresses:
                logger.debug("UDP_CMD| No addresses decoded from addr command")
                return True
                
            logger.debug("UDP_CMD| Decoded %d addresses from %s:%i", 
                       len(addresses), self.destination.host, self.destination.port)
            
            if not self.local:
                logger.debug("UDP_SECURITY| Rejecting addr from non-local IP: %s", 
                           self.destination.host)
                return True
                
            remoteport = False
            for seenTime, stream, _, ip, port in addresses:
                logger.debug("UDP_ADDR| Processing address - IP: %s, port: %s, stream: %s", 
                           ip, port, stream)
                
                decodedIP = protocol.checkIPAddress(ip)
                if stream not in network.connectionpool.pool.streams:
                    logger.debug("UDP_STREAM| Stream %s not in our streams (%s), skipping", 
                               stream, network.connectionpool.pool.streams)
                    continue
                    
                if (seenTime < time.time() - protocol.MAX_TIME_OFFSET or 
                    seenTime > time.time() + protocol.MAX_TIME_OFFSET):
                    logger.debug("UDP_TIME| Timestamp %s out of allowed range, skipping", seenTime)
                    continue
                    
                if decodedIP is False:
                    remoteport = port
                    logger.debug("UDP_ADDR| Found remote port announcement: %s", remoteport)
                    
            if remoteport is False:
                logger.debug("UDP_ADDR| No valid remote port found in addr message")
                return True
                
            logger.info("UDP_PEER| Received peer discovery from %s:%i (port %i)",
                      self.destination.host, self.destination.port, remoteport)
            state.discoveredPeers[Peer(self.destination.host, remoteport)] = time.time()
            logger.debug("UDP_PEER| Added peer %s:%i to discoveredPeers at %s", 
                       self.destination.host, remoteport, time.time())
            
        except Exception as e:
            logger.error("UDP_ERROR| Error processing addr command: %s", e, exc_info=True)
            
        return True

    def handle_read(self) -> None:
        """Handle incoming UDP data with detailed debugging"""
        try:
            logger.debug("UDP_READ| Waiting for data from socket")
            recdata, addr = self.socket.recvfrom(self._buf_len)
            logger.debug("UDP_READ| Received %d bytes from %s:%i", 
                       len(recdata), addr[0], addr[1])
            
            self.destination = Peer(*addr)
            encodedAddr = protocol.encodeHost(addr[0])
            self.local = bool(protocol.checkIPAddress(encodedAddr, True))
            logger.debug("UDP_READ| Source: %s, local: %s, encoded: %s", 
                       addr, self.local, encodedAddr)
            
            self.read_buf[0:] = recdata
            logger.debug("UDP_READ| Updated read_buf length to %d bytes", len(self.read_buf))
            
            self.bm_proto_reset()
            receiveDataQueue.put(self.listening)
            logger.debug("UDP_READ| Added socket %s to receiveDataQueue", self.listening)
            
        except socket.error as e:
            logger.error("UDP_ERROR| Socket recvfrom error: %s", e, exc_info=True)
        except Exception as e:
            logger.error("UDP_CRITICAL| Unexpected read error: %s", e, exc_info=True)

    def handle_write(self) -> None:
        """Handle outgoing UDP data with detailed debugging"""
        try:
            if not self.write_buf:
                logger.debug("UDP_WRITE| No data to write")
                return
                
            logger.debug("UDP_WRITE| Sending %d bytes via broadcast to port %i", 
                       len(self.write_buf), self.port)
            
            try:
                retval = self.socket.sendto(self.write_buf, ('<broadcast>', self.port))
                if retval <= 0:  # Explizite Fehlerprüfung
                    logger.warning("UDP_WARN| Send failed, bytes sent: %d", retval)
                    retval = len(self.write_buf)  # Wie alte Version: Vollständigen Puffer verwerfen
                self.slice_write_buf(retval)
            except socket.error as e:
                logger.error("UDP_ERROR| Broadcast send failed: %s", e)
                self.slice_write_buf(len(self.write_buf))  # Puffer komplett leeren
                # Optional: Socket neu initialisieren falls persistente Fehler
            
        except socket.error as e:
            logger.error("UDP_ERROR| Socket sendto error: %s", e, exc_info=True)
            self.slice_write_buf(len(self.write_buf))
        except Exception as e:
            logger.error("UDP_CRITICAL| Unexpected write error: %s", e, exc_info=True)

    def writable(self) -> bool:
        """Check if socket is writable with debugging"""
        result = bool(self.write_buf)
        logger.debug("UDP_STATE| writable=%s (write_buf: %d bytes)", 
                   result, len(self.write_buf))
        return result

    def readable(self) -> bool:
        """Check if socket is readable with debugging"""
        result = len(self.read_buf) < self._buf_len
        logger.debug("UDP_STATE| readable=%s (read_buf: %d/%d bytes)", 
                   result, len(self.read_buf), self._buf_len)
        return result

    # Disabled commands with debug logging
    def bm_command_getdata(self) -> bool:
        logger.debug("UDP_CMD| getdata called (disabled)")
        return True

    def bm_command_inv(self) -> bool:
        logger.debug("UDP_CMD| inv called (disabled)")
        return True

    def bm_command_portcheck(self) -> bool:
        logger.debug("UDP_CMD| portcheck called (disabled)")
        return True

    def bm_command_ping(self) -> bool:
        logger.debug("UDP_CMD| ping called (disabled)")
        return True

    def bm_command_pong(self) -> bool:
        logger.debug("UDP_CMD| pong called (disabled)")
        return True

    def bm_command_verack(self) -> bool:
        logger.debug("UDP_CMD| verack called (disabled)")
        return True

    def bm_command_version(self) -> bool:
        logger.debug("UDP_CMD| version called (disabled)")
        return True

    def handle_connect(self) -> None:
        logger.debug("UDP_STATE| handle_connect called (no-op for UDP)")
