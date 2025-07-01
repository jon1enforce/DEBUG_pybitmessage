"""
SOCKS4a proxy module
"""
# pylint: disable=attribute-defined-outside-init
import logging
import socket
import struct
import six

from .proxy import GeneralProxyError, Proxy, ProxyError

logger = logging.getLogger('default')


class Socks4aError(ProxyError):
    """SOCKS4a error base class"""
    errorCodes = (
        "Request granted",
        "Request rejected or failed",
        "Request rejected because SOCKS server cannot connect to identd"
        " on the client",
        "Request rejected because the client program and identd report"
        " different user-ids",
        "Unknown error"
    )

    def __init__(self, code):
        super(Socks4aError, self).__init__(code)
        logger.debug("DEBUG: Socks4aError created with code %d: %s", 
                    code, self.errorCodes[code-1])


class Socks4a(Proxy):
    """SOCKS4a proxy class"""
    def __init__(self, address=None):
        logger.debug("DEBUG: Initializing Socks4a with address: %s", address)
        Proxy.__init__(self, address)
        self.ipaddr = None
        self.destport = address[1] if address else None
        logger.debug("DEBUG: Socks4a initialized with destport: %s", self.destport)

    def state_init(self):
        """Protocol initialisation (before connection is established)"""
        logger.debug("DEBUG: Entering state_init for Socks4a")
        self.set_state("auth_done", 0)
        logger.debug("DEBUG: Transitioning directly to auth_done state")
        return True

    def state_pre_connect(self):
        """Handle feedback from SOCKS4a while it is connecting on our behalf"""
        logger.debug("DEBUG: Entering state_pre_connect with read_buf: %s", self.read_buf[:8])
        
        if self.read_buf[0:1] != six.int2byte(0x00):
            logger.error("DEBUG: Invalid null byte in response")
            self.close()
            raise GeneralProxyError(1)
            
        response_code = six.byte2int(self.read_buf[1:2])
        if response_code != 0x5A:
            logger.error("DEBUG: Connection failed with code: %d", response_code)
            self.close()
            if response_code in (91, 92, 93):
                error_code = response_code - 90
                logger.debug("DEBUG: Raising Socks4aError with code %d", error_code)
                raise Socks4aError(error_code)
            else:
                logger.debug("DEBUG: Raising unknown Socks4aError")
                raise Socks4aError(4)
                
        self.boundport = struct.unpack(">H", self.read_buf[2:4])[0]
        self.boundaddr = self.read_buf[4:8]
        self.__proxysockname = (self.boundaddr, self.boundport)
        
        if self.ipaddr:
            self.__proxypeername = (socket.inet_ntoa(self.ipaddr), self.destination[1])
        else:
            self.__proxypeername = (self.destination[0], self.destport)
            
        logger.debug("DEBUG: Connection successful - bound port: %d, bound addr: %s", 
                    self.boundport, self.boundaddr)
        logger.debug("DEBUG: Proxy sockname: %s, peername: %s",
                    self.__proxysockname, self.__proxypeername)
        
        self.set_state("proxy_handshake_done", length=8)
        return True

    def proxy_sock_name(self):
        """Return resolved address when using SOCKS4a for DNS resolving"""
        result = socket.inet_ntoa(self.__proxysockname[0])
        logger.debug("DEBUG: proxy_sock_name returning: %s", result)
        return result


class Socks4aConnection(Socks4a):
    """Child SOCKS4a class used for making outbound connections."""
    def __init__(self, address):
        logger.debug("DEBUG: Initializing Socks4aConnection to %s:%d", 
                    address[0], address[1])
        Socks4a.__init__(self, address=address)

    def state_auth_done(self):
        """Request connection to be made"""
        logger.debug("DEBUG: Socks4aConnection state_auth_done")
        rmtrslv = False
        
        # Build initial connection request
        self.append_write_buf(struct.pack('>BBH', 0x04, 0x01, self.destination[1]))
        logger.debug("DEBUG: Sent SOCKS4a header (version 4, command 1, port %d)", 
                    self.destination[1])
        
        # Handle destination address
        try:
            self.ipaddr = socket.inet_aton(self.destination[0])
            logger.debug("DEBUG: Using IPv4 address: %s", self.destination[0])
            self.append_write_buf(self.ipaddr)
        except socket.error:
            if self._remote_dns:
                logger.debug("DEBUG: Using remote DNS resolution for: %s", self.destination[0])
                rmtrslv = True
                self.ipaddr = None
                self.append_write_buf(struct.pack("BBBB", 0x00, 0x00, 0x00, 0x01))
            else:
                logger.debug("DEBUG: Resolving locally: %s", self.destination[0])
                self.ipaddr = socket.inet_aton(
                    socket.gethostbyname(self.destination[0]))
                self.append_write_buf(self.ipaddr)
        
        # Handle authentication if needed
        if self._auth:
            logger.debug("DEBUG: Adding authentication username")
            self.append_write_buf(self._auth[0])
        
        self.append_write_buf(six.int2byte(0x00))  # Null terminator
        
        if rmtrslv:
            logger.debug("DEBUG: Adding hostname for remote resolution")
            self.append_write_buf(self.destination[0].encode("utf-8", "replace") + six.int2byte(0x00))
        
        self.set_state("pre_connect", length=0, expectBytes=8)
        return True

    def state_pre_connect(self):
        """Tell SOCKS4a to initiate a connection"""
        logger.debug("DEBUG: Socks4aConnection state_pre_connect")
        try:
            return Socks4a.state_pre_connect(self)
        except Socks4aError as e:
            logger.error("DEBUG: Socks4aError in state_pre_connect: %s", e.message)
            self.close_reason = e.message
            self.set_state("close")


class Socks4aResolver(Socks4a):
    """DNS resolver class using SOCKS4a"""
    def __init__(self, host):
        logger.debug("DEBUG: Initializing Socks4aResolver for host: %s", host)
        self.host = host
        self.port = 8444
        Socks4a.__init__(self, address=(self.host, self.port))

    def state_auth_done(self):
        """Request connection to be made"""
        logger.debug("DEBUG: Socks4aResolver state_auth_done")
        
        # Build resolution request
        self.append_write_buf(struct.pack('>BBH', 0x04, 0xF0, self.destination[1]))
        logger.debug("DEBUG: Sent SOCKS4a header (version 4, command F0, port %d)", 
                    self.destination[1])
        
        self.append_write_buf(struct.pack("BBBB", 0x00, 0x00, 0x00, 0x01))
        
        if self._auth:
            logger.debug("DEBUG: Adding authentication username")
            self.append_write_buf(self._auth[0])
        
        self.append_write_buf(six.int2byte(0x00))  # Null terminator
        self.append_write_buf(self.host + six.int2byte(0x00))
        logger.debug("DEBUG: Added hostname for resolution: %s", self.host)
        
        self.set_state("pre_connect", length=0, expectBytes=8)
        return True

    def resolved(self):
        """Log resolved address"""
        resolved_addr = self.proxy_sock_name()
        logger.debug('DEBUG: Resolved %s as %s', self.host, resolved_addr)
        return resolved_addr
