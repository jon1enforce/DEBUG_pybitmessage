"""
SOCKS4a proxy module
"""
# pylint: disable=attribute-defined-outside-init
import logging
import socket
import struct
import six

import sys
from .helpers import resolve_hostname, get_socket_family, safe_inet_pton, is_openbsd
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
        
        if self.safe_bytearray_slice(read_buf, 0, 1) != six.int2byte(0x00):
            logger.error("DEBUG: Invalid null byte in response")
            self.close()
            raise GeneralProxyError(1)
            
        response_code = six.byte2int(self.safe_bytearray_slice(read_buf, 1, 2))
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
                
        self.boundport = safe_struct_unpack(">H", self.safe_bytearray_slice(read_buf, 2, 4))[0]
        self.boundaddr = self.safe_bytearray_slice(read_buf, 4, 8)
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
        
        # Importiere die Hilfsfunktionen
        from .helpers import resolve_hostname, get_socket_family, safe_inet_pton
        
        # Build initial connection request
        self.append_write_buf(struct.pack('>BBH', 0x04, 0x01, self.destination[1]))
        logger.debug("DEBUG: Sent SOCKS4a header (version 4, command 1, port %d)", 
                    self.destination[1])
        
        # Handle destination address - OpenBSD-kompatible Auflösung
        try:
            # Versuche direkte IP-Adressen-Erkennung
            ipaddr_result, addr_family = safe_inet_pton(self.destination[0])
            
            if ipaddr_result is not None:
                # Direkte IP-Adresse erkannt
                self.ipaddr = ipaddr_result
                logger.debug("DEBUG: Direct IP address detected: %s", self.destination[0])
                self.append_write_buf(self.ipaddr)
            else:
                # Hostname - muss aufgelöst werden
                logger.debug("DEBUG: Hostname detected, resolving: %s", self.destination[0])
                
                if self._remote_dns:
                    # Remote DNS Auflösung verwenden
                    logger.debug("DEBUG: Using remote DNS resolution for: %s", self.destination[0])
                    rmtrslv = True
                    self.ipaddr = None
                    self.append_write_buf(struct.pack("BBBB", 0x00, 0x00, 0x00, 0x01))
                else:
                    # Lokale Auflösung versuchen
                    try:
                        resolved_ip = resolve_hostname(self.destination[0])
                        logger.debug("DEBUG: Resolved %s to %s", self.destination[0], resolved_ip)
                        
                        # Überprüfe ob die aufgelöste Adresse eine IP ist
                        ipaddr_result, addr_family = safe_inet_pton(resolved_ip)
                        if ipaddr_result is not None:
                            self.ipaddr = ipaddr_result
                            self.append_write_buf(self.ipaddr)
                            logger.debug("DEBUG: Successfully resolved and using IP: %s", resolved_ip)
                        else:
                            # Aufgelöster Wert ist kein gültige IP, verwende Remote DNS
                            logger.debug("DEBUG: Resolved value is not a valid IP, using remote DNS")
                            rmtrslv = True
                            self.ipaddr = None
                            self.append_write_buf(struct.pack("BBBB", 0x00, 0x00, 0x00, 0x01))
                            
                    except (socket.error, OSError, Exception) as e:
                        logger.debug("DEBUG: Local resolution failed: %s, using remote DNS", str(e))
                        rmtrslv = True
                        self.ipaddr = None
                        self.append_write_buf(struct.pack("BBBB", 0x00, 0x00, 0x00, 0x01))
                        
        except (socket.error, OSError, Exception) as e:
            logger.debug("DEBUG: Address resolution error: %s, using remote DNS as fallback", str(e))
            rmtrslv = True
            self.ipaddr = None
            self.append_write_buf(struct.pack("BBBB", 0x00, 0x00, 0x00, 0x01))
        
        # Handle authentication if needed
        if self._auth:
            logger.debug("DEBUG: Adding authentication username: %s", self._auth[0])
            self.append_write_buf(self._auth[0])
        
        self.append_write_buf(six.int2byte(0x00))  # Null terminator
        
        if rmtrslv:
            logger.debug("DEBUG: Adding hostname for remote resolution: %s", self.destination[0])
            try:
                hostname_encoded = self.destination[0].encode("utf-8", "replace")
                self.append_write_buf(hostname_encoded + six.int2byte(0x00))
            except UnicodeError:
                # Fallback für nicht-UTF-8 Hostnames
                logger.debug("DEBUG: UTF-8 encoding failed, using raw bytes")
                self.append_write_buf(self.destination[0].encode("latin-1", "replace") + six.int2byte(0x00))
        
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
