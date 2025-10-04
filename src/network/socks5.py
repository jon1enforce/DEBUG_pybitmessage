"""
SOCKS5 proxy module
"""
# pylint: disable=attribute-defined-outside-init

import logging
import socket
import struct
import six

from .node import Peer
from .proxy import GeneralProxyError, Proxy, ProxyError
# Am Anfang der Datei hinzufügen:
import sys
from .helpers import resolve_hostname, get_socket_family, safe_inet_pton, is_openbsd
logger = logging.getLogger('default')


class Socks5AuthError(ProxyError):
    """Raised when the socks5 protocol encounters an authentication error"""
    errorCodes = (
        "Succeeded",
        "Authentication is required",
        "All offered authentication methods were rejected",
        "Unknown username or invalid password",
        "Unknown error"
    )

    def __init__(self, code):
        super(Socks5AuthError, self).__init__(code)
        logger.debug("DEBUG: Socks5AuthError created with code %d: %s", 
                    code, self.errorCodes[code])


class Socks5Error(ProxyError):
    """Raised when socks5 protocol encounters an error"""
    errorCodes = (
        "Succeeded",
        "General SOCKS server failure",
        "Connection not allowed by ruleset",
        "Network unreachable",
        "Host unreachable",
        "Connection refused",
        "TTL expired",
        "Command not supported",
        "Address type not supported",
        "Unknown error"
    )

    def __init__(self, code):
        super(Socks5Error, self).__init__(code)
        logger.debug("DEBUG: Socks5Error created with code %d: %s", 
                    code, self.errorCodes[code])


class Socks5(Proxy):
    """A socks5 proxy base class"""
    def __init__(self, address=None):
        logger.debug("DEBUG: Initializing Socks5 proxy with address: %s", address)
        Proxy.__init__(self, address)
        self.ipaddr = None
        self.destport = address[1] if address else None
        logger.debug("DEBUG: Socks5 initialized with destport: %s", self.destport)

    def state_init(self):
        """Protocol initialization (before connection is established)"""
        logger.debug("DEBUG: Entering state_init")
        if self._auth:
            logger.debug("DEBUG: Using authentication, sending methods 0x00 and 0x02")
            self.append_write_buf(struct.pack('BBBB', 0x05, 0x02, 0x00, 0x02))
        else:
            logger.debug("DEBUG: No authentication, sending method 0x00")
            self.append_write_buf(struct.pack('BBB', 0x05, 0x01, 0x00))
        
        self.set_state("auth_1", length=0, expectBytes=2)
        logger.debug("DEBUG: Transitioning to state auth_1")
        return True

    def state_auth_1(self):
        """Perform authentication if peer is requesting it."""
        logger.debug("DEBUG: Entering state_auth_1 with read_buf: %s", self.read_buf[:2])
        ret = safe_struct_unpack('BB', self.read_buf[:2])
        if ret[0] != 5:
            logger.error("DEBUG: Invalid SOCKS version: %d", ret[0])
            raise GeneralProxyError(1)
        elif ret[1] == 0:
            logger.debug("DEBUG: No authentication required")
            self.set_state("auth_done", length=2)
        elif ret[1] == 2:
            logger.debug("DEBUG: Username/password authentication required")
            auth_packet = struct.pack('BB', 1, len(self._auth[0])) + self._auth[0] + \
                         struct.pack('B', len(self._auth[1])) + self._auth[1]
            self.append_write_buf(auth_packet)
            self.set_state("auth_needed", length=2, expectBytes=2)
        else:
            if ret[1] == 0xff:
                logger.error("DEBUG: All authentication methods rejected")
                raise Socks5AuthError(2)
            else:
                logger.error("DEBUG: Unknown authentication method: %d", ret[1])
                raise GeneralProxyError(1)
        return True

    def state_auth_needed(self):
        """Handle response to authentication attempt"""
        logger.debug("DEBUG: Entering state_auth_needed with read_buf: %s", self.read_buf[:2])
        ret = safe_struct_unpack('BB', self.safe_bytearray_slice(read_buf, 0, 2))
        if ret[0] != 1:
            logger.error("DEBUG: Invalid authentication version: %d", ret[0])
            raise GeneralProxyError(1)
        if ret[1] != 0:
            logger.error("DEBUG: Authentication failed with code: %d", ret[1])
            raise Socks5AuthError(3)
            
        logger.debug("DEBUG: Authentication successful")
        self.set_state("auth_done", length=2)
        return True

    def state_pre_connect(self):
        """Handle feedback from socks5 while it is connecting on our behalf."""
        logger.debug("DEBUG: Entering state_pre_connect")
        if self.safe_bytearray_slice(read_buf, 0, 1) != six.int2byte(0x05):
            logger.error("DEBUG: Invalid SOCKS version in response")
            self.close()
            raise GeneralProxyError(1)
        elif self.safe_bytearray_slice(read_buf, 1, 2) != six.int2byte(0x00):
            error_code = six.byte2int(self.safe_bytearray_slice(read_buf, 1, 2))
            logger.error("DEBUG: Connection failed with code: %d", error_code)
            self.close()
            if error_code <= 8:
                raise Socks5Error(error_code)
            else:
                raise Socks5Error(9)
                
        addr_type = self.safe_bytearray_slice(read_buf, 3, 4)
        if addr_type == six.int2byte(0x01):
            logger.debug("DEBUG: IPv4 address type received")
            self.set_state("proxy_addr_1", length=4, expectBytes=4)
        elif addr_type == six.int2byte(0x03):
            logger.debug("DEBUG: Domain name address type received")
            self.set_state("proxy_addr_2_1", length=4, expectBytes=1)
        else:
            logger.error("DEBUG: Unsupported address type: %s", addr_type)
            self.close()
            raise GeneralProxyError(1)
        return True

    def state_proxy_addr_1(self):
        """Handle IPv4 address returned for peer"""
        self.boundaddr = self.safe_bytearray_slice(read_buf, 0, 4)
        logger.debug("DEBUG: Received IPv4 bound address: %s", self.boundaddr)
        self.set_state("proxy_port", length=4, expectBytes=2)
        return True

    def state_proxy_addr_2_1(self):
        """Handle domain name length"""
        self.address_length = six.byte2int(self.safe_bytearray_slice(read_buf, 0, 1))
        logger.debug("DEBUG: Received domain name length: %d", self.address_length)
        self.set_state("proxy_addr_2_2", length=1, expectBytes=self.address_length)
        return True

    def state_proxy_addr_2_2(self):
        """Handle domain name"""
        self.boundaddr = self.read_buf[0:self.address_length]
        logger.debug("DEBUG: Received domain name: %s", self.boundaddr)
        self.set_state("proxy_port", length=self.address_length, expectBytes=2)
        return True

    def state_proxy_port(self):
        """Handle peer's port being returned."""
        self.boundport = safe_struct_unpack(">H", self.safe_bytearray_slice(read_buf, 0, 2))[0]
        logger.debug("DEBUG: Received bound port: %d", self.boundport)
        
        self.__proxysockname = (self.boundaddr, self.boundport)
        if self.ipaddr is not None:
            self.__proxypeername = (socket.inet_ntoa(self.ipaddr), self.destination[1])
        else:
            self.__proxypeername = (self.destination[0], self.destport)
            
        logger.debug("DEBUG: Proxy sockname: %s, peername: %s", 
                    self.__proxysockname, self.__proxypeername)
        
        self.set_state("proxy_handshake_done", length=2)
        return True

    def proxy_sock_name(self):
        """Return resolved address when using SOCKS5 for DNS resolving"""
        result = socket.inet_ntoa(self.__proxysockname[0])
        logger.debug("DEBUG: proxy_sock_name returning: %s", result)
        return result


class Socks5Connection(Socks5):
    """Child socks5 class used for making outbound connections."""
    def state_auth_done(self):
        """Request connection to be made"""
        logger.debug("DEBUG: Socks5Connection state_auth_done")
        self.append_write_buf(struct.pack('BBB', 0x05, 0x01, 0x00))
        
        # Importiere die Hilfsfunktion
        from .helpers import resolve_hostname, get_socket_family
        
        try:
            # Versuche zuerst IPv4
            try:
                self.ipaddr = socket.inet_pton(socket.AF_INET, self.destination[0])
                addr_type = 0x01  # IPv4
            except (socket.error, OSError, ValueError):
                # Fallback: Versuche IPv6
                try:
                    self.ipaddr = socket.inet_pton(socket.AF_INET6, self.destination[0])
                    addr_type = 0x04  # IPv6
                except (socket.error, OSError, ValueError):
                    # Hostname - verwende DNS
                    self.ipaddr = None
                    addr_type = 0x03  # Hostname
                    
                    # OpenBSD-kompatible Hostname-Auflösung
                    resolved_host = resolve_hostname(self.destination[0])
                    if resolved_host != self.destination[0]:
                        # Hostname wurde aufgelöst, versuche erneut mit IP
                        try:
                            family = get_socket_family(resolved_host)
                            self.ipaddr = socket.inet_pton(family, resolved_host)
                            addr_type = 0x01 if family == socket.AF_INET else 0x04
                        except (socket.error, OSError, ValueError):
                            # Bleibe bei Hostname
                            pass
        
        except Exception as e:
            logger.debug("DEBUG: Error in address resolution: %s", str(e))
            self.ipaddr = None
            addr_type = 0x03  # Hostname als Fallback
        
        # Je nach Adresstyp den entsprechenden SOCKS5 Befehl konstruieren
        if addr_type == 0x01:  # IPv4
            self.append_write_buf(six.int2byte(addr_type) + self.ipaddr)
        elif addr_type == 0x04:  # IPv6
            self.append_write_buf(six.int2byte(addr_type) + self.ipaddr)
        else:  # Hostname (0x03)
            if self._remote_dns:
                logger.debug("DEBUG: Using remote DNS for: %s", self.destination[0])
                hostname_encoded = self.destination[0].encode("utf-8", "replace")
                self.append_write_buf(six.int2byte(addr_type) + 
                                    six.int2byte(len(hostname_encoded)) + 
                                    hostname_encoded)
            else:
                logger.debug("DEBUG: Resolving locally: %s", self.destination[0])
                try:
                    # OpenBSD-kompatible Auflösung
                    resolved_ip = resolve_hostname(self.destination[0])
                    family = get_socket_family(resolved_ip)
                    
                    if family == socket.AF_INET:
                        self.ipaddr = socket.inet_aton(resolved_ip)
                        self.append_write_buf(six.int2byte(0x01) + self.ipaddr)
                    elif family == socket.AF_INET6:
                        self.ipaddr = socket.inet_pton(socket.AF_INET6, resolved_ip)
                        self.append_write_buf(six.int2byte(0x04) + self.ipaddr)
                    else:
                        # Fallback zu Remote DNS
                        hostname_encoded = self.destination[0].encode("utf-8", "replace")
                        self.append_write_buf(six.int2byte(0x03) + 
                                            six.int2byte(len(hostname_encoded)) + 
                                            hostname_encoded)
                except Exception as e:
                    logger.debug("DEBUG: Local resolution failed: %s", str(e))
                    # Fallback zu Remote DNS
                    hostname_encoded = self.destination[0].encode("utf-8", "replace")
                    self.append_write_buf(six.int2byte(0x03) + 
                                        six.int2byte(len(hostname_encoded)) + 
                                        hostname_encoded)
        
        # Port immer anhängen
        self.append_write_buf(struct.pack(">H", self.destination[1]))
        self.set_state("pre_connect", length=0, expectBytes=4)
        return True

    def state_pre_connect(self):
        """Tell socks5 to initiate a connection"""
        logger.debug("DEBUG: Socks5Connection state_pre_connect")
        try:
            return Socks5.state_pre_connect(self)
        except Socks5Error as e:
            logger.error("DEBUG: Socks5Error in state_pre_connect: %s", e.message)
            self.close_reason = e.message
            self.set_state("close")


class Socks5Resolver(Socks5):
    """DNS resolver class using socks5"""
    def __init__(self, host):
        logger.debug("DEBUG: Initializing Socks5Resolver for host: %s", host)
        self.host = host
        self.port = 8444
        Socks5.__init__(self, address=Peer(self.host, self.port))

    def state_auth_done(self):
        """Perform resolving"""
        logger.debug("DEBUG: Socks5Resolver state_auth_done")
        self.append_write_buf(struct.pack('BBB', 0x05, 0xF0, 0x00))
        self.append_write_buf(six.int2byte(0x03) + six.int2byte(
            len(self.host)) + bytes(self.host))
        self.append_write_buf(struct.pack(">H", self.port))
        self.set_state("pre_connect", length=0, expectBytes=4)
        return True

    def resolved(self):
        """Log resolved address"""
        resolved_addr = self.proxy_sock_name()
        logger.debug('DEBUG: Resolved %s as %s', self.host, resolved_addr)
        return resolved_addr
