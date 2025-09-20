import socket
import sys
from struct import pack
def resolve_hostname(hostname):
    """Resolve hostname in a cross-platform compatible way"""
    if not hostname:
        return hostname
    
    try:
        # Prefer getaddrinfo for IPv4/IPv6 compatibility
        addr_info = socket.getaddrinfo(hostname, None)
        return addr_info[0][4][0]  # Return first IPv4/IPv6 address
    except (socket.gaierror, OSError, IndexError, TypeError):
        # Fallback to gethostbyname for older systems
        try:
            return socket.gethostbyname(hostname)
        except (socket.error, OSError, TypeError):
            return hostname  # Final fallback

def get_socket_family(host):
    """Robust socket family detection for OpenBSD compatibility"""
    if not host:
        return socket.AF_INET
    
    try:
        # Try IPv6 first
        socket.inet_pton(socket.AF_INET6, host)
        return socket.AF_INET6
    except (socket.error, OSError, ValueError, AttributeError):
        try:
            # Try IPv4
            socket.inet_pton(socket.AF_INET, host)
            return socket.AF_INET
        except (socket.error, OSError, ValueError, AttributeError):
            # Fallback to simple detection
            return socket.AF_INET6 if ":" in host else socket.AF_INET
def is_openbsd():
    """Check if running on OpenBSD"""
    return sys.platform.startswith('openbsd') or 'openbsd' in sys.platform.lower()

def openbsd_socket_compat(sock):
    """OpenBSD-specific socket compatibility fixes"""
    if is_openbsd():
        try:
            # OpenBSD-spezifische Einstellungen
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            # Set smaller buffer sizes for better performance on OpenBSD
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
        except (socket.error, OSError):
            pass
    return sock
    
    
def inet_aton_openbsd(host):
    if is_openbsd():
        # OpenBSD-spezifische Implementierung
        try:
            return socket.inet_pton(socket.AF_INET, host)
        except (socket.error, OSError, AttributeError):
            # Fallback zu traditioneller Methode
            try:
                return socket.inet_aton(host)
            except (socket.error, OSError):
                # Finaler Fallback - manuelles Parsen
                parts = host.split('.')
                if len(parts) == 4:
                    try:
                        return pack('!BBBB', *[int(p) for p in parts])
                    except (ValueError, TypeError):
                        pass
                raise
    else:
        # Auf anderen Plattformen die Standardfunktion verwenden
        try:
            return socket.inet_aton(host)
        except (socket.error, OSError):
            # Fallback für IPv6-mapped IPv4 addresses?
            raise
def safe_inet_pton(address):
    """Safe version of inet_pton that works on all platforms"""
    # Try IPv4 first (more common for SOCKS4a)
    try:
        return socket.inet_pton(socket.AF_INET, address), socket.AF_INET
    except (socket.error, OSError, ValueError, AttributeError):
        # Try IPv6 as fallback (though SOCKS4a officially doesn't support it)
        try:
            return socket.inet_pton(socket.AF_INET6, address), socket.AF_INET6
        except (socket.error, OSError, ValueError, AttributeError):
            return None, None    
