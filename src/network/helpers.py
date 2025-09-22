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
        # Fallback für OpenBSD und andere Systeme
        try:
            return socket.gethostbyname(hostname)
        except (socket.error, OSError, TypeError, socket.gaierror):
            # Final fallback - return hostname as is
            return hostname

def get_socket_family(host):
    """Get socket family for host with OpenBSD fixes"""
    if host is None:
        # Critical fix: Default to IPv4 instead of failing
        return socket.AF_INET
    
    # Handle empty string case
    if host == "":
        return socket.AF_INET
    
    # Try IPv6 first
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return socket.AF_INET6
    except (socket.error, OSError, AttributeError, TypeError):
        pass
    
    # Try IPv4
    try:
        socket.inet_pton(socket.AF_INET, host)
        return socket.AF_INET
    except (socket.error, OSError, AttributeError, TypeError):
        pass
    
    # If it's a hostname, try to resolve it
    try:
        resolved_ip = resolve_hostname(host)
        if resolved_ip and resolved_ip != host:
            # Recursively try with resolved IP
            return get_socket_family(resolved_ip)
    except:
        pass
    
    # Final fallback: IPv4
    return socket.AF_INET

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
        except (socket.error, OSError, AttributeError):
            pass
    return sock

def inet_aton_openbsd(host):
    """OpenBSD-compatible inet_aton implementation"""
    if host is None:
        raise ValueError("Host cannot be None")
    
    try:
        # First try standard inet_pton for IPv4
        return socket.inet_pton(socket.AF_INET, host)
    except (socket.error, OSError, AttributeError):
        # Fallback to traditional method
        try:
            return socket.inet_aton(host)
        except (socket.error, OSError, AttributeError):
            # Manual parsing as last resort
            parts = host.split('.')
            if len(parts) == 4:
                try:
                    return pack('!BBBB', *[int(p) for p in parts])
                except (ValueError, TypeError):
                    pass
            raise

def safe_inet_pton(address):
    """Safe version of inet_pton that works on all platforms"""
    if address is None:
        return None, None
        
    # Try IPv4 first
    try:
        return socket.inet_pton(socket.AF_INET, address), socket.AF_INET
    except (socket.error, OSError, ValueError, AttributeError, TypeError):
        pass
    
    # Try IPv6 as fallback
    try:
        return socket.inet_pton(socket.AF_INET6, address), socket.AF_INET6
    except (socket.error, OSError, ValueError, AttributeError, TypeError):
        pass
    
    return None, None

# New function to handle OpenBSD-specific network initialization
def get_default_bind_address():
    """Get default bind address for OpenBSD compatibility"""
    if is_openbsd():
        # OpenBSD: try to get actual IP, fallback to localhost
        try:
            # Get hostname and resolve it
            hostname = socket.gethostname()
            try:
                ip = socket.gethostbyname(hostname)
                if ip and ip != "127.0.0.1":
                    return ip
            except:
                pass
            
            # Try to get external interface IP
            try:
                # Create temporary socket to get local IP
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    return s.getsockname()[0]
            except:
                pass
        except:
            pass
        
        # Final fallback for OpenBSD
        return "0.0.0.0"
    else:
        # Default for other systems
        return "0.0.0.0"

# Additional helper for OpenBSD network detection
def detect_openbsd_network_settings():
    """Detect OpenBSD-specific network settings"""
    if not is_openbsd():
        return {}
    
    settings = {}
    try:
        # Try to detect available network interfaces
        import netifaces
        interfaces = netifaces.interfaces()
        for interface in interfaces:
            addrs = netifaces.ifaddresses(interface)
            if netifaces.AF_INET in addrs:
                ip_info = addrs[netifaces.AF_INET][0]
                settings[interface] = ip_info['addr']
    except ImportError:
        # netifaces not available, use socket-based detection
        try:
            hostname = socket.gethostname()
            settings['hostname'] = hostname
            settings['localhost'] = "127.0.0.1"
            settings['default_bind'] = "0.0.0.0"
        except:
            pass
    
    return settings
