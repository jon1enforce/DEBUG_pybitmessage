import socket
import logging
from .advanceddispatcher import AdvancedDispatcher
from network import asyncore_pollchoose as asyncore
from .proxy import ProxyError
from .socks5 import Socks5Connection, Socks5Resolver
from .socks4a import Socks4aConnection, Socks4aResolver

# Initialize logger
logger = logging.getLogger('default')

class HttpError(ProxyError):
    pass


class HttpConnection(AdvancedDispatcher):
    def __init__(self, host, path="/"):     # pylint: disable=redefined-outer-name
        logger.debug("DEBUG: Initializing HttpConnection to %s%s", host, path)
        AdvancedDispatcher.__init__(self)
        self.path = path
        self.destination = (host, 80)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.debug("DEBUG: Attempting connection to %s:%i", *self.destination)
        self.connect(self.destination)
        logger.debug("DEBUG: Background connection initiated to %s:%i", *self.destination)

    def state_init(self):
        request = "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (
            self.path, self.destination[0])
        self.append_write_buf(request)
        logger.debug("DEBUG: Sending HTTP request (%d bytes):\n%s", 
                   len(request), request.strip())
        self.set_state("http_request_sent", 0)
        return False

    def state_http_request_sent(self):
        if self.read_buf:
            logger.debug("DEBUG: Received %d bytes of HTTP response", len(self.read_buf))
            logger.debug("DEBUG: Response data (first 200 bytes): %s", 
                       self.read_buf[:200].decode('ascii', errors='replace'))
            self.read_buf = b""
        if not self.connected:
            logger.debug("DEBUG: Connection closed by remote")
            self.set_state("close", 0)
        return False


class Socks5HttpConnection(Socks5Connection, HttpConnection):
    def __init__(self, host, path="/"):     # pylint: disable=super-init-not-called, redefined-outer-name
        logger.debug("DEBUG: Initializing Socks5HttpConnection to %s%s", host, path)
        self.path = path
        Socks5Connection.__init__(self, address=(host, 80))
        logger.debug("DEBUG: Socks5HttpConnection initialized")

    def state_socks_handshake_done(self):
        logger.debug("DEBUG: SOCKS5 handshake complete, switching to HTTP")
        HttpConnection.state_init(self)
        return False


class Socks4aHttpConnection(Socks4aConnection, HttpConnection):
    def __init__(self, host, path="/"):     # pylint: disable=super-init-not-called, redefined-outer-name
        logger.debug("DEBUG: Initializing Socks4aHttpConnection to %s%s", host, path)
        Socks4aConnection.__init__(self, address=(host, 80))
        self.path = path
        logger.debug("DEBUG: Socks4aHttpConnection initialized")

    def state_socks_handshake_done(self):
        logger.debug("DEBUG: SOCKS4a handshake complete, switching to HTTP")
        HttpConnection.state_init(self)
        return False


if __name__ == "__main__":
    logger.debug("DEBUG: Starting HTTP test script")
    
    # Test SOCKS5 and SOCKS4a resolvers
    for host in ("bootstrap8080.bitmessage.org", "bootstrap8444.bitmessage.org"):
        logger.debug("DEBUG: Testing SOCKS5 resolver for %s", host)
        proxy = Socks5Resolver(host=host)
        while asyncore.socket_map:
            logger.debug("DEBUG: SOCKS5 loop - state: %s, connections: %d", 
                       proxy.state, len(asyncore.socket_map))
            asyncore.loop(timeout=1, count=1)
        proxy.resolved()
        logger.debug("DEBUG: SOCKS5 resolution complete for %s", host)

        logger.debug("DEBUG: Testing SOCKS4a resolver for %s", host)
        proxy = Socks4aResolver(host=host)
        while asyncore.socket_map:
            logger.debug("DEBUG: SOCKS4a loop - state: %s, connections: %d", 
                       proxy.state, len(asyncore.socket_map))
            asyncore.loop(timeout=1, count=1)
        proxy.resolved()
        logger.debug("DEBUG: SOCKS4a resolution complete for %s", host)

    # Test direct and proxied connections
    for host in ("bitmessage.org",):
        logger.debug("DEBUG: Testing direct HTTP connection to %s", host)
        direct = HttpConnection(host)
        while asyncore.socket_map:
            logger.debug("DEBUG: Direct connection state: %s", direct.state)
            asyncore.loop(timeout=1, count=1)
        logger.debug("DEBUG: Direct HTTP test complete")

        logger.debug("DEBUG: Testing SOCKS5 HTTP connection to %s", host)
        proxy = Socks5HttpConnection(host)
        while asyncore.socket_map:
            logger.debug("DEBUG: SOCKS5 HTTP state: %s", proxy.state)
            asyncore.loop(timeout=1, count=1)
        logger.debug("DEBUG: SOCKS5 HTTP test complete")

        logger.debug("DEBUG: Testing SOCKS4a HTTP connection to %s", host)
        proxy = Socks4aHttpConnection(host)
        while asyncore.socket_map:
            logger.debug("DEBUG: SOCKS4a HTTP state: %s", proxy.state)
            asyncore.loop(timeout=1, count=1)
        logger.debug("DEBUG: SOCKS4a HTTP test complete")

    logger.debug("DEBUG: HTTP test script completed")
