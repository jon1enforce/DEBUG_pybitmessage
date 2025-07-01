"""
src/network/httpd.py
=======================
"""
import asyncore
import socket
import logging
from tls import TLSHandshake

# Initialize logger
logger = logging.getLogger('default')

class HTTPRequestHandler(asyncore.dispatcher):
    """Handling HTTP request"""
    response = """HTTP/1.0 200 OK\r
    Date: Sun, 23 Oct 2016 18:02:00 GMT\r
    Content-Type: text/html; charset=UTF-8\r
    Content-Encoding: UTF-8\r
    Content-Length: 136\r
    Last-Modified: Wed, 08 Jan 2003 23:11:55 GMT\r
    Server: Apache/1.3.3.7 (Unix) (Red-Hat/Linux)\r
    ETag: "3f80f-1b6-3e1cb03b"\r
    Accept-Ranges: bytes\r
    Connection: close\r
    \r
    <html>
    <head>
      <title>An Example Page</title>
    </head>
      <body>
         Hello World, this is a very simple HTML document.
      </body>
    </html>"""

    def __init__(self, sock):
        logger.debug("DEBUG: Initializing HTTPRequestHandler")
        if not hasattr(self, '_map'):
            asyncore.dispatcher.__init__(self, sock)
        self.inbuf = ""
        self.ready = True
        self.busy = False
        self.respos = 0
        logger.debug("DEBUG: HTTPRequestHandler initialized - ready: %s, busy: %s", 
                    self.ready, self.busy)

    def handle_close(self):
        logger.debug("DEBUG: HTTPRequestHandler closing connection")
        self.close()
        logger.debug("DEBUG: Connection closed")

    def readable(self):
        logger.debug("DEBUG: Checking readable state: %s", self.ready)
        return self.ready

    def writable(self):
        logger.debug("DEBUG: Checking writable state: %s", self.busy)
        return self.busy

    def handle_read(self):
        logger.debug("DEBUG: Handling HTTP read")
        data = self.recv(8192)
        self.inbuf += data
        logger.debug("DEBUG: Received %d bytes, total buffer: %d bytes", 
                    len(data), len(self.inbuf))
        
        if self.inbuf[-4:] == "\r\n\r\n":
            logger.debug("DEBUG: Detected end of HTTP headers")
            self.busy = True
            self.ready = False
            self.inbuf = ""
            logger.debug("DEBUG: Ready for response, buffer cleared")
        elif self.inbuf == "":
            logger.debug("DEBUG: Empty read, connection may be closing")

    def handle_write(self):
        if self.busy and self.respos < len(HTTPRequestHandler.response):
            logger.debug("DEBUG: Sending HTTP response")
            written = self.send(HTTPRequestHandler.response[self.respos:65536])
            self.respos += written
            logger.debug("DEBUG: Sent %d bytes, total sent: %d/%d", 
                        written, self.respos, len(HTTPRequestHandler.response))
        elif self.busy:
            logger.debug("DEBUG: HTTP response complete")
            self.busy = False
            self.ready = True
            self.close()


class HTTPSRequestHandler(HTTPRequestHandler, TLSHandshake):
    """Handling HTTPS request"""
    def __init__(self, sock):
        logger.debug("DEBUG: Initializing HTTPSRequestHandler")
        if not hasattr(self, '_map'):
            asyncore.dispatcher.__init__(self, sock)  # pylint: disable=non-parent-init-called
        
        logger.debug("DEBUG: Initializing TLSHandshake")
        TLSHandshake.__init__(
            self,
            sock=sock,
            certfile='/home/shurdeek/src/PyBitmessage/src/sslkeys/cert.pem',
            keyfile='/home/shurdeek/src/PyBitmessage/src/sslkeys/key.pem',
            server_side=True)
        
        logger.debug("DEBUG: Initializing HTTPRequestHandler")
        HTTPRequestHandler.__init__(self, sock)
        logger.debug("DEBUG: HTTPSRequestHandler initialized")

    def handle_connect(self):
        logger.debug("DEBUG: Handling HTTPS connect")
        TLSHandshake.handle_connect(self)
        logger.debug("DEBUG: TLSHandshake.connect completed")

    def handle_close(self):
        logger.debug("DEBUG: Handling HTTPS close")
        if self.tlsDone:
            logger.debug("DEBUG: Closing HTTP connection")
            HTTPRequestHandler.close(self)
        else:
            logger.debug("DEBUG: Closing TLS connection")
            TLSHandshake.close(self)

    def readable(self):
        if self.tlsDone:
            logger.debug("DEBUG: Checking HTTP readable state")
            return HTTPRequestHandler.readable(self)
        logger.debug("DEBUG: Checking TLS readable state")
        return TLSHandshake.readable(self)

    def handle_read(self):
        if self.tlsDone:
            logger.debug("DEBUG: Handling HTTP read")
            HTTPRequestHandler.handle_read(self)
        else:
            logger.debug("DEBUG: Handling TLS read")
            TLSHandshake.handle_read(self)
            if hasattr(self, 'tlsDone') and self.tlsDone:
                logger.debug("DEBUG: TLS handshake completed")

    def writable(self):
        if self.tlsDone:
            logger.debug("DEBUG: Checking HTTP writable state")
            return HTTPRequestHandler.writable(self)
        logger.debug("DEBUG: Checking TLS writable state")
        return TLSHandshake.writable(self)

    def handle_write(self):
        if self.tlsDone:
            logger.debug("DEBUG: Handling HTTP write")
            HTTPRequestHandler.handle_write(self)
        else:
            logger.debug("DEBUG: Handling TLS write")
            TLSHandshake.handle_write(self)


class HTTPServer(asyncore.dispatcher):
    """Handling HTTP Server"""
    port = 12345

    def __init__(self):
        logger.debug("DEBUG: Initializing HTTPServer on port %d", self.port)
        if not hasattr(self, '_map'):
            asyncore.dispatcher.__init__(self)
        
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind(('127.0.0.1', self.port))
        self.connections = 0
        self.listen(5)
        logger.debug("DEBUG: HTTPServer initialized and listening")

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logger.debug("DEBUG: New connection from %s", repr(addr))
            self.connections += 1
            logger.debug("DEBUG: Total connections: %d", self.connections)
            HTTPRequestHandler(sock)
            logger.debug("DEBUG: HTTPRequestHandler created for new connection")


class HTTPSServer(HTTPServer):
    """Handling HTTPS Server"""
    port = 12345

    def __init__(self):
        logger.debug("DEBUG: Initializing HTTPSServer on port %d", self.port)
        if not hasattr(self, '_map'):
            HTTPServer.__init__(self)
        logger.debug("DEBUG: HTTPSServer initialized")

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            logger.debug("DEBUG: New HTTPS connection from %s", repr(addr))
            self.connections += 1
            logger.debug("DEBUG: Total HTTPS connections: %d", self.connections)
            HTTPSRequestHandler(sock)
            logger.debug("DEBUG: HTTPSRequestHandler created for new connection")


if __name__ == "__main__":
    logger.debug("DEBUG: Starting HTTP server in main mode")
    server = HTTPSServer()
    logger.debug("DEBUG: Entering asyncore loop")
    asyncore.loop()
    logger.debug("DEBUG: Asyncore loop exited")
