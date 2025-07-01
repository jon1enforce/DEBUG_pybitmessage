import asyncore
import logging
from http import HTTPClient
from tls import TLSHandshake

# Initialize logger
logger = logging.getLogger('default')

"""
self.sslSock = ssl.wrap_socket(
    self.sock,
    keyfile=os.path.join(paths.codePath(), 'sslkeys', 'key.pem'),
    certfile=os.path.join(paths.codePath(), 'sslkeys', 'cert.pem'),
    server_side=not self.initiatedConnection,
    ssl_version=ssl.PROTOCOL_TLSv1,
    do_handshake_on_connect=False,
    ciphers='AECDH-AES256-SHA')
"""


class HTTPSClient(HTTPClient, TLSHandshake):
    def __init__(self, host, path):
        logger.debug("DEBUG: Initializing HTTPSClient for host: %s, path: %s", host, path)
        
        if not hasattr(self, '_map'):
            logger.debug("DEBUG: Creating asyncore.dispatcher instance")
            asyncore.dispatcher.__init__(self)
            
        self.tlsDone = False
        logger.debug("DEBUG: TLS handshake not yet completed")
        
        """
        TLSHandshake.__init__(
            self,
            address=(host, 443),
            certfile='/home/shurdeek/src/PyBitmessage/sslsrc/keys/cert.pem',
            keyfile='/home/shurdeek/src/PyBitmessage/src/sslkeys/key.pem',
            server_side=False,
            ciphers='AECDH-AES256-SHA')
        """
        logger.debug("DEBUG: Initializing HTTPClient")
        HTTPClient.__init__(self, host, path, connect=False)
        
        logger.debug("DEBUG: Initializing TLSHandshake")
        TLSHandshake.__init__(self, address=(host, 443), server_side=False)
        
        logger.debug("DEBUG: HTTPSClient initialization complete")

    def handle_connect(self):
        logger.debug("DEBUG: Handling connect event")
        TLSHandshake.handle_connect(self)
        logger.debug("DEBUG: TLSHandshake.handle_connect completed")

    def handle_close(self):
        logger.debug("DEBUG: Handling close event")
        if self.tlsDone:
            logger.debug("DEBUG: Closing HTTPClient connection")
            HTTPClient.close(self)
        else:
            logger.debug("DEBUG: Closing TLSHandshake connection")
            TLSHandshake.close(self)
        logger.debug("DEBUG: Connection closed")

    def readable(self):
        if self.tlsDone:
            logger.debug("DEBUG: Checking HTTPClient readable state")
            return HTTPClient.readable(self)
        else:
            logger.debug("DEBUG: Checking TLSHandshake readable state")
            return TLSHandshake.readable(self)

    def handle_read(self):
        if self.tlsDone:
            logger.debug("DEBUG: Handling HTTP data read")
            HTTPClient.handle_read(self)
        else:
            logger.debug("DEBUG: Handling TLS handshake read")
            TLSHandshake.handle_read(self)
            if hasattr(self, 'tlsDone') and self.tlsDone:
                logger.debug("DEBUG: TLS handshake completed successfully")

    def writable(self):
        if self.tlsDone:
            logger.debug("DEBUG: Checking HTTPClient writable state")
            return HTTPClient.writable(self)
        else:
            logger.debug("DEBUG: Checking TLSHandshake writable state")
            return TLSHandshake.writable(self)

    def handle_write(self):
        if self.tlsDone:
            logger.debug("DEBUG: Handling HTTP data write")
            HTTPClient.handle_write(self)
        else:
            logger.debug("DEBUG: Handling TLS handshake write")
            TLSHandshake.handle_write(self)
            if hasattr(self, 'tlsDone') and self.tlsDone:
                logger.debug("DEBUG: TLS handshake write completed, connection secured")


if __name__ == "__main__":
    logger.debug("DEBUG: Starting HTTPSClient in main mode")
    client = HTTPSClient('anarchy.economicsofbitcoin.com', '/')
    logger.debug("DEBUG: Entering asyncore loop")
    asyncore.loop()
    logger.debug("DEBUG: Asyncore loop exited")
