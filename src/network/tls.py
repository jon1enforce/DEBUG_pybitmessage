"""
SSL/TLS negotiation.
"""
import logging
import os
import socket
import ssl
import sys
import six

import network.asyncore_pollchoose as asyncore
import paths
from network.advanceddispatcher import AdvancedDispatcher
from network import receiveDataQueue

logger = logging.getLogger('default')

_DISCONNECTED_SSL = frozenset((ssl.SSL_ERROR_EOF,))

if sys.version_info >= (2, 7, 13):
    # this means TLSv1 or higher
    # in the future change to
    # ssl.PROTOCOL_TLS1.2
    sslProtocolVersion = ssl.PROTOCOL_TLS  # pylint: disable=no-member
    logger.debug("DEBUG: Using PROTOCOL_TLS for Python >= 2.7.13")
elif sys.version_info >= (2, 7, 9):
    # this means any SSL/TLS.
    # SSLv2 and 3 are excluded with an option after context is created
    sslProtocolVersion = ssl.PROTOCOL_SSLv23
    logger.debug("DEBUG: Using PROTOCOL_SSLv23 for Python >= 2.7.9")
else:
    # this means TLSv1, there is no way to set "TLSv1 or higher"
    # or "TLSv1.2" in < 2.7.9
    sslProtocolVersion = ssl.PROTOCOL_TLSv1
    logger.debug("DEBUG: Using PROTOCOL_TLSv1 for Python < 2.7.9")


# ciphers
if (
    ssl.OPENSSL_VERSION_NUMBER >= 0x10100000
    and not ssl.OPENSSL_VERSION.startswith("LibreSSL")
):
    sslProtocolCiphers = "AECDH-AES256-SHA@SECLEVEL=0"
    logger.debug("DEBUG: Using modern cipher with security level 0")
else:
    sslProtocolCiphers = "AECDH-AES256-SHA"
    logger.debug("DEBUG: Using legacy cipher suite")


class TLSDispatcher(AdvancedDispatcher):
    """TLS functionality for classes derived from AdvancedDispatcher"""
    # pylint: disable=too-many-instance-attributes, too-many-arguments
    # pylint: disable=super-init-not-called
    def __init__(self, _=None, sock=None, certfile=None, keyfile=None,
                 server_side=False, ciphers=sslProtocolCiphers):
        logger.debug("DEBUG: Initializing TLSDispatcher")
        self.want_read = self.want_write = True
        self.certfile = certfile or os.path.join(
            paths.codePath(), 'sslkeys', 'cert.pem')
        self.keyfile = keyfile or os.path.join(
            paths.codePath(), 'sslkeys', 'key.pem')
        logger.debug(f"DEBUG: Using certfile: {self.certfile}, keyfile: {self.keyfile}")
        
        self.server_side = server_side
        self.ciphers = ciphers
        self.tlsStarted = False
        self.tlsDone = False
        self.tlsVersion = "N/A"
        self.isSSL = False
        if six.PY3 or ssl.OPENSSL_VERSION_NUMBER >= 0x30000000:
            logger.debug("DEBUG: Enabling TLS preparation for OpenSSL >= 3.0 or Python 3")
            self.tlsPrepared = False

    def state_tls_init(self):
        """Prepare sockets for TLS handshake"""
        logger.debug("DEBUG: Starting TLS initialization")
        self.isSSL = True
        self.tlsStarted = True

        if six.PY3 or ssl.OPENSSL_VERSION_NUMBER >= 0x30000000:
            logger.debug("DEBUG: Preparing for async TLS handshake (Python 3/OpenSSL 3)")
            self.want_read = self.want_write = True
            self.set_state("tls_handshake")
            return False

        logger.debug("DEBUG: Performing immediate TLS initialization")
        return self.do_tls_init()

    def do_tls_init(self):
        logger.debug("DEBUG: Performing TLS socket initialization")
        # Once the connection has been established,
        # it's safe to wrap the socket.
        if sys.version_info >= (2, 7, 9):
            logger.debug("DEBUG: Using modern SSL context creation")
            if ssl.OPENSSL_VERSION_NUMBER >= 0x30000000:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER
                    if self.server_side else ssl.PROTOCOL_TLS_CLIENT)
                logger.debug("DEBUG: Created TLS context for OpenSSL 3.0+")
            else:
                context = ssl.create_default_context(
                    purpose=ssl.Purpose.SERVER_AUTH
                    if self.server_side else ssl.Purpose.CLIENT_AUTH)
                logger.debug("DEBUG: Created default SSL context")
            
            logger.debug(f"DEBUG: Setting ciphers: {self.ciphers}")
            context.set_ciphers(self.ciphers)
            context.set_ecdh_curve("secp256k1")
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            if ssl.OPENSSL_VERSION_NUMBER >= 0x30000000:
                context.options = ssl.OP_ALL | ssl.OP_NO_SSLv2 |\
                    ssl.OP_NO_SSLv3 | ssl.OP_SINGLE_ECDH_USE |\
                    ssl.OP_CIPHER_SERVER_PREFERENCE | ssl.OP_NO_TLSv1_3
                logger.debug("DEBUG: Set OpenSSL 3.0+ options")
            else:
                context.options = ssl.OP_ALL | ssl.OP_NO_SSLv2 |\
                    ssl.OP_NO_SSLv3 | ssl.OP_SINGLE_ECDH_USE |\
                    ssl.OP_CIPHER_SERVER_PREFERENCE
                logger.debug("DEBUG: Set legacy OpenSSL options")
            
            self.sslSocket = context.wrap_socket(
                self.socket, server_side=self.server_side,
                do_handshake_on_connect=False)
            logger.debug("DEBUG: Wrapped socket with SSL context")
        else:
            logger.debug("DEBUG: Using legacy SSL wrapping")
            self.sslSocket = ssl.wrap_socket(
                self.socket, server_side=self.server_side,
                ssl_version=sslProtocolVersion,
                certfile=self.certfile, keyfile=self.keyfile,
                ciphers=self.ciphers, do_handshake_on_connect=False)
            logger.debug("DEBUG: Wrapped socket with legacy SSL")
        
        self.sslSocket.setblocking(0)
        self.want_read = self.want_write = True
        
        if six.PY3 or ssl.OPENSSL_VERSION_NUMBER >= 0x30000000:
            self.tlsPrepared = True
            logger.debug("DEBUG: Marked TLS as prepared")
        else:
            self.set_state("tls_handshake")
            logger.debug("DEBUG: Set state to tls_handshake")
        return False

    @staticmethod
    def state_tls_handshake():
        """
        Do nothing while TLS handshake is pending, as during this phase
        we need to react to callbacks instead
        """
        logger.debug("DEBUG: TLS handshake pending, waiting for callbacks")
        return False

    def writable(self):
        """Handle writable checks for TLS-enabled sockets"""
        try:
            if self.tlsStarted and not self.tlsDone and not self.write_buf:
                logger.debug(f"DEBUG: writable check during TLS - want_write: {self.want_write}")
                return self.want_write
        except AttributeError:
            pass
        result = AdvancedDispatcher.writable(self)
        logger.debug(f"DEBUG: writable check result: {result}")
        return result

    def readable(self):
        """Handle readable check for TLS-enabled sockets"""
        try:
            # during TLS handshake, and after flushing write buffer,
            # return status of last handshake attempt
            if self.tlsStarted and not self.tlsDone and not self.write_buf:
                if ssl.OPENSSL_VERSION_NUMBER < 0x30000000:
                    logger.debug('DEBUG: TLS readable check - want_read: %r', self.want_read)
                return self.want_read
            # prior to TLS handshake,
            # receiveDataThread should emulate synchronous behaviour
            if not self.fullyEstablished and (
                    self.expectBytes == 0 or not self.write_buf_empty()):
                logger.debug("DEBUG: Not fully established, not readable")
                return False
        except AttributeError:
            pass
        result = AdvancedDispatcher.readable(self)
        logger.debug(f"DEBUG: readable check result: {result}")
        return result

    def handle_read(self):
        """
        Handle reads for sockets during TLS handshake. Requires special
        treatment as during the handshake, buffers must remain empty
        and normal reads must be ignored.
        """
        logger.debug("DEBUG: handle_read called")
        try:
            # wait for write buffer flush
            if self.tlsStarted and not self.tlsDone and not self.write_buf:
                logger.debug("DEBUG: In TLS handshake phase")
                if six.PY3 or ssl.OPENSSL_VERSION_NUMBER >= 0x30000000:
                    if not self.tlsPrepared:
                        logger.debug("DEBUG: TLS not prepared, initializing")
                        self.do_tls_init()
                        return
                self.tls_handshake()
            else:
                logger.debug("DEBUG: Normal read handling")
                AdvancedDispatcher.handle_read(self)
        except AttributeError:
            logger.debug("DEBUG: AttributeError in handle_read, falling back")
            AdvancedDispatcher.handle_read(self)
        except ssl.SSLError as err:
            if err.errno == ssl.SSL_ERROR_WANT_READ:
                logger.debug("DEBUG: SSL wants read, waiting")
                return
            if err.errno not in _DISCONNECTED_SSL:
                logger.info("SSL Error: %s", err)
                logger.debug("DEBUG: SSL Error in handle_read: %s", str(err))
            self.close_reason = "SSL Error in handle_read"
            logger.debug("DEBUG: Closing due to SSL error in handle_read")
            self.handle_close()

    def handle_write(self):
        """
        Handle writes for sockets during TLS handshake. Requires special
        treatment as during the handshake, buffers must remain empty
        and normal writes must be ignored.
        """
        logger.debug("DEBUG: handle_write called")
        try:
            # wait for write buffer flush
            if self.tlsStarted and not self.tlsDone and not self.write_buf:
                logger.debug("DEBUG: In TLS handshake phase")
                if six.PY3 or ssl.OPENSSL_VERSION_NUMBER >= 0x30000000:
                    if not self.tlsPrepared:
                        logger.debug("DEBUG: TLS not prepared, initializing")
                        self.do_tls_init()
                        return
                self.tls_handshake()
            else:
                logger.debug("DEBUG: Normal write handling")
                AdvancedDispatcher.handle_write(self)
        except AttributeError:
            logger.debug("DEBUG: AttributeError in handle_write, falling back")
            AdvancedDispatcher.handle_write(self)
        except ssl.SSLError as err:
            if err.errno == ssl.SSL_ERROR_WANT_WRITE:
                logger.debug("DEBUG: SSL wants write, waiting")
                return
            if err.errno not in _DISCONNECTED_SSL:
                logger.info("SSL Error: %s", err)
                logger.debug("DEBUG: SSL Error in handle_write: %s", str(err))
            self.close_reason = "SSL Error in handle_write"
            logger.debug("DEBUG: Closing due to SSL error in handle_write")
            self.handle_close()

    def tls_handshake(self):
        """Perform TLS handshake and handle its stages"""
        logger.debug("DEBUG: tls_handshake called")
        # wait for flush
        if self.write_buf:
            logger.debug("DEBUG: Write buffer not empty, waiting for flush")
            return False
        
        # Perform the handshake.
        try:
            logger.debug("DEBUG: Attempting SSL handshake")
            self.sslSocket.do_handshake()
        except ssl.SSLError as err:
            self.close_reason = "SSL Error in tls_handshake"
            logger.info("%s:%i: handshake fail", *self.destination)
            logger.debug("DEBUG: SSL handshake failed: %s", str(err))
            
            self.want_read = self.want_write = False
            if err.args[0] == ssl.SSL_ERROR_WANT_READ:
                logger.debug("DEBUG: SSL wants read")
                self.want_read = True
            if err.args[0] == ssl.SSL_ERROR_WANT_WRITE:
                logger.debug("DEBUG: SSL wants write")
                self.want_write = True
            if not (self.want_write or self.want_read):
                logger.debug("DEBUG: Fatal SSL error, raising exception")
                raise
        except socket.error as err:
            # pylint: disable=protected-access
            if err.errno in asyncore._DISCONNECTED:
                self.close_reason = "socket.error in tls_handshake"
                logger.debug("DEBUG: Socket error in handshake: %s", str(err))
                self.handle_close()
            else:
                logger.debug("DEBUG: Unexpected socket error, raising")
                raise
        else:
            if sys.version_info >= (2, 7, 9):
                self.tlsVersion = self.sslSocket.version()
                logger.debug(
                    'DEBUG: %s:%i: TLS handshake success, TLS protocol version: %s',
                    self.destination.host, self.destination.port,
                    self.tlsVersion)
            else:
                self.tlsVersion = "TLSv1"
                logger.debug(
                    'DEBUG: %s:%i: TLS handshake success',
                    self.destination.host, self.destination.port)
            
            # The handshake has completed, so remove this channel and...
            self.del_channel()
            self.set_socket(self.sslSocket)
            self.tlsDone = True
            logger.debug("DEBUG: TLS handshake completed successfully")

            self.bm_proto_reset()
            self.set_state("connection_fully_established")
            receiveDataQueue.put(self.destination)
            logger.debug("DEBUG: Connection fully established and queued")
        return False
