"""
Set proxy if available otherwise exception
"""
# pylint: disable=protected-access
import logging
import socket
import time

from network import asyncore_pollchoose as asyncore
from .advanceddispatcher import AdvancedDispatcher
from bmconfigparser import config
from .node import Peer

logger = logging.getLogger('default')


def _ends_with(s, tail):
    try:
        result = s.endswith(tail)
    except AttributeError:
        result = s.decode("utf-8", "replace").endswith(tail)
    logger.debug("DEBUG: _ends_with check - string: %s, tail: %s, result: %s", 
                s, tail, result)
    return result


class ProxyError(Exception):
    """Base proxy exception class"""
    errorCodes = ("Unknown error",)

    def __init__(self, code=-1):
        self.code = code
        try:
            self.message = self.errorCodes[code]
        except IndexError:
            self.message = self.errorCodes[-1]
        logger.debug("DEBUG: ProxyError created - code: %d, message: %s", 
                    code, self.message)
        super(ProxyError, self).__init__(self.message)


class GeneralProxyError(ProxyError):
    """General proxy error class (not specific to an implementation)"""
    errorCodes = (
        "Success",
        "Invalid data",
        "Not connected",
        "Not available",
        "Bad proxy type",
        "Bad input",
        "Timed out",
        "Network unreachable",
        "Connection refused",
        "Host unreachable"
    )

    def __init__(self, code=-1):
        super(GeneralProxyError, self).__init__(code)
        logger.debug("DEBUG: GeneralProxyError created - code: %d", code)


class Proxy(AdvancedDispatcher):
    """Base proxy class"""
    # these are global, and if you change config during runtime,
    # all active/new instances should change too
    _proxy = ("127.0.0.1", 9050)
    _auth = None
    _onion_proxy = None
    _onion_auth = None
    _remote_dns = True

    @property
    def proxy(self):
        """Return proxy IP and port"""
        logger.debug("DEBUG: Getting proxy: %s:%d", self.__class__._proxy[0], self.__class__._proxy[1])
        return self.__class__._proxy

    @proxy.setter
    def proxy(self, address):
        """Set proxy IP and port"""
        logger.debug("DEBUG: Attempting to set proxy to: %s", address)
        if (not isinstance(address, tuple) or len(address) < 2
                or not isinstance(address[0], str)
                or not isinstance(address[1], int)):
            logger.error("DEBUG: Invalid proxy address format")
            raise ValueError
        self.__class__._proxy = address
        logger.debug("DEBUG: Proxy set to: %s:%d", address[0], address[1])

    @property
    def auth(self):
        """Return proxy authentication settings"""
        logger.debug("DEBUG: Getting auth settings: %s", self.__class__._auth)
        return self.__class__._auth

    @auth.setter
    def auth(self, authTuple):
        """Set proxy authentication (username and password)"""
        logger.debug("DEBUG: Setting auth settings")
        self.__class__._auth = authTuple

    @property
    def onion_proxy(self):
        """Return separate proxy for onion addresses"""
        logger.debug("DEBUG: Getting onion proxy: %s", self.__class__._onion_proxy)
        return self.__class__._onion_proxy

    @onion_proxy.setter
    def onion_proxy(self, address):
        """Set onion proxy address"""
        logger.debug("DEBUG: Setting onion proxy to: %s", address)
        if address is not None and (
            not isinstance(address, tuple) or len(address) < 2
            or not isinstance(address[0], str)
            or not isinstance(address[1], int)
        ):
            logger.error("DEBUG: Invalid onion proxy address format")
            raise ValueError
        self.__class__._onion_proxy = address
        logger.debug("DEBUG: Onion proxy set to: %s", address)

    @property
    def onion_auth(self):
        """Return proxy auth for onion hosts"""
        logger.debug("DEBUG: Getting onion auth: %s", self.__class__._onion_auth)
        return self.__class__._onion_auth

    @onion_auth.setter
    def onion_auth(self, authTuple):
        """Set proxy authentication for onion hosts"""
        logger.debug("DEBUG: Setting onion auth")
        self.__class__._onion_auth = authTuple

    def __init__(self, address):
        logger.debug("DEBUG: Initializing Proxy with address: %s", address)
        if not isinstance(address, Peer):
            logger.error("DEBUG: Invalid address type - expected Peer")
            raise ValueError
            
        AdvancedDispatcher.__init__(self)
        self.destination = address
        self.isOutbound = True
        self.fullyEstablished = False
        
        logger.debug("DEBUG: Creating socket for proxy connection")
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        
        if config.safeGetBoolean("bitmessagesettings", "socksauthentication"):
            logger.debug("DEBUG: Configuring proxy authentication")
            self.auth = (
                config.safeGet("bitmessagesettings", "socksusername"),
                config.safeGet("bitmessagesettings", "sockspassword"))
        else:
            logger.debug("DEBUG: No proxy authentication configured")
            self.auth = None
            
        proxy_target = self.onion_proxy if _ends_with(address.host, ".onion") and self.onion_proxy else self.proxy
        logger.debug("DEBUG: Connecting to proxy: %s:%d", proxy_target[0], proxy_target[1])
        self.connect(proxy_target)

    def handle_connect(self):
        """Handle connection event (to the proxy)"""
        logger.debug("DEBUG: Proxy connection established to %s:%d", 
                    self.destination.host, self.destination.port)
        self.set_state("init")
        try:
            AdvancedDispatcher.handle_connect(self)
        except socket.error as e:
            if e.errno in asyncore._DISCONNECTED:
                logger.debug("DEBUG: Connection failed to %s:%d: %s",
                            self.destination.host, self.destination.port, e)
                return
        logger.debug("DEBUG: Initializing proxy state")
        self.state_init()

    def state_proxy_handshake_done(self):
        """Handshake is complete at this point"""
        self.connectedAt = time.time()
        logger.debug("DEBUG: Proxy handshake completed at %f", self.connectedAt)
        return False
