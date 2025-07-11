"""
Global runtime variables.
"""

import sys
import logging

# Setup debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='DEBUG: %(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

logger.debug("Initializing state module - setting up global runtime variables")

neededPubkeys = {}
logger.debug("Initialized neededPubkeys dictionary")

extPort = None
logger.debug("Initialized extPort (for UPnP) as None")

socksIP = None
logger.debug("Initialized socksIP (for Tor hidden service) as None")

appdata = ""
logger.debug("Initialized appdata (application data storage directory) as empty string")

shutdown = 0
logger.debug("Initialized shutdown flag to 0 (1 = shutdown requested)")

# Component control flags
logger.debug("Initializing component control flags:")
enableNetwork = True
logger.debug("  enableNetwork = True (enable network threads)")
enableObjProc = True
logger.debug("  enableObjProc = True (enable object processing thread)")
enableAPI = True
logger.debug("  enableAPI = True (enable API if configured)")
enableGUI = True
logger.debug("  enableGUI = True (enable GUI)")
enableSTDIO = False
logger.debug("  enableSTDIO = False (disable STDIO threads)")
enableKivy = False
logger.debug("  enableKivy = False (disable kivy app)")
curses = False
logger.debug("  curses = False (disable ncurses mode)")

maximumNumberOfHalfOpenConnections = 0
logger.debug("Initialized maximumNumberOfHalfOpenConnections to 0")

maximumLengthOfTimeToBotherResendingMessages = 0
logger.debug("Initialized maximumLengthOfTimeToBotherResendingMessages to 0")

ownAddresses = {}
logger.debug("Initialized ownAddresses dictionary")

discoveredPeers = {}
logger.debug("Initialized discoveredPeers dictionary")

kivy = False
logger.debug("Initialized kivy flag to False")

kivyapp = None
logger.debug("Initialized kivyapp to None")

testmode = False
logger.debug("Initialized testmode to False")

clientHasReceivedIncomingConnections = False
logger.debug("Initialized clientHasReceivedIncomingConnections to False (used by API command clientStatus)")

numberOfMessagesProcessed = 0
logger.debug("Initialized numberOfMessagesProcessed to 0")

numberOfBroadcastsProcessed = 0
logger.debug("Initialized numberOfBroadcastsProcessed to 0")

numberOfPubkeysProcessed = 0
logger.debug("Initialized numberOfPubkeysProcessed to 0")

statusIconColor = "red"
logger.debug("Initialized statusIconColor to 'red' (GUI status icon color)")

ackdataForWhichImWatching = {}
logger.debug("Initialized ackdataForWhichImWatching dictionary")

thisapp = None
logger.debug("Initialized thisapp (singleton instance) to None")

backend_py3_compatible = False
logger.debug("Initialized backend_py3_compatible to False")


class Placeholder(object):  # pylint:disable=too-few-public-methods
    """Placeholder class with debug logging"""
    
    def __init__(self, className):
        logger.debug("Creating Placeholder instance for class: %s", className)
        self.className = className

    def __getattr__(self, name):
        logger.error("Attempted to access undefined attribute '%s' on Placeholder for %s", name, self.className)
        self._raise()

    def __setitem__(self, key, value):
        logger.error("Attempted to set item '%s' on Placeholder for %s", key, self.className)
        self._raise()

    def __getitem__(self, key):
        logger.error("Attempted to get item '%s' from Placeholder for %s", key, self.className)
        self._raise()

    def _raise(self):
        error_msg = "Probably you forgot to initialize state variable for {}".format(self.className)
        logger.error(error_msg)
        raise NotImplementedError(error_msg)


logger.debug("Creating Inventory placeholder")
Inventory = Placeholder("Inventory")
logger.debug("state module initialization complete")
