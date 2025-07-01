# pylint: disable=unused-import, wrong-import-position, ungrouped-imports
# flake8: noqa:E401, E402

"""Mock kivy app with mock threads."""

import os
import logging
from kivy.config import Config
from mockbm import multiqueue
import state

from mockbm.class_addressGenerator import FakeAddressGenerator  # noqa:E402
from bitmessagekivy.mpybit import NavigateApp  # noqa:E402
from mockbm import network  # noqa:E402

# Initialize logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('default')

stats = network.stats
objectracker = network.objectracker
logger.debug("DEBUG: Initialized network stats and objectracker")


def main():
    """main method for starting threads"""
    logger.debug("DEBUG: main() function started")
    
    # Initialize environment variable for tests
    if 'INSTALL_TESTS' not in os.environ:
        os.environ['INSTALL_TESTS'] = "True"
        logger.debug("DEBUG: Set INSTALL_TESTS environment variable")
    
    # Start address generator thread
    logger.debug("DEBUG: Creating FakeAddressGenerator thread")
    addressGeneratorThread = FakeAddressGenerator()
    addressGeneratorThread.daemon = True
    logger.debug("DEBUG: Starting FakeAddressGenerator thread")
    addressGeneratorThread.start()
    
    # Initialize and run Kivy application
    logger.debug("DEBUG: Initializing NavigateApp")
    state.kivyapp = NavigateApp()
    
    try:
        logger.debug("DEBUG: Starting Kivy application run loop")
        state.kivyapp.run()
        logger.debug("DEBUG: Kivy application run loop exited")
    except Exception as e:
        logger.error("DEBUG: Error in Kivy application: %s", str(e))
        raise
    finally:
        # Clean up threads
        logger.debug("DEBUG: Stopping FakeAddressGenerator thread")
        addressGeneratorThread.stopThread()
        logger.debug("DEBUG: FakeAddressGenerator thread stopped")

    logger.debug("DEBUG: main() function completed")


if __name__ == "__main__":
    logger.debug("DEBUG: Script started as __main__")
    
    # Ensure test environment is set
    if 'INSTALL_TESTS' not in os.environ:
        os.environ['INSTALL_TESTS'] = "True"
        logger.debug("DEBUG: Set INSTALL_TESTS environment variable in __main__")
    
    try:
        logger.debug("DEBUG: Calling main() function")
        main()
        logger.debug("DEBUG: main() function completed successfully")
    except Exception as e:
        logger.error("DEBUG: Fatal error in main execution: %s", str(e))
        raise
    
    logger.debug("DEBUG: Script execution completed")
