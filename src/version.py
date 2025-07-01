softwareName = 'PyBitmessage'
softwareVersion = '0.6.3.2'
"""
Module defining software version information with enhanced debugging
"""

import sys
import logging
import inspect

# Debug-Setup
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

def _log_version_access():
    """Helper function to log version access details"""
    caller_frame = inspect.currentframe().f_back
    caller_info = inspect.getframeinfo(caller_frame)
    logger.debug(
        f"Version info accessed from {caller_info.filename} line {caller_info.lineno} "
        f"by {caller_frame.f_code.co_name}"
    )

# Version constants with access logging
@property
def softwareName():
    _log_version_access()
    logger.info("Accessing software name")
    return 'PyBitmessage'

@property
def softwareVersion():
    _log_version_access()
    logger.info("Accessing software version")
    return '0.6.3.2'

# Alternative approach for direct variable access
_softwareName = 'PyBitmessage'
_softwareVersion = '0.6.3.2'

def get_software_info():
    """Get version info with proper logging"""
    logger.debug("Retrieving full software info")
    return {
        'name': _softwareName,
        'version': _softwareVersion,
        'type': 'Bitmessage client',
        'debug': True
    }

# Initialization logging
logger.info(f"{_softwareName} version {_softwareVersion} initialized")
logger.debug("Version module fully loaded")

if __name__ == '__main__':
    # Test the logging
    logger.debug("Running version module test")
    print("Software:", softwareName)
    print("Version:", softwareVersion)
    print("Full info:", get_software_info())
