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
def softwareName_property():
    _log_version_access()
    logger.info("Accessing software name via property")
    return 'PyBitmessage'

@property
def softwareVersion_property():
    _log_version_access()
    logger.info("Accessing software version via property")
    return '0.6.3.2'

# Keep direct variable access for compatibility
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

# Compatibility exports - this is what setup.py needs
# Export both the string version and property version
softwareName = _softwareName  # Simple string export
softwareVersion = _softwareVersion  # Simple string export
softwareName_prop = softwareName_property  # Property version
softwareVersion_prop = softwareVersion_property  # Property version

if __name__ == '__main__':
    # Test the logging
    logger.debug("Running version module test")
    print("Software (direct):", softwareName)
    print("Version (direct):", softwareVersion)
    print("Software (property):", softwareName_prop)
    print("Version (property):", softwareVersion_prop)
    print("Full info:", get_software_info())
