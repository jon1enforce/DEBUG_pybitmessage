# pylint: disable=no-else-return, too-many-return-statements

"""To check the platform"""

import logging
from sys import platform as _sys_platform
from os import environ

logger = logging.getLogger('default')

def _get_platform():
    """Determine the current platform with detailed debugging"""
    logger.debug("DEBUG: Starting platform detection")
    
    # Check for KIVY_BUILD environment variable first
    kivy_build = environ.get("KIVY_BUILD", "")
    logger.debug("DEBUG: KIVY_BUILD value: %s", kivy_build)
    
    if kivy_build in {"android", "ios"}:
        logger.debug("DEBUG: Detected platform via KIVY_BUILD: %s", kivy_build)
        return kivy_build
    
    # Check for Android-specific environment variables
    if "P4A_BOOTSTRAP" in environ:
        logger.debug("DEBUG: Detected Android via P4A_BOOTSTRAP")
        return "android"
    
    if "ANDROID_ARGUMENT" in environ:
        logger.debug("DEBUG: Detected Android via ANDROID_ARGUMENT")
        return "android"
    
    # Check system platform strings
    logger.debug("DEBUG: System platform string: %s", _sys_platform)
    
    if _sys_platform in ("win32", "cygwin"):
        logger.debug("DEBUG: Detected Windows platform")
        return "win"
    
    if _sys_platform == "darwin":
        logger.debug("DEBUG: Detected macOS platform")
        return "macosx"
    
    if _sys_platform.startswith("linux"):
        logger.debug("DEBUG: Detected Linux platform")
        return "linux"
    
    if _sys_platform.startswith("freebsd"):
        logger.debug("DEBUG: Detected FreeBSD platform (mapped to linux)")
        return "linux"
    
    if _sys_platform.startswith("openbsd"):
        logger.debug("DEBUG: Detected OpenBSD platform (mapped to linux)")
        return "linux"
    
    logger.warning("DEBUG: Unknown platform detected: %s", _sys_platform)
    return "unknown"

def platform():
    """Public interface for platform detection with debug logging"""
    detected_platform = _get_platform()
    logger.debug("DEBUG: Final platform detection result: %s", detected_platform)
    return detected_platform
