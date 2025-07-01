import os
import sys
import logging

logger = logging.getLogger('default')

def setup():
    """Add path to this file to sys.path"""
    logger.debug("DEBUG: setup() called")
    
    # Get absolute path of current directory
    app_dir = os.path.dirname(os.path.abspath(__file__))
    logger.debug("DEBUG: Current directory path: %s", app_dir)
    
    # Change working directory
    try:
        os.chdir(app_dir)
        logger.debug("DEBUG: Changed working directory to: %s", app_dir)
    except Exception as e:
        logger.error("DEBUG: Failed to change directory: %s", str(e))
        raise
    
    # Add to Python path
    if app_dir not in sys.path:
        sys.path.insert(0, app_dir)
        logger.debug("DEBUG: Added to sys.path: %s", app_dir)
    else:
        logger.debug("DEBUG: Path already exists in sys.path: %s", app_dir)
    
    logger.debug("DEBUG: setup() returning: %s", app_dir)
    return app_dir
