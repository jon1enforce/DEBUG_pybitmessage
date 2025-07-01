"""
Singleton decorator definition with enhanced debugging
"""

import sys
import logging
from functools import wraps

# Setup debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='DEBUG: %(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

logger.debug("Initializing singleton decorator module")

def Singleton(cls):
    """
    Decorator implementing the singleton pattern with debug logging:
    it restricts the instantiation of a class to one "single" instance.
    """
    logger.debug("Creating Singleton decorator for class: %s", cls.__name__)
    instances = {}
    logger.debug("Initialized instances dictionary for Singleton tracking")

    @wraps(cls)
    def getinstance():
        """Find an instance or save newly created one with debug logging"""
        logger.debug("getinstance() called for class: %s", cls.__name__)
        
        if cls not in instances:
            logger.debug("No existing instance found for %s, creating new one", cls.__name__)
            instances[cls] = cls()
            logger.debug("Created and stored new instance of %s", cls.__name__)
        else:
            logger.debug("Returning existing instance of %s", cls.__name__)
            
        return instances[cls]

    logger.debug("Singleton decorator setup complete for %s", cls.__name__)
    return getinstance

logger.debug("singleton module initialization complete")
