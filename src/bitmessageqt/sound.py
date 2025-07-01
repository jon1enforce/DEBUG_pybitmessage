# -*- coding: utf-8 -*-
"""Sound Module - Handles sound related functionality and constants"""

import logging

# Debugging setup
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Sound type constants
SOUND_NONE = 0
SOUND_KNOWN = 1
SOUND_UNKNOWN = 2
SOUND_CONNECTED = 3
SOUND_DISCONNECTED = 4
SOUND_CONNECTION_GREEN = 5

logger.debug("DEBUG: Sound constants initialized: "
             "SOUND_NONE=%d, SOUND_KNOWN=%d, SOUND_UNKNOWN=%d, "
             "SOUND_CONNECTED=%d, SOUND_DISCONNECTED=%d, "
             "SOUND_CONNECTION_GREEN=%d",
             SOUND_NONE, SOUND_KNOWN, SOUND_UNKNOWN,
             SOUND_CONNECTED, SOUND_DISCONNECTED, SOUND_CONNECTION_GREEN)

def is_connection_sound(category):
    """
    Check if sound type is related to connectivity rather than message reception.
    
    Args:
        category (int): Sound category constant to check
        
    Returns:
        bool: True if the sound is connection-related, False otherwise
    """
    logger.debug("DEBUG: is_connection_sound() called with category=%d", category)
    
    result = category in (
        SOUND_CONNECTED,
        SOUND_DISCONNECTED,
        SOUND_CONNECTION_GREEN
    )
    
    logger.debug("DEBUG: is_connection_sound() returning %s for category %d", 
                result, category)
    return result

# Supported audio file extensions
extensions = ('wav', 'mp3', 'oga')
logger.debug("DEBUG: Supported sound extensions initialized: %s", extensions)
