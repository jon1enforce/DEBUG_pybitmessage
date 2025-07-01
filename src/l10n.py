"""Localization helpers"""

import logging
import os
import re
import time
import six

from six.moves import range

from bmconfigparser import config

logger = logging.getLogger('default')

DEFAULT_ENCODING = 'ISO8859-1'
DEFAULT_LANGUAGE = 'en_US'
DEFAULT_TIME_FORMAT = '%Y-%m-%d %H:%M:%S'

logger.debug("DEBUG: Initializing localization with defaults - encoding: %s, language: %s, time_format: %s", 
             DEFAULT_ENCODING, DEFAULT_LANGUAGE, DEFAULT_TIME_FORMAT)

try:
    import locale
    encoding = locale.getpreferredencoding(True) or DEFAULT_ENCODING
    language = (
        locale.getlocale()[0] or locale.getdefaultlocale()[0]
        or DEFAULT_LANGUAGE)
    logger.debug("DEBUG: Detected system locale - encoding: %s, language: %s", encoding, language)
except (ImportError, AttributeError):
    logger.exception('DEBUG: Could not determine language or encoding, using defaults')
    locale = None
    encoding = DEFAULT_ENCODING
    language = DEFAULT_LANGUAGE
    logger.debug("DEBUG: Fallback to defaults - encoding: %s, language: %s", encoding, language)


windowsLanguageMap = {
    "ar": "arabic",
    "cs": "czech",
    "da": "danish",
    "de": "german",
    "en": "english",
    "eo": "esperanto",
    "fr": "french",
    "it": "italian",
    "ja": "japanese",
    "nl": "dutch",
    "no": "norwegian",
    "pl": "polish",
    "pt": "portuguese",
    "ru": "russian",
    "sk": "slovak",
    "zh": "chinese",
    "zh_CN": "chinese-simplified",
    "zh_HK": "chinese-traditional",
    "zh_SG": "chinese-simplified",
    "zh_TW": "chinese-traditional"
}
logger.debug("DEBUG: Windows language map initialized with %d entries", len(windowsLanguageMap))


time_format = config.safeGet(
    'bitmessagesettings', 'timeformat', DEFAULT_TIME_FORMAT)
logger.debug("DEBUG: Retrieved time_format from config: %s", time_format)

if not re.search(r'\d', time.strftime(time_format)):
    time_format = DEFAULT_TIME_FORMAT
    logger.debug("DEBUG: Invalid time_format, falling back to default: %s", time_format)

# It seems some systems lie about the encoding they use
# so we perform comprehensive decoding tests
elif six.PY2:
    logger.debug("DEBUG: Performing encoding validation tests for Python 2")
    try:
        # Check day names
        for i in range(7):
            test_str = time.strftime(time_format, (0, 0, 0, 0, 0, 0, i, 0, 0))
            test_str.decode(encoding)
            logger.debug("DEBUG: Day %d encoding test passed", i)
        # Check month names
        for i in range(1, 13):
            test_str = time.strftime(time_format, (0, i, 0, 0, 0, 0, 0, 0, 0))
            test_str.decode(encoding)
            logger.debug("DEBUG: Month %d encoding test passed", i)
        # Check AM/PM
        time.strftime(time_format, (0, 0, 0, 11, 0, 0, 0, 0, 0)).decode(encoding)
        time.strftime(time_format, (0, 0, 0, 13, 0, 0, 0, 0, 0)).decode(encoding)
        logger.debug("DEBUG: AM/PM encoding tests passed")
        # Check DST
        time.strftime(time_format, (0, 0, 0, 0, 0, 0, 0, 0, 1)).decode(encoding)
        logger.debug("DEBUG: DST encoding test passed")
    except Exception as e:
        logger.exception('DEBUG: Could not decode locale formatted timestamp: %s', str(e))
        encoding = DEFAULT_ENCODING
        logger.debug("DEBUG: Fallback to default encoding: %s", encoding)


def setlocale(newlocale):
    """Set the locale"""
    logger.debug("DEBUG: setlocale called with: %s", newlocale)
    try:
        locale.setlocale(locale.LC_ALL, newlocale)
        logger.debug("DEBUG: Successfully set locale to: %s", newlocale)
    except AttributeError:  # locale is None
        logger.debug("DEBUG: locale module not available, skipping setlocale")
        pass
    except Exception as e:
        logger.debug("DEBUG: Error setting locale: %s", str(e))
    
    # Set environment variable as fallback
    os.environ["LC_ALL"] = newlocale
    logger.debug("DEBUG: Set LC_ALL environment variable to: %s", newlocale)


def formatTimestamp(timestamp=None):
    """Return a formatted timestamp"""
    logger.debug("DEBUG: formatTimestamp called with timestamp: %s", timestamp)
    
    # For some reason some timestamps are strings so we need to sanitize.
    if timestamp is not None and not isinstance(timestamp, int):
        logger.debug("DEBUG: Converting non-integer timestamp")
        try:
            timestamp = int(timestamp)
            logger.debug("DEBUG: Converted timestamp to: %d", timestamp)
        except (ValueError, TypeError) as e:
            logger.debug("DEBUG: Timestamp conversion failed: %s", str(e))
            timestamp = None

    # timestamp can't be less than 0.
    if timestamp is not None and timestamp < 0:
        logger.debug("DEBUG: Negative timestamp, setting to None")
        timestamp = None

    if timestamp is None:
        logger.debug("DEBUG: Using current time for timestamp")
        timestring = time.strftime(time_format)
    else:
        # In case timestamp is too far in the future
        try:
            timestring = time.strftime(time_format, time.localtime(timestamp))
            logger.debug("DEBUG: Formatted timestamp successfully")
        except ValueError as e:
            logger.debug("DEBUG: Timestamp formatting error, using current time: %s", str(e))
            timestring = time.strftime(time_format)

    if six.PY2:
        logger.debug("DEBUG: Python 2 detected, decoding timestring")
        try:
            decoded = timestring.decode(encoding)
            logger.debug("DEBUG: Successfully decoded timestring")
            return decoded
        except Exception as e:
            logger.debug("DEBUG: Error decoding timestring: %s", str(e))
            return timestring
    
    logger.debug("DEBUG: Returning timestring without decoding (Python 3)")
    return timestring


def getTranslationLanguage():
    """Return the user's language choice"""
    logger.debug("DEBUG: getTranslationLanguage called")
    
    userlocale = config.safeGet(
        'bitmessagesettings', 'userlocale', 'system')
    logger.debug("DEBUG: Retrieved userlocale from config: %s", userlocale)
    
    if userlocale and userlocale != 'system':
        logger.debug("DEBUG: Using user-specified locale: %s", userlocale)
        return userlocale
    
    logger.debug("DEBUG: Using system default language: %s", language)
    return language


def getWindowsLocale(posixLocale):
    """
    Get the Windows locale
    Technically this converts the locale string from UNIX to Windows format,
    because they use different ones in their
    libraries. E.g. "en_EN.UTF-8" to "english".
    """
    logger.debug("DEBUG: getWindowsLocale called with: %s", posixLocale)
    
    if posixLocale in windowsLanguageMap:
        result = windowsLanguageMap[posixLocale]
        logger.debug("DEBUG: Found exact match in language map: %s", result)
        return result
    
    if "." in posixLocale:
        loc = posixLocale.split(".", 1)
        if loc[0] in windowsLanguageMap:
            result = windowsLanguageMap[loc[0]]
            logger.debug("DEBUG: Found match after splitting by dot: %s", result)
            return result
    
    if "_" in posixLocale:
        loc = posixLocale.split("_", 1)
        if loc[0] in windowsLanguageMap:
            result = windowsLanguageMap[loc[0]]
            logger.debug("DEBUG: Found match after splitting by underscore: %s", result)
            return result
    
    if posixLocale != DEFAULT_LANGUAGE:
        logger.debug("DEBUG: Trying with default language: %s", DEFAULT_LANGUAGE)
        return getWindowsLocale(DEFAULT_LANGUAGE)
    
    logger.debug("DEBUG: No matching Windows locale found")
    return None
