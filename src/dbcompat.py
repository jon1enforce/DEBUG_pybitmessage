import logging
import six

# Debug setup
DEBUG = True

def debug_print(message):
    if DEBUG:
        print(f"DEBUG: {message}")

debug_print("Initializing dbcompat module")

logger = logging.getLogger("default")

def dbstr(v):
    """Convert database values to appropriate string type for Python version.
    
    Args:
        v: Input value to convert (str, bytes, or unicode)
    
    Returns:
        Appropriate string type for current Python version
    """
    debug_print(f"Starting dbstr conversion for value: {v} (type: {type(v)})")
    
    if six.PY3:
        debug_print("Python 3 environment detected")
        if isinstance(v, str):
            debug_print("Input is already str type, returning as-is")
            return v
        elif isinstance(v, bytes):
            debug_print("Input is bytes type, decoding to utf-8 with replacement")
            return v.decode("utf-8", "replace")
        debug_print(f"Unexpected type in dbstr(): {type(v)}")
        logger.debug("unexpected type in dbstr(): {}".format(type(v)))
        debug_print("Returning unconverted value as fallback")
        return v  # hope this never happens..
    else:  # assume six.PY2
        debug_print("Python 2 environment detected")
        if isinstance(v, unicode):
            debug_print("Input is unicode type, encoding to utf-8 with replacement")
            return v.encode("utf-8", "replace")
        elif isinstance(v, str):
            debug_print("Input is already str type, returning as-is")
            return v
        elif isinstance(v, bytes):
            debug_print("Input is bytes type, converting to str")
            return str(v)
        debug_print(f"Unexpected type in dbstr(): {type(v)}")
        logger.debug("unexpected type in dbstr(): {}".format(type(v)))
        debug_print("Returning unconverted value as fallback")
        return v  # hope this never happens..

debug_print("dbcompat module initialization complete")
