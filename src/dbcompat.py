import logging
import six
from helper_sql import safe_decode

logger = logging.getLogger("default")

def dbstr(v):
    if six.PY3:
        if isinstance(v, str):
            return v
        elif isinstance(v, bytes):
            return safe_decode(v, "utf-8", "replace")
        logger.debug("unexpected type in dbstr(): {}".format(type(v)))
        return v  # hope this never happens..
    else:  # assume six.PY2
        if isinstance(v, unicode):
            return v.encode("utf-8", "replace")
        elif isinstance(v, str):
            return v
        elif isinstance(v, bytes):
            return str(v)
        logger.debug("unexpected type in dbstr(): {}".format(type(v)))
        return v  # hope this never happens..
