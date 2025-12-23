import sys
import six
from helper_sql import safe_decode

def ustr(v):
    """Convert input to appropriate string type for current Python version"""
    
    if six.PY3:
        if isinstance(v, str):
            return v
        elif isinstance(v, bytes):
            return safe_decode(v, "utf-8", "replace")
        else:
            return str(v)
    
    # assume six.PY2
    if isinstance(v, unicode):
        return v.encode("utf-8", "replace")
    
    return str(v)

def unic(v):
    """Convert input to unicode string (Python 2) or str (Python 3)"""
    
    if six.PY3:
        return v
    
    # assume six.PY2
    if isinstance(v, unicode):
        return v
    
    return unicode(v, "utf-8", "replace")
