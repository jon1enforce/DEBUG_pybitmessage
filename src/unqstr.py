import sys
import six
from helper_sql import safe_decode

def ustr(v):
    """Convert input to appropriate string type for current Python version"""
    print("DEBUG: ustr() called with input type: %s" % type(v))
    
    if six.PY3:
        print("DEBUG: Running on Python 3")
        if isinstance(v, str):
            print("DEBUG: Input is already str, returning as-is")
            return v
        elif isinstance(v, bytes):
            print("DEBUG: Input is bytes, decoding to utf-8 with replacement")
            return safe_decode(v, "utf-8", "replace")
        else:
            print("DEBUG: Input is other type (%s), converting to str" % type(v))
            return str(v)
    
    # assume six.PY2
    print("DEBUG: Running on Python 2")
    if isinstance(v, unicode):
        print("DEBUG: Input is unicode, encoding to utf-8 with replacement")
        return v.encode("utf-8", "replace")
    
    print("DEBUG: Input is other type (%s), converting to str" % type(v))
    return str(v)

def unic(v):
    """Convert input to unicode string (Python 2) or str (Python 3)"""
    print("DEBUG: unic() called with input type: %s" % type(v))
    
    if six.PY3:
        print("DEBUG: Running on Python 3, returning input as-is")
        return v
    
    # assume six.PY2
    print("DEBUG: Running on Python 2")
    if isinstance(v, unicode):
        print("DEBUG: Input is already unicode, returning as-is")
        return v
    
    print("DEBUG: Converting input to unicode with utf-8 decoding and replacement")
    return unicode(v, "utf-8", "replace")

# Debug initialization message
print("DEBUG: unqstr module initialized - Python %s detected" % ("3" if six.PY3 else "2"))
