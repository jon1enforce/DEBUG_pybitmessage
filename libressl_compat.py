#!/usr/bin/env python3
# test_openssl_compat.py

import ctypes
import sys

def test_libressl_compatibility(lib_path):
    try:
        openssl = ctypes.CDLL(lib_path)
        
        # Test basic functions
        version_func = openssl.SSLeay_version
        version_func.restype = ctypes.c_char_p
        version_func.argtypes = [ctypes.c_int]
        
        version = version_func(0)
        print(f"Library version: {version}")
        
        # Test some common functions that PyBitmessage uses
        test_functions = [
            'SSL_new', 'SSL_free', 'SSL_accept', 'SSL_connect',
            'SSL_read', 'SSL_write', 'SSL_shutdown'
        ]
        
        for func_name in test_functions:
            try:
                func = getattr(openssl, func_name)
                print(f"✓ {func_name} found")
            except AttributeError:
                print(f"✗ {func_name} missing")
                
        return True
        
    except Exception as e:
        print(f"Error loading {lib_path}: {e}")
        return False

# Test your compiled LibreSSL
print("Testing your compiled LibreSSL 2.5.0...")
test_libressl_compatibility("/home/libressl-2.5.0/build/ssl/libssl.so")
