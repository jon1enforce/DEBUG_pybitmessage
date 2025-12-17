#!/usr/bin/env python3
# test_pow2.py - Debug PoW Problem

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

import hashlib
import proofofwork
import time

print("=== TESTING PoW ===")

# 1. Welche PoW-Methode wird verwendet?
print("1. Checking PoW type...")
try:
    from proofofwork import getPowType
    pow_type = getPowType()
    print(f"   PoW Type: {pow_type}")
except Exception as e:
    print(f"   Error getting PoW type: {e}")

# 2. Test mit einfachem Target
print("\n2. Testing simple PoW...")
test_data = b"test123"
test_hash = hashlib.sha512(test_data).digest()[:32]
target = 2**58  # Einfache Difficulty

print(f"   Target: {target}")
print(f"   Hash length: {len(test_hash)} bytes")

start_time = time.time()

try:
    # Direkt _doFastPoW testen
    print("   Testing _doFastPoW...")
    result = proofofwork._doFastPoW(target, test_hash)
    elapsed = time.time() - start_time
    print(f"   SUCCESS! Result: {result}")
    print(f"   Time: {elapsed:.2f} seconds")
    
except Exception as e:
    elapsed = time.time() - start_time
    print(f"   ERROR in _doFastPoW: {e}")
    print(f"   Time: {elapsed:.2f} seconds")
    
    # Test _doSafePoW
    try:
        print("\n   Testing _doSafePoW...")
        start_time = time.time()
        result = proofofwork._doSafePoW(target, test_hash)
        elapsed = time.time() - start_time
        print(f"   SUCCESS! Result: {result}")
        print(f"   Time: {elapsed:.2f} seconds")
    except Exception as e2:
        elapsed = time.time() - start_time
        print(f"   ERROR in _doSafePoW: {e2}")
        print(f"   Time: {elapsed:.2f} seconds")

# 3. Check state.shutdown
print("\n3. Checking state...")
try:
    import state
    print(f"   state.shutdown = {state.shutdown}")
except Exception as e:
    print(f"   Error checking state: {e}")

print("\n=== TEST COMPLETE ===")
