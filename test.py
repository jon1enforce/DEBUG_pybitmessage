# test_ecdsa.py
import sys
sys.path.insert(0, '/home/jon/DEBUG_pybitmessage/src')

import highlevelcrypto
import hashlib
from binascii import hexlify, unhexlify

print("Testing ECDSA functions...")

# Test 1: SHA256
print("\n1. Testing SHA256...")
test_data = b"test message"
hash_result = hashlib.sha256(test_data).hexdigest()
print(f"   SHA256('test message') = {hash_result}")

# Test 2: ECDSA Key Generation
print("\n2. Testing ECDSA key generation...")
try:
    privkey = highlevelcrypto.randomBytes(32)
    pubkey = highlevelcrypto.privToPub(hexlify(privkey))
    print(f"   Private key: {hexlify(privkey)[:64]}...")
    print(f"   Public key: {pubkey[:128]}...")
    print("   ✓ Key generation successful")
except Exception as e:
    print(f"   ✗ Key generation failed: {e}")

# Test 3: ECDSA Sign/Verify
print("\n3. Testing ECDSA sign/verify...")
try:
    # Generate keys
    privkey = highlevelcrypto.randomBytes(32)
    privkey_hex = hexlify(privkey).decode()
    pubkey = highlevelcrypto.privToPub(privkey_hex)
    
    # Sign message
    message = b"test message to sign"
    signature = highlevelcrypto.sign(message, privkey_hex)
    print(f"   Signature length: {len(signature)}")
    
    # Verify signature
    verify_result = highlevelcrypto.verify(message, signature, pubkey)
    print(f"   Verification result: {verify_result}")
    
    if verify_result:
        print("   ✓ Sign/verify successful")
    else:
        print("   ✗ Sign/verify failed")
        
except Exception as e:
    print(f"   ✗ Sign/verify failed: {e}")
    import traceback
    traceback.print_exc()

# Test 4: Check bitmsghash module
print("\n4. Checking bitmsghash module...")
try:
    import bitmsghash
    print(f"   bitmsghash module loaded: {bitmsghash}")
    print(f"   Functions available: {[x for x in dir(bitmsghash) if not x.startswith('_')]}")
except Exception as e:
    print(f"   ✗ bitmsghash not available: {e}")
    
    # Try alternative
    try:
        from bitmsghash import bitmsghash as bmh
        print(f"   Alternative import successful: {bmh}")
    except:
        print("   Alternative import also failed")
