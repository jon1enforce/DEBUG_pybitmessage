"""
High level cryptographic functions based on `.pyelliptic` OpenSSL bindings.

.. note::
  Upstream pyelliptic was upgraded from SHA1 to SHA256 for signing. We must
  `upgrade PyBitmessage gracefully. <https://github.com/Bitmessage/PyBitmessage/issues/953>`_
  `More discussion. <https://github.com/yann2192/pyelliptic/issues/32>`_
"""

import logging
from unqstr import unic
import hashlib
import os
from binascii import hexlify, unhexlify
import sys

logger = logging.getLogger('default')

try:
    import pyelliptic
    from fallback import RIPEMD160Hash
    from pyelliptic import OpenSSL
    from pyelliptic import arithmetic as a
    logger.debug("DEBUG: Successfully imported pyelliptic and dependencies")
except ImportError:
    from pybitmessage import pyelliptic
    from pybitmessage.fallback import RIPEMD160Hash
    from pybitmessage.pyelliptic import OpenSSL
    from pybitmessage.pyelliptic import arithmetic as a
    logger.debug("DEBUG: Using fallback imports from pybitmessage")


__all__ = [
    'decodeWalletImportFormat', 'deterministic_keys',
    'double_sha512', 'calculateInventoryHash', 'encodeWalletImportFormat',
    'encrypt', 'makeCryptor', 'pointMult', 'privToPub', 'randomBytes',
    'random_keys', 'sign', 'to_ripe', 'verify']


# PYTHON 3 COMPATIBILITY FIXES
def _ensure_bytes(data):
    """Ensure data is bytes for Python 3 compatibility."""
    if isinstance(data, str):
        return data.encode('latin-1')
    elif isinstance(data, bytes):
        return data
    elif isinstance(data, memoryview):
        return bytes(data)
    else:
        return bytes(str(data), 'latin-1')


def _ensure_str(data):
    """Ensure data is string for Python 3 compatibility."""
    if isinstance(data, bytes):
        try:
            return data.decode('utf-8')
        except UnicodeDecodeError:
            return data.decode('latin-1')
    elif isinstance(data, str):
        return data
    else:
        return str(data)


def decodeWalletImportFormat(WIFstring):
    """
    Convert private key from base58 that's used in the config file to
    8-bit binary string.
    """
    logger.debug("DEBUG: decodeWalletImportFormat called with WIFstring")
    try:
        fullString = a.changebase(WIFstring, 58, 256)
        privkey = fullString[:-4]
        
        checksum = hashlib.sha256(hashlib.sha256(privkey).digest()).digest()[:4]
        if fullString[-4:] != checksum:
            logger.error("DEBUG: Checksum failed for WIF string")
            raise ValueError('Checksum failed')
        elif privkey[0:1] == b'\x80':  # checksum passed
            logger.debug("DEBUG: Successfully decoded WIF string")
            return privkey[1:]
        
        logger.error("DEBUG: No hex 80 prefix in WIF string")
        raise ValueError('No hex 80 prefix')
    except Exception as e:
        logger.error("DEBUG: Error in decodeWalletImportFormat: %s", str(e))
        raise


def encodeWalletImportFormat(privKey):
    """
    Convert private key from binary 8-bit string into base58check WIF string.
    """
    logger.debug("DEBUG: encodeWalletImportFormat called")
    try:
        privKey = b'\x80' + privKey
        checksum = hashlib.sha256(hashlib.sha256(privKey).digest()).digest()[0:4]
        result = a.changebase(privKey + checksum, 256, 58)
        logger.debug("DEBUG: Successfully encoded WIF format")
        return result
    except Exception as e:
        logger.error("DEBUG: Error in encodeWalletImportFormat: %s", str(e))
        raise


def randomBytes(n):
    """Get n random bytes"""
    logger.debug("DEBUG: randomBytes called for %d bytes", n)
    try:
        result = os.urandom(n)
        logger.debug("DEBUG: Generated random bytes using os.urandom")
        return result
    except NotImplementedError:
        result = OpenSSL.rand(n)
        logger.debug("DEBUG: Generated random bytes using OpenSSL.rand")
        return result


def _bm160(data):
    """RIPEME160(SHA512(data)) -> bytes"""
    logger.debug("DEBUG: _bm160 hash calculation")
    try:
        sha512_hash = hashlib.sha512(data).digest()
        ripe_hash = RIPEMD160Hash(sha512_hash).digest()
        logger.debug("DEBUG: Completed _bm160 hash")
        return ripe_hash
    except Exception as e:
        logger.error("DEBUG: Error in _bm160: %s", str(e))
        raise


def to_ripe(signing_key, encryption_key):
    """Convert two public keys to a ripe hash"""
    logger.debug("DEBUG: to_ripe called with signing_key and encryption_key")
    try:
        combined = signing_key + encryption_key
        result = _bm160(combined)
        logger.debug("DEBUG: Generated ripe hash successfully")
        return result
    except Exception as e:
        logger.error("DEBUG: Error in to_ripe: %s", str(e))
        raise


def double_sha512(data):
    """Binary double SHA512 digest"""
    logger.debug("DEBUG: double_sha512 called")
    try:
        first_hash = hashlib.sha512(data).digest()
        result = hashlib.sha512(first_hash).digest()
        logger.debug("DEBUG: Completed double SHA512 hash")
        return result
    except Exception as e:
        logger.error("DEBUG: Error in double_sha512: %s", str(e))
        raise


def calculateInventoryHash(data):
    """Calculate inventory hash from object data"""
    logger.debug("DEBUG: calculateInventoryHash called")
    try:
        full_hash = double_sha512(data)
        result = full_hash[:32]
        logger.debug("DEBUG: Calculated inventory hash")
        return result
    except Exception as e:
        logger.error("DEBUG: Error in calculateInventoryHash: %s", str(e))
        raise


def random_keys():
    """Return a pair of keys, private and public"""
    logger.debug("DEBUG: random_keys called")
    try:
        priv = randomBytes(32)
        pub = pointMult(priv)
        logger.debug("DEBUG: Generated random key pair")
        return priv, pub
    except Exception as e:
        logger.error("DEBUG: Error in random_keys: %s", str(e))
        raise


def deterministic_keys(passphrase, nonce):
    """Generate keys from *passphrase* and *nonce* (encoded as varint)"""
    logger.debug("DEBUG: deterministic_keys called")
    try:
        combined = unic(passphrase).encode("utf-8", "replace") + nonce
        priv = hashlib.sha512(combined).digest()[:32]
        pub = pointMult(priv)
        logger.debug("DEBUG: Generated deterministic key pair")
        return priv, pub
    except Exception as e:
        logger.error("DEBUG: Error in deterministic_keys: %s", str(e))
        raise


def hexToPubkey(pubkey):
    """Convert a pubkey from hex to binary"""
    logger = logging.getLogger('highlevelcrypto')
    
    try:
        # Handle input - keep it SIMPLE like Python 2 version
        if isinstance(pubkey, bytes):
            # Convert bytes to string
            hex_string = pubkey.decode('ascii')
        elif isinstance(pubkey, str):
            hex_string = pubkey
        else:
            raise TypeError("pubkey must be str or bytes")
        
        # EXACTLY like Python 2 version: Skip first 2 chars ('04')
        hex_string = hex_string[2:]
        
        # Use manual conversion to avoid a.changebase() bug
        # hex_string should be 128 chars (64 bytes * 2)
        if len(hex_string) != 128:
            # Pad if needed
            hex_string = hex_string.rjust(128, '0')[:128]
        
        # Convert hex to bytes manually
        pubkey_raw = bytes.fromhex(hex_string)
        
        # Build binary format exactly like Python 2
        # Format: b'\x02\xca\x00 ' + X (32 bytes) + b'\x00 ' + Y (32 bytes)
        pubkey_bin = b'\x02\xca\x00 ' + pubkey_raw[:32] + b'\x00 ' + pubkey_raw[32:]
        
        return pubkey_bin
        
    except Exception as e:
        logger.error("Error in hexToPubkey: %s", str(e), exc_info=True)
        raise


def privToPub(privkey):
    """Converts hex private key into hex public key"""
    logger.debug("DEBUG: privToPub called")
    try:
        # PYTHON 3 FIX: Convert hex string to bytes manually
        if isinstance(privkey, str):
            # Remove any spaces or non-hex characters
            privkey_clean = ''.join(c for c in privkey if c in '0123456789abcdefABCDEF')
            if len(privkey_clean) % 2 != 0:
                privkey_clean = '0' + privkey_clean
            private_key = bytes.fromhex(privkey_clean)
        else:
            private_key = _ensure_bytes(privkey)
        
        public_key = pointMult(private_key)
        result = hexlify(public_key)
        logger.debug("DEBUG: Converted private key to public key")
        return result
    except Exception as e:
        logger.error("DEBUG: Error in privToPub: %s", str(e))
        raise


def pointMult(secret):
    """
    Does an EC point multiplication; turns a private key into a public key.
    """
    logger.debug("DEBUG: pointMult called")
    while True:
        try:
            k = OpenSSL.EC_KEY_new_by_curve_name(
                OpenSSL.get_curve('secp256k1'))
            priv_key = OpenSSL.BN_bin2bn(secret, 32, None)
            group = OpenSSL.EC_KEY_get0_group(k)
            pub_key = OpenSSL.EC_POINT_new(group)

            OpenSSL.EC_POINT_mul(group, pub_key, priv_key, None, None, None)
            OpenSSL.EC_KEY_set_private_key(k, priv_key)
            OpenSSL.EC_KEY_set_public_key(k, pub_key)

            size = OpenSSL.i2o_ECPublicKey(k, None)
            mb = OpenSSL.create_string_buffer(size)
            OpenSSL.i2o_ECPublicKey(k, OpenSSL.byref(OpenSSL.pointer(mb)))

            logger.debug("DEBUG: Successfully performed point multiplication")
            return mb.raw

        except Exception:
            import traceback
            import time
            logger.error("DEBUG: Error in pointMult, retrying...")
            traceback.print_exc()
            time.sleep(0.2)
        finally:
            OpenSSL.EC_POINT_free(pub_key)
            OpenSSL.BN_free(priv_key)
            OpenSSL.EC_KEY_free(k)


def makeCryptor(privkey, curve='secp256k1'):
    """Return a private `.pyelliptic.ECC` instance"""
    logger.debug("DEBUG: makeCryptor called")
    try:
        # PYTHON 3 FIX: Convert hex to bytes safely
        if isinstance(privkey, str):
            # Clean hex string
            privkey_clean = ''.join(c for c in privkey if c in '0123456789abcdefABCDEF')
            if len(privkey_clean) % 2 != 0:
                privkey_clean = '0' + privkey_clean
            private_key = bytes.fromhex(privkey_clean)
        else:
            private_key = _ensure_bytes(privkey)
        
        public_key = pointMult(private_key)
        
        # Extract X and Y coordinates from public key
        # Public key format: b'\x02\xca\x00 ' + X + b'\x00 ' + Y
        if len(public_key) >= 66:
            pubkey_x = public_key[1:-32]  # Skip first byte, get X (32 bytes)
            pubkey_y = public_key[-32:]    # Get Y (32 bytes)
        else:
            # Fallback for older format
            pubkey_x = public_key[1:33]
            pubkey_y = public_key[33:]
        
        cryptor = pyelliptic.ECC(
            pubkey_x=pubkey_x, 
            pubkey_y=pubkey_y,
            raw_privkey=private_key, 
            curve=curve
        )
        logger.debug("DEBUG: Created cryptor successfully")
        return cryptor
    except Exception as e:
        logger.error("DEBUG: Error in makeCryptor: %s", str(e))
        raise


def makePubCryptor(pubkey):
    """Return a public `.pyelliptic.ECC` instance"""
    logger = logging.getLogger('highlevelcrypto')
    logger.debug("=== MAKEPUBCRYPTOR DEBUG ===")
    logger.debug("Python version: %s", sys.version)
    
    try:
        # First, ensure we have the correct format
        if isinstance(pubkey, bytes):
            # Check if it's already in binary format (starts with b'\x02\xca')
            if pubkey.startswith(b'\x02\xca'):
                logger.debug("Pubkey already in binary format")
                pubkey_bin = pubkey
            else:
                # Convert using hexToPubkey
                pubkey_bin = hexToPubkey(pubkey)
                logger.debug("Converted to binary via hexToPubkey")
        else:
            # Assume it's hex string
            pubkey_bin = hexToPubkey(pubkey)
            logger.debug("Converted hex string to binary")
        
        logger.debug("Binary pubkey length: %d", len(pubkey_bin))
        logger.debug("Binary pubkey first 20 bytes: %s", hexlify(pubkey_bin[:20]))
        
        # Create ECC instance
        cryptor = pyelliptic.ECC(curve='secp256k1', pubkey=pubkey_bin)
        logger.debug("Created public cryptor successfully")
        logger.debug("=== MAKEPUBCRYPTOR DEBUG END ===")
        return cryptor
        
    except Exception as e:
        logger.error("Error in makePubCryptor: %s", str(e), exc_info=True)
        logger.debug("=== MAKEPUBCRYPTOR DEBUG END (ERROR) ===")
        raise


def encrypt(msg, hexPubkey):
    """Encrypts message with hex public key"""
    logger.debug("DEBUG: encrypt called")
    try:
        # Convert message to bytes if needed
        if isinstance(msg, str):
            msg_bytes = msg.encode('utf-8')
        else:
            msg_bytes = _ensure_bytes(msg)
        
        cryptor = pyelliptic.ECC(curve='secp256k1')
        pubkey_bin = hexToPubkey(hexPubkey)
        result = cryptor.encrypt(msg_bytes, pubkey_bin)
        logger.debug("DEBUG: Message encrypted successfully")
        return result
    except Exception as e:
        logger.error("DEBUG: Error in encrypt: %s", str(e))
        raise


def decrypt(msg, hexPrivkey):
    """Decrypts message with hex private key"""
    logger.debug("DEBUG: decrypt called")
    try:
        cryptor = makeCryptor(hexPrivkey)
        result = cryptor.decrypt(msg)
        logger.debug("DEBUG: Message decrypted successfully")
        return result
    except Exception as e:
        logger.error("DEBUG: Error in decrypt: %s", str(e))
        raise


def decryptFast(msg, cryptor):
    """Decrypts message with an existing `.pyelliptic.ECC` object"""
    logger.debug("DEBUG: decryptFast called")
    try:
        result = cryptor.decrypt(msg)
        logger.debug("DEBUG: Message decrypted (fast) successfully")
        return result
    except Exception as e:
        logger.error("DEBUG: Error in decryptFast: %s", str(e))
        raise


def _choose_digest_alg(name):
    """Choose openssl digest constant by name"""
    logger.debug("DEBUG: _choose_digest_alg called with: %s", name)
    if name not in ("sha1", "sha256"):
        logger.error("DEBUG: Unknown digest algorithm: %s", name)
        raise ValueError("Unknown digest algorithm %s" % name)
    
    result = OpenSSL.digest_ecdsa_sha1 if name == "sha1" else OpenSSL.EVP_sha256
    logger.debug("DEBUG: Selected digest algorithm: %s", name)
    return result


def sign(msg, hexPrivkey, digestAlg="sha256"):
    """Signs with hex private key"""
    logger.debug("DEBUG: sign called with digestAlg: %s", digestAlg)
    try:
        cryptor = makeCryptor(hexPrivkey)
        
        # Convert message to bytes if needed
        if isinstance(msg, str):
            msg_bytes = msg.encode('utf-8')
        else:
            msg_bytes = _ensure_bytes(msg)
        
        result = cryptor.sign(msg_bytes, digest_alg=_choose_digest_alg(digestAlg))
        logger.debug("DEBUG: Message signed successfully")
        return result
    except Exception as e:
        logger.error("DEBUG: Error in sign: %s", str(e))
        raise


def verify(msg, sig, hexPubkey, digestAlg=None):
    """Verifies with hex public key"""
    import sys
    logger = logging.getLogger('highlevelcrypto')
    
    logger.debug("=== HIGHLEVELCRYPTO VERIFY DEBUG START ===")
    logger.debug("Python version: %s", sys.version)
    logger.debug("Input message type: %s, length: %d", type(msg), len(msg))
    logger.debug("Input signature type: %s, length: %d", type(sig), len(sig))
    logger.debug("Input hexPubkey type: %s, length: %d", type(hexPubkey), len(hexPubkey))
    
    try:
        # 1. Convert all inputs to appropriate types
        msg_bytes = _ensure_bytes(msg)
        sig_bytes = _ensure_bytes(sig)
        hexPubkey_str = _ensure_str(hexPubkey)
        
        logger.debug("Converted message length: %d", len(msg_bytes))
        logger.debug("Converted signature length: %d", len(sig_bytes))
        logger.debug("Converted pubkey: %s...", hexPubkey_str[:100])
        
        # 2. Try different digest algorithms if not specified
        if digestAlg is None:
            logger.debug("No digestAlg specified, trying SHA256 then SHA1")
            
            # Try SHA256 first (newer)
            logger.debug("=== TRYING SHA256 ===")
            try:
                if _verify_single(msg_bytes, sig_bytes, hexPubkey_str, "sha256"):
                    logger.debug("=== VERIFY SUCCESS WITH SHA256 ===")
                    logger.debug("=== HIGHLEVELCRYPTO VERIFY DEBUG END ===")
                    return True
            except Exception as e:
                logger.debug("SHA256 verify exception: %s", e)
            
            # Try SHA1 (older)
            logger.debug("=== TRYING SHA1 ===")
            try:
                if _verify_single(msg_bytes, sig_bytes, hexPubkey_str, "sha1"):
                    logger.debug("=== VERIFY SUCCESS WITH SHA1 ===")
                    logger.debug("=== HIGHLEVELCRYPTO VERIFY DEBUG END ===")
                    return True
            except Exception as e:
                logger.debug("SHA1 verify exception: %s", e)
            
            logger.debug("=== ALL DIGEST ALGORITHMS FAILED ===")
            logger.debug("=== HIGHLEVELCRYPTO VERIFY DEBUG END ===")
            return False
        
        # 3. Specific digest algorithm
        logger.debug("Using specific digest algorithm: %s", digestAlg)
        return _verify_single(msg_bytes, sig_bytes, hexPubkey_str, digestAlg)
        
    except Exception as e:
        logger.error("Unhandled exception in verify: %s", e, exc_info=True)
        logger.debug("=== HIGHLEVELCRYPTO VERIFY DEBUG END ===")
        return False


def _verify_single(msg_bytes, sig_bytes, hexPubkey_str, digestAlg):
    """Internal helper for verification with specific algorithm"""
    logger = logging.getLogger('highlevelcrypto')
    
    # Try different pubkey formats
    test_keys = []
    
    # Original format
    test_keys.append(("original", hexPubkey_str))
    
    # Without '04' prefix
    if hexPubkey_str.startswith('04'):
        test_keys.append(("without_04", hexPubkey_str[2:]))
    
    # With '04' prefix if missing
    if not hexPubkey_str.startswith('04'):
        test_keys.append(("with_04", '04' + hexPubkey_str))
    
    # Lowercase
    test_keys.append(("lowercase", hexPubkey_str.lower()))
    
    # Uppercase
    test_keys.append(("uppercase", hexPubkey_str.upper()))
    
    for test_name, test_key in test_keys:
        logger.debug("=== TRYING KEY FORMAT: %s ===", test_name)
        try:
            cryptor = makePubCryptor(test_key)
            result = cryptor.verify(
                sig_bytes, 
                msg_bytes, 
                digest_alg=_choose_digest_alg(digestAlg)
            )
            logger.debug("Verify with format '%s': %s", test_name, result)
            if result:
                logger.info("=== VERIFICATION SUCCESS with format: %s ===", test_name)
                return True
        except Exception as e:
            logger.debug("Verify with format '%s' failed: %s", test_name, str(e))
    
    logger.error("=== ALL PUBKEY FORMATS FAILED for %s ===", digestAlg)
    return False


# PYTHON 3 COMPATIBILITY MONKEY-PATCH
if sys.version_info[0] >= 3:
    logger.debug("Applying Python 3 compatibility patches...")
    
    # Patch arithmetic functions to handle Python 3 properly
    original_decode = a.decode
    
    def patched_decode(string, base):
        """Patched decode function for Python 3 compatibility"""
        # Get code string
        code_string = a.get_code_string(base)
        result = 0
        
        # Handle different input types
        if base == 256:
            # For base 256, code_string is bytes
            if isinstance(string, str):
                string = string.encode('latin-1')
            
            # Process each byte
            for byte in string:
                if isinstance(byte, int):
                    # Python 3: byte is int (0-255)
                    result = result * base + byte
                else:
                    # Python 2: byte is bytes/str
                    result = result * base + code_string.find(byte)
        else:
            # For other bases
            if isinstance(string, bytes):
                if base == 16:
                    string = string.decode('ascii').lower()
                else:
                    string = string.decode('latin-1')
            elif base == 16 and isinstance(string, str):
                string = string.lower()
            
            # Process each character
            for char in string:
                result = result * base + code_string.find(char)
        
        return result
    
    # Apply the patch
    a.decode = patched_decode
    logger.debug("Patched a.decode() for Python 3 compatibility")
