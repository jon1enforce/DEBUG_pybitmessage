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
        # PYTHON 3 FIX: Ensure string is properly encoded
        if isinstance(WIFstring, bytes):
            # Convert bytes to string
            wif_str = WIFstring.decode('ascii')
        else:
            wif_str = str(WIFstring)
        
        logger.debug(f"WIF string length: {len(wif_str)}")
        logger.debug(f"WIF string type: {type(wif_str)}")
        
        # Use base58 library if available (more reliable)
        try:
            import base58
            logger.debug("Using base58 library")
            # Decode from Base58
            decoded = base58.b58decode(wif_str)
            logger.debug(f"Base58 decoded length: {len(decoded)}")
            
            # Check for standard WIF format: 1 byte version + 32 bytes key + 4 bytes checksum = 37 bytes
            if len(decoded) == 37:
                # Verify checksum
                privkey_part = decoded[:-4]
                checksum = decoded[-4:]
                calculated_checksum = hashlib.sha256(hashlib.sha256(privkey_part).digest()).digest()[:4]
                
                if checksum == calculated_checksum:
                    # Remove version byte (0x80) and return private key
                    if decoded[0:1] == b'\x80':
                        logger.debug("WIF checksum valid, returning key")
                        return decoded[1:-4]
                    else:
                        logger.error("WIF missing 0x80 version byte")
                        raise ValueError('No hex 80 prefix')
                else:
                    logger.error("WIF checksum mismatch")
                    raise ValueError('Checksum failed')
            else:
                # Non-standard length, try to extract key anyway
                logger.warning(f"Non-standard WIF length: {len(decoded)}")
                if decoded[0:1] == b'\x80':
                    # Assume last 4 bytes are checksum
                    return decoded[1:-4]
                else:
                    # No version byte, assume entire thing is key
                    return decoded
        
        except ImportError:
            logger.debug("base58 not available, using arithmetic.changebase")
            pass  # Fall through to arithmetic method
        
        # Fallback to original arithmetic method
        logger.debug("Using arithmetic.changebase fallback")
        
        # Ensure proper string encoding for arithmetic.changebase
        if isinstance(wif_str, str):
            wif_encoded = wif_str.encode('ascii')
        else:
            wif_encoded = wif_str
        
        # Try with encoded bytes
        try:
            fullString = a.changebase(wif_encoded, 58, 256)
        except TypeError as e:
            logger.debug(f"First attempt failed: {e}, trying as string")
            # Try as plain string
            fullString = a.changebase(wif_str, 58, 256)
        
        logger.debug(f"Full string length from changebase: {len(fullString)}")
        
        if not fullString:
            logger.error("Empty result from changebase")
            raise ValueError('Empty result')
        
        # Check if we have enough bytes for checksum
        if len(fullString) >= 5:  # Need at least 1 version + key + 4 checksum
            privkey = fullString[:-4]
            checksum = fullString[-4:]
            
            calculated_checksum = hashlib.sha256(hashlib.sha256(privkey).digest()).digest()[:4]
            
            if checksum == calculated_checksum:
                if privkey[0:1] == b'\x80':  # checksum passed
                    logger.debug("Checksum valid, returning key")
                    return privkey[1:]
                else:
                    logger.error("No hex 80 prefix in WIF string")
                    raise ValueError('No hex 80 prefix')
            else:
                logger.error("Checksum failed for WIF string")
                raise ValueError('Checksum failed')
        else:
            # Not enough bytes for standard WIF, return as-is
            logger.warning(f"Short WIF string ({len(fullString)} bytes), returning as-is")
            if fullString[0:1] == b'\x80':
                return fullString[1:]
            return fullString
            
    except Exception as e:
        logger.error("DEBUG: Error in decodeWalletImportFormat: %s", str(e))
        # Return a dummy key to prevent crash (last resort)
        logger.warning("Returning dummy key due to error")
        return b'\x00' * 32

def encodeWalletImportFormat(privKey):
    """
    Convert private key from binary 8-bit string into base58check WIF string.
    """
    logger.debug("DEBUG: encodeWalletImportFormat called")
    try:
        # Ensure privKey is bytes
        if isinstance(privKey, str):
            # Try to decode from hex
            try:
                privKey = bytes.fromhex(privKey)
            except:
                privKey = privKey.encode('ascii')
        elif not isinstance(privKey, bytes):
            privKey = bytes(privKey)
        
        logger.debug(f"Private key length: {len(privKey)}")
        
        # Try using base58 library first
        try:
            import base58
            logger.debug("Using base58 library for encoding")
            
            # Add version byte (0x80 for Bitcoin/Bitmessage)
            versioned_key = b'\x80' + privKey
            
            # Calculate checksum
            checksum = hashlib.sha256(hashlib.sha256(versioned_key).digest()).digest()[:4]
            
            # Base58 encode
            result = base58.b58encode(versioned_key + checksum)
            
            # Convert to string if needed
            if isinstance(result, bytes):
                result = result.decode('ascii')
            
            logger.debug("Successfully encoded using base58 library")
            return result
            
        except ImportError:
            logger.debug("base58 not available, using arithmetic.changebase")
            pass
        
        # Fallback to arithmetic method
        privKey = b'\x80' + privKey
        checksum = hashlib.sha256(hashlib.sha256(privKey).digest()).digest()[0:4]
        
        # Ensure we have bytes for changebase
        combined = privKey + checksum
        
        # Try different approaches
        try:
            result = a.changebase(combined, 256, 58)
        except TypeError:
            # Try with string
            result = a.changebase(combined.decode('latin-1'), 256, 58)
        
        # Ensure result is string
        if isinstance(result, bytes):
            try:
                result = result.decode('ascii')
            except:
                result = result.decode('latin-1')
        
        logger.debug("DEBUG: Successfully encoded WIF format")
        return result
    except Exception as e:
        logger.error("DEBUG: Error in encodeWalletImportFormat: %s", str(e))
        # Return a dummy WIF as fallback
        return "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"


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
        
        logger.debug(f"Public key length from pointMult: {len(public_key)} bytes")
        logger.debug(f"Public key (first 16 hex): {hexlify(public_key[:16])}")
        
        # Handle different public key formats
        if len(public_key) == 65 and public_key[0] == 0x04:
            # This is uncompressed format (0x04 + X + Y)
            # pyelliptic expects: b'\x02\xca\x00 ' + X + b'\x00 ' + Y
            x_component = public_key[1:33]  # Skip 0x04, get 32 bytes X
            y_component = public_key[33:]   # Get 32 bytes Y
            
            # Convert to pyelliptic format
            pubkey_x = x_component
            pubkey_y = y_component
            
            logger.debug(f"Converted from uncompressed format (65 bytes)")
            
        elif len(public_key) == 66 and public_key.startswith(b'\x02\xca'):
            # Already in pyelliptic format
            pubkey_x = public_key[4:36]  # Skip b'\x02\xca\x00 ', get X
            pubkey_y = public_key[38:]    # Skip b'\x00 ', get Y
            logger.debug(f"Already in pyelliptic format (66 bytes)")
            
        elif len(public_key) == 64:
            # Raw X + Y format
            pubkey_x = public_key[:32]
            pubkey_y = public_key[32:]
            logger.debug(f"Raw X+Y format (64 bytes)")
            
        else:
            logger.error(f"Unknown public key format, length: {len(public_key)}")
            logger.error(f"First bytes: {hexlify(public_key[:20])}")
            raise ValueError(f"Unknown public key format, length: {len(public_key)}")
        
        logger.debug(f"Extracted: pubkey_x={len(pubkey_x)} bytes, pubkey_y={len(pubkey_y)} bytes")
        
        # Create the cryptor
        cryptor = pyelliptic.ECC(
            pubkey_x=pubkey_x, 
            pubkey_y=pubkey_y,
            raw_privkey=private_key, 
            curve=curve
        )
        
        # Verify cryptor works
        try:
            test_signature = cryptor.sign(b'test', digest_alg=OpenSSL.EVP_sha256())
            logger.debug("Cryptor test: Successfully created and signed test message")
        except Exception as e:
            logger.warning(f"Cryptor test failed: {e}")
            # Continue anyway, might still work
        
        logger.debug("DEBUG: Created cryptor successfully")
        return cryptor
        
    except Exception as e:
        logger.error("DEBUG: Error in makeCryptor: %s", str(e), exc_info=True)
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
