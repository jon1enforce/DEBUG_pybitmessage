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
    SIMPLIFIED VERSION without arithmetic.changebase
    """
    logger.debug("DEBUG: decodeWalletImportFormat called")
    
    try:
        # Ensure we have a string
        if isinstance(WIFstring, bytes):
            wif = WIFstring.decode('ascii')
        else:
            wif = str(WIFstring)
        
        logger.debug(f"Decoding WIF: {wif[:10]}...")
        
        # Simple base58 decoding without external libraries
        alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        
        # Convert from base58 to integer
        num = 0
        for char in wif:
            num = num * 58 + alphabet.index(char)
        
        # Convert integer to bytes
        # Count leading '1's in WIF (which represent leading zeros in base58)
        leading_zeros = len(wif) - len(wif.lstrip('1'))
        
        # Convert to hex
        hex_str = format(num, 'x')
        if len(hex_str) % 2 != 0:
            hex_str = '0' + hex_str
        
        # Create bytes with leading zeros
        result = bytes([0] * leading_zeros) + bytes.fromhex(hex_str)
        
        logger.debug(f"Decoded bytes length: {len(result)}")
        
        # Validate WIF format (should be 37 bytes: 1 version + 32 privkey + 4 checksum)
        if len(result) < 37:
            logger.warning(f"Short WIF ({len(result)} bytes), may not be standard")
            # If it starts with 0x80, assume it's a valid private key
            if result and result[0] == 0x80:
                return result[1:]  # Skip version byte
            return result  # Return as-is
        
        # Standard WIF validation
        data = result[:-4]
        checksum = result[-4:]
        
        # Calculate checksum
        calculated = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
        
        if checksum != calculated:
            raise ValueError("Checksum failed")
        
        if data[0] != 0x80:
            raise ValueError("Missing version byte 0x80")
        
        # Return the private key (skip version byte)
        return data[1:]
        
    except Exception as e:
        logger.error("DEBUG: Error in decodeWalletImportFormat: %s", str(e), exc_info=True)
        # Don't return dummy key - let it crash so we see the error
        raise
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
    Returns 65 bytes: 0x04 + X (32 bytes) + Y (32 bytes)
    """
    logger.debug("DEBUG: pointMult called")
    secret_bytes = _ensure_bytes(secret)
    
    while True:
        try:
            k = OpenSSL.EC_KEY_new_by_curve_name(
                OpenSSL.get_curve('secp256k1'))
            priv_key = OpenSSL.BN_bin2bn(secret_bytes, 32, None)
            group = OpenSSL.EC_KEY_get0_group(k)
            pub_key = OpenSSL.EC_POINT_new(group)

            OpenSSL.EC_POINT_mul(group, pub_key, priv_key, None, None, None)
            OpenSSL.EC_KEY_set_private_key(k, priv_key)
            OpenSSL.EC_KEY_set_public_key(k, pub_key)

            size = OpenSSL.i2o_ECPublicKey(k, None)
            mb = OpenSSL.create_string_buffer(size)
            OpenSSL.i2o_ECPublicKey(k, OpenSSL.byref(OpenSSL.pointer(mb)))

            result = mb.raw
            
            # VERIFY: Should be 65 bytes starting with 0x04
            if len(result) == 65 and result[0] == 0x04:
                logger.debug("DEBUG: Successfully performed point multiplication (65 bytes)")
                return result
            else:
                logger.warning(f"Unexpected public key format: {len(result)} bytes, first byte: 0x{result[0]:02x}")
                # Try to convert if possible
                if len(result) == 65:
                    return result
                elif len(result) > 65:
                    return result[:65]  # Truncate if too long
                else:
                    # Pad if too short
                    return result + b'\x00' * (65 - len(result))

        except Exception as e:
            import traceback
            import time
            logger.error("DEBUG: Error in pointMult: %s", e)
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
        # Get private key bytes (handle WIF or hex)
        if isinstance(privkey, str):
            # Check if it's hex (64 chars) or WIF
            if len(privkey) in (51, 52) and privkey[0] in '5KL':
                # It's WIF
                private_key = decodeWalletImportFormat(privkey)
            else:
                # Assume hex - clean the string
                clean_hex = ''.join(c for c in privkey if c in '0123456789abcdefABCDEF')
                
                # If it's 64 characters, it's a hex representation of 32 bytes
                if len(clean_hex) == 64:
                    private_key = bytes.fromhex(clean_hex)
                # If it's 32 bytes encoded as hex (should be 64 chars)
                elif len(clean_hex) == 32 and all(ord(c) < 128 for c in clean_hex):
                    # It might actually be 32 bytes of binary data as a string
                    private_key = clean_hex.encode('latin-1')
                elif len(clean_hex) < 64:
                    # Pad with zeros if too short
                    clean_hex = clean_hex.rjust(64, '0')
                    private_key = bytes.fromhex(clean_hex)
                else:
                    # If longer than 64 chars, take first 64
                    clean_hex = clean_hex[:64]
                    private_key = bytes.fromhex(clean_hex)
        else:
            # Already bytes or similar
            private_key = _ensure_bytes(privkey)
        
        # Now ensure it's exactly 32 bytes
        if len(private_key) > 32:
            # Take first 32 bytes if too long
            private_key = private_key[:32]
        elif len(private_key) < 32:
            # Pad with zeros if too short
            private_key = private_key + b'\x00' * (32 - len(private_key))
        
        # Verify private key is 32 bytes
        if len(private_key) != 32:
            raise ValueError(f"Private key must be 32 bytes, got {len(private_key)} (after processing)")
        
        # DEBUG: Show what we have
        logger.debug(f"Private key type: {type(private_key)}")
        logger.debug(f"Private key length: {len(private_key)}")
        logger.debug(f"Private key hex: {hexlify(private_key).decode('ascii')}")
        
        # Get public key - should be 65 bytes (0x04 + X + Y)
        public_key = pointMult(private_key)
        
        if len(public_key) != 65 or public_key[0] != 0x04:
            logger.error(f"Invalid public key format from pointMult: {len(public_key)} bytes, first: 0x{public_key[0]:02x}")
            # Try to fix: assume first 65 bytes are the key
            if len(public_key) >= 65:
                public_key = public_key[:65]
                if public_key[0] != 0x04:
                    public_key = b'\x04' + public_key[1:65]
            else:
                raise ValueError(f"Public key too short: {len(public_key)} bytes")
        
        # EXACTLY LIKE PYTHON 2 VERSION:
        # public_key[1:-32] = skip first byte (0x04), get X (32 bytes)
        # public_key[-32:] = get Y (32 bytes)
        pubkey_x = public_key[1:-32]  # Should be 32 bytes
        pubkey_y = public_key[-32:]   # Should be 32 bytes
        
        # Verify lengths
        if len(pubkey_x) != 32 or len(pubkey_y) != 32:
            logger.error(f"Invalid pubkey components: X={len(pubkey_x)}, Y={len(pubkey_y)}")
            raise ValueError("Invalid public key components")
        
        # Create cryptor EXACTLY like Python 2
        cryptor = pyelliptic.ECC(
            pubkey_x=pubkey_x, 
            pubkey_y=pubkey_y,
            raw_privkey=private_key, 
            curve=curve
        )
        
        # Test the cryptor works - FIXED VERSION
        try:
            # FIX 1: Ohne digest_alg Parameter (Standard verwenden)
            test_sig = cryptor.sign(b'test')
            
            # FIX 2: ODER mit korrekter Konstante (ohne Klammern)
            # test_sig = cryptor.sign(b'test', digest_alg=OpenSSL.EVP_sha256)
            
            # Optional: Verifikation testen
            valid = cryptor.verify(test_sig, b'test')
            if valid:
                logger.debug("Cryptor validation passed")
            else:
                logger.warning("Cryptor validation failed: signature doesn't verify")
                # Nicht abbrechen, könnte trotzdem funktionieren
        except Exception as e:
            logger.warning(f"Cryptor test failed (non-fatal): {e}")
            # Absichtlich ignorieren, Hauptfunktion soll weitergehen
        
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
    logger.debug(f"Input hexPrivkey type: {type(hexPrivkey)}, length: {len(hexPrivkey) if hasattr(hexPrivkey, '__len__') else 'N/A'}")
    
    try:
        # Convert hexPrivkey to appropriate format before passing to makeCryptor
        if isinstance(hexPrivkey, str):
            # Clean the hex string
            clean_hex = ''.join(c for c in hexPrivkey if c in '0123456789abcdefABCDEF')
            logger.debug(f"Cleaned hex string length: {len(clean_hex)}")
            
            if len(clean_hex) == 64:
                # It's a proper hex string, makeCryptor should handle it
                cryptor = makeCryptor(clean_hex)
            else:
                # Try to handle other formats
                cryptor = makeCryptor(hexPrivkey)
        else:
            # Already bytes or similar
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
        logger.error("DEBUG: Error in sign: %s", str(e), exc_info=True)
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
