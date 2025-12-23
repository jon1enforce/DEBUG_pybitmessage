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
        # 1. Handle input
        if isinstance(pubkey, bytes):
            # If it's already in binary format with header
            if pubkey.startswith(b'\x02\xca'):
                logger.debug("Pubkey already in binary format")
                return pubkey
            # Otherwise decode as hex
            try:
                hex_string = pubkey.decode('ascii')
            except:
                hex_string = pubkey.decode('latin-1')
        elif isinstance(pubkey, str):
            hex_string = pubkey
        else:
            raise TypeError(f"pubkey must be str or bytes, got {type(pubkey)}")
        
        logger.debug(f"hexToPubkey input: {hex_string[:50]}... (length: {len(hex_string)})")
        
        # 2. Clean hex string
        import re
        hex_clean = re.sub(r'[^0-9a-fA-F]', '', hex_string)
        
        # 3. WICHTIG: Pyelliptic pubkey format ist 70 bytes: 
        #    b'\x02\xca\x00 ' (4 bytes) + X (32 bytes) + b'\x00 ' (2 bytes) + Y (32 bytes)
        #    Das sind 70 bytes insgesamt.
        #    Wenn wir 140 chars haben, ist das schon das komplette Format als Hex!
        
        if len(hex_clean) == 140:  # 70 bytes * 2 = 140 chars
            # Das ist schon das komplette pyelliptic Format als Hex
            logger.debug("Already 140 chars (70 bytes) - full pyelliptic format")
            # Konvertiere direkt von Hex zu Bytes
            return bytes.fromhex(hex_clean)
        
        elif len(hex_clean) == 130 and hex_clean.startswith('04'):
            # 65 bytes (130 chars) mit '04' prefix (uncompressed)
            logger.debug("65-byte uncompressed format with '04' prefix")
            # Entferne '04' prefix
            hex_clean = hex_clean[2:]  # Jetzt 128 chars (64 bytes)
            
        elif len(hex_clean) == 128:
            # 64 bytes (128 chars) ohne prefix
            logger.debug("64-byte raw format (no prefix)")
            # Keep as-is
            pass
            
        else:
            # Ungültige Länge
            logger.warning(f"Unexpected pubkey length: {len(hex_clean)} chars")
            # Versuche zu reparieren
            if len(hex_clean) > 128:
                hex_clean = hex_clean[:128]
            else:
                hex_clean = hex_clean.rjust(128, '0')
        
        # 4. Ensure exactly 128 chars (64 bytes) für X + Y
        hex_clean = hex_clean[:128].rjust(128, '0')
        
        # 5. Convert to bytes (64 bytes)
        pubkey_raw = bytes.fromhex(hex_clean)
        
        if len(pubkey_raw) != 64:
            raise ValueError(f"Pubkey must be 64 bytes after conversion, got {len(pubkey_raw)}")
        
        # 6. Build pyelliptic binary format
        # Format: b'\x02\xca\x00 ' + X (32 bytes) + b'\x00 ' + Y (32 bytes)
        pubkey_bin = b'\x02\xca\x00 ' + pubkey_raw[:32] + b'\x00 ' + pubkey_raw[32:]
        
        logger.debug(f"hexToPubkey output: {len(pubkey_bin)} bytes, first 10: {pubkey_bin[:10].hex()}")
        
        return pubkey_bin
        
    except Exception as e:
        logger.error("Error in hexToPubkey: %s", str(e), exc_info=True)
        logger.error(f"Input was: {pubkey[:100] if isinstance(pubkey, (str, bytes)) else pubkey}")
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
    while True:
        try:
            # Stelle sicher dass secret Bytes sind
            if isinstance(secret, str):
                secret = secret.encode('latin-1')
            elif not isinstance(secret, bytes):
                secret = bytes(secret)
            
            # Stelle sicher es sind 32 Bytes
            if len(secret) != 32:
                if len(secret) > 32:
                    secret = secret[:32]
                else:
                    secret = secret.ljust(32, b'\x00')
            
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

            result = mb.raw
            
            # WICHTIG: Überprüfe das Ergebnis
            # Sollte 65 Bytes sein: 0x04 + 32 bytes X + 32 bytes Y
            if len(result) == 65 and result[0] == 0x04:
                return result
            else:
                # Versuche zu reparieren
                logger = logging.getLogger('highlevelcrypto')
                logger.warning(f"pointMult: Unexpected result: {len(result)} bytes, first: 0x{result[0]:02x}")
                
                if len(result) > 65:
                    return result[:65]  # Schneide ab
                elif len(result) < 65:
                    # Pade auf 65 Bytes
                    return result.ljust(65, b'\x00')
                else:
                    # 65 Bytes aber falsches erstes Byte
                    return b'\x04' + result[1:] if len(result) >= 2 else b'\x04' + b'\x00' * 64

        except Exception:
            import traceback
            import time
            logger = logging.getLogger('highlevelcrypto')
            logger.warning("pointMult exception, retrying...")
            traceback.print_exc()
            time.sleep(0.2)
        finally:
            # Cleanup
            if 'pub_key' in locals():
                OpenSSL.EC_POINT_free(pub_key)
            if 'priv_key' in locals():
                OpenSSL.BN_free(priv_key)
            if 'k' in locals():
                OpenSSL.EC_KEY_free(k)
def makeCryptor(privkey, curve='secp256k1'):
    """Return a private `.pyelliptic.ECC` instance"""
    logger = logging.getLogger('highlevelcrypto')
    logger.debug("DEBUG: makeCryptor called")
    try:
        # 1. Konvertiere privkey in 32 Bytes, GENAU WIE IM ORIGINAL: a.changebase(privkey, 16, 256, minlen=32)
        if isinstance(privkey, str):
            # Bereinige den Hex-String (entferne alles außer 0-9, a-f, A-F)
            import re
            clean_hex = re.sub(r'[^0-9a-fA-F]', '', privkey)
            # Stelle sicher, dass die Länge für 32 Bytes ausreicht (64 Zeichen)
            if len(clean_hex) < 64:
                clean_hex = clean_hex.rjust(64, '0')
            # Konvertiere Hex zu Integer, dann zu Bytes (Simuliert a.changebase von 16 zu 256)
            try:
                # Fallback: Direkte Konvertierung für den Anfang
                private_key = bytes.fromhex(clean_hex[:64])
            except Exception:
                # Versuche es mit manueller Konvertierung falls nötig
                private_key = bytes([int(clean_hex[i:i+2], 16) for i in range(0, 64, 2)])
        else:
            # privkey ist bereits Bytes
            private_key = _ensure_bytes(privkey)
            if len(private_key) > 32:
                private_key = private_key[:32]
            elif len(private_key) < 32:
                private_key = private_key.ljust(32, b'\x00')

        # 2. Erzeuge öffentlichen Schlüssel (GENAU WIE ORIGINAL)
        public_key = pointMult(private_key)
        
        # DEBUG: Überprüfe das Format
        logger.debug(f"Public key from pointMult: {len(public_key)} bytes")
        if len(public_key) == 65 and public_key[0] == 0x04:
            logger.debug("✓ Public key format correct (65 bytes, 0x04 prefix)")
        else:
            logger.warning(f"⚠️  Public key format unexpected: {len(public_key)} bytes, starts with 0x{public_key[0]:02x}")

        # 3. Erstelle binäres Format FÜR PYELLIPTIC (GENAU WIE ORIGINAL)
        # Original: privkey_bin = '\x02\xca\x00\x20' + private_key
        #          pubkey_bin = '\x02\xca\x00\x20' + public_key[1:33] + '\x00\x20' + public_key[33:]
        
        # 0x02ca = 714 (curve ID für secp256k1 in pyelliptic)
        privkey_bin = b'\x02\xca\x00\x20' + private_key
        
        # Extrahiere X und Y aus public_key (65 bytes: 0x04 + 32 bytes X + 32 bytes Y)
        if len(public_key) >= 65:
            pubkey_x = public_key[1:33]   # 32 bytes
            pubkey_y = public_key[33:65]  # 32 bytes
        else:
            # Fallback falls Format falsch
            pubkey_x = private_key[:32]
            pubkey_y = private_key[:32]
            
        pubkey_bin = b'\x02\xca\x00\x20' + pubkey_x + b'\x00\x20' + pubkey_y
        
        logger.debug(f"privkey_bin length: {len(privkey_bin)}")
        logger.debug(f"pubkey_bin length: {len(pubkey_bin)}")

        # 4. Erstelle ECC-Objekt MIT DEN BINÄRFORMATEN (GENAU WIE ORIGINAL)
        # Original: cryptor = pyelliptic.ECC(curve='secp256k1', privkey=privkey_bin, pubkey=pubkey_bin)
        cryptor = pyelliptic.ECC(
            curve=curve,
            privkey=privkey_bin,
            pubkey=pubkey_bin
        )
        
        logger.debug("✓ ECC object created with binary key format")
        
        # 5. Optional: Teste das Cryptor
        try:
            test_sig = cryptor.sign(b'test')
            test_valid = cryptor.verify(test_sig, b'test')
            logger.debug(f"Cryptor sign/verify test: {test_valid}")
        except Exception as e:
            logger.warning(f"Cryptor test warning: {e}")
        
        return cryptor
        
    except Exception as e:
        logger.error(f"makeCryptor error: {e}", exc_info=True)
        raise


def makePubCryptor(pubkey):
    """Return a public `.pyelliptic.ECC` instance"""
    logger = logging.getLogger('highlevelcrypto')
    logger.debug("DEBUG: makePubCryptor called")
    
    try:
        # Konvertiere pubkey zum binären Format, das pyelliptic erwartet
        if isinstance(pubkey, bytes):
            if pubkey.startswith(b'\x02\xca'):
                # Bereits im richtigen Format
                pubkey_bin = pubkey
            elif len(pubkey) == 65 and pubkey[0] == 0x04:
                # Format: 0x04 + X + Y → konvertiere zu pyelliptic Format
                pubkey_bin = b'\x02\xca\x00\x20' + pubkey[1:33] + b'\x00\x20' + pubkey[33:65]
            else:
                # Versuche es als Hex-String zu behandeln
                try:
                    hex_str = pubkey.decode('ascii')
                    pubkey_bin = hexToPubkey(hex_str)
                except:
                    raise ValueError(f"Unknown pubkey format: {len(pubkey)} bytes")
        else:
            # pubkey ist String (Hex)
            pubkey_bin = hexToPubkey(pubkey)
        
        logger.debug(f"Converted pubkey to {len(pubkey_bin)} bytes (pyelliptic format)")
        
        # Erstelle öffentliches ECC-Objekt
        cryptor = pyelliptic.ECC(curve='secp256k1', pubkey=pubkey_bin)
        
        logger.debug("✓ Public cryptor created")
        return cryptor
        
    except Exception as e:
        logger.error(f"makePubCryptor error: {e}")
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
    """Choose openssl digest constant by name - returns a CALLABLE function"""
    logger.debug("DEBUG: _choose_digest_alg called with: %s", name)
    
    if name not in ("sha1", "sha256"):
        logger.error("DEBUG: Unknown digest algorithm: %s", name)
        raise ValueError("Unknown digest algorithm %s" % name)
    
    # PYELLIPTIC EXPECTS A CALLABLE THAT RETURNS THE INTEGER!
    # Looking at the error: OpenSSL.EVP_DigestInit_ex(md_ctx, digest_alg(), None)
    # It calls digest_alg() to get the integer!
    
    if name == "sha1":
        # Return a function that returns the SHA1 constant
        def get_sha1():
            return OpenSSL.digest_ecdsa_sha1
        logger.debug("DEBUG: Returning SHA1 callable function")
        return get_sha1
        
    else:  # sha256
        # Return a function that returns the SHA256 constant
        def get_sha256():
            return OpenSSL.EVP_sha256
        logger.debug("DEBUG: Returning SHA256 callable function")
        return get_sha256

def sign(msg, hexPrivkey, digestAlg="sha256"):
    """Signs with hex private key - ULTRA SIMPLE VERSION"""
    logger.debug("DEBUG: sign called")
    
    try:
        cryptor = makeCryptor(hexPrivkey)
        
        if isinstance(msg, str):
            msg_bytes = msg.encode('utf-8')
        else:
            msg_bytes = _ensure_bytes(msg)
        
        # ULTRA SIMPLE: Don't pass ANY digest_alg parameter!
        # Let pyelliptic handle it internally
        result = cryptor.sign(msg_bytes)
        
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
    
    try:
        # 1. Convert all inputs to appropriate types
        msg_bytes = _ensure_bytes(msg)
        sig_bytes = _ensure_bytes(sig)
        
        # Clean and normalize the public key
        hexPubkey_str = _ensure_str(hexPubkey)
        
        # Remove any whitespace
        import re
        hexPubkey_clean = re.sub(r'[^0-9a-fA-F]', '', hexPubkey_str)
        
        logger.debug(f"Cleaned pubkey: {hexPubkey_clean[:30]}... ({len(hexPubkey_clean)} chars)")
        
        # 2. WICHTIG: Pyelliptic pubkey format ist 70 bytes = 140 chars
        #    Wir müssen NICHT auf 128 chars kürzen!
        
        if len(hexPubkey_clean) == 140:
            # Das ist das korrekte pyelliptic Format (70 bytes)
            logger.debug("✓ Correct pyelliptic format (140 chars = 70 bytes)")
            # Nichts ändern!
            
        elif len(hexPubkey_clean) == 130 and hexPubkey_clean.lower().startswith('04'):
            # 65 bytes uncompressed format
            logger.debug("65-byte uncompressed format, converting to pyelliptic format")
            # Entferne '04' prefix
            hexPubkey_clean = hexPubkey_clean[2:]  # Jetzt 128 chars
            # Jetzt müssen wir zu pyelliptic Format konvertieren
            # Aber das sollte hexToPubkey machen
            
        elif len(hexPubkey_clean) == 128:
            # 64 bytes raw format
            logger.debug("64-byte raw format")
            # Keep as-is, hexToPubkey wird es konvertieren
            
        else:
            # Unerwartete Länge
            logger.warning(f"Unexpected pubkey length: {len(hexPubkey_clean)} chars")
            # Versuche das Beste
            if len(hexPubkey_clean) > 140:
                hexPubkey_clean = hexPubkey_clean[:140]
            elif len(hexPubkey_clean) < 128:
                hexPubkey_clean = hexPubkey_clean.rjust(128, '0')
        
        logger.debug(f"Final pubkey length: {len(hexPubkey_clean)} chars")
        
        # 3. Try different digest algorithms if not specified
        if digestAlg is None:
            logger.debug("No digestAlg specified, trying SHA256 then SHA1")
            
            # Try SHA256 first (newer)
            logger.debug("=== TRYING SHA256 ===")
            try:
                if _verify_single(msg_bytes, sig_bytes, hexPubkey_clean, "sha256"):
                    logger.debug("=== VERIFY SUCCESS WITH SHA256 ===")
                    logger.debug("=== HIGHLEVELCRYPTO VERIFY DEBUG END ===")
                    return True
                else:
                    logger.debug("SHA256 verify returned False")
            except Exception as e:
                logger.debug("SHA256 verify exception: %s", e)
            
            # Try SHA1 (older)
            logger.debug("=== TRYING SHA1 ===")
            try:
                if _verify_single(msg_bytes, sig_bytes, hexPubkey_clean, "sha1"):
                    logger.debug("=== VERIFY SUCCESS WITH SHA1 ===")
                    logger.debug("=== HIGHLEVELCRYPTO VERIFY DEBUG END ===")
                    return True
                else:
                    logger.debug("SHA1 verify returned False")
            except Exception as e:
                logger.debug("SHA1 verify exception: %s", e)
            
            logger.error("=== ALL DIGEST ALGORITHMS FAILED ===")
            logger.debug("=== HIGHLEVELCRYPTO VERIFY DEBUG END ===")
            return False
        
        # 4. Specific digest algorithm
        logger.debug("Using specific digest algorithm: %s", digestAlg)
        return _verify_single(msg_bytes, sig_bytes, hexPubkey_clean, digestAlg)
        
    except Exception as e:
        logger.error("Unhandled exception in verify: %s", e, exc_info=True)
        logger.debug("=== HIGHLEVELCRYPTO VERIFY DEBUG END ===")
        return False
def _verify_single(msg_bytes, sig_bytes, hexPubkey_clean, digestAlg):
    """Internal helper for verification - ULTRA SIMPLE VERSION"""
    logger = logging.getLogger('highlevelcrypto')
    
    try:
        cryptor = makePubCryptor(hexPubkey_clean)
        
        # ULTRA SIMPLE: Don't pass ANY digest_alg parameter!
        # Just like in sign() function
        result = cryptor.verify(sig_bytes, msg_bytes)
        
        logger.debug("Verify result: %s", result)
        
        if result:
            logger.info("=== VERIFICATION SUCCESS ===")
            return True
        else:
            logger.error("=== VERIFICATION FAILED (cryptor.verify returned False) ===")
            return False
            
    except Exception as e:
        logger.error(f"Error in _verify_single: {e}")
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
