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
from binascii import hexlify

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
    logger.debug("DEBUG: hexToPubkey called")
    try:
        pubkey_raw = a.changebase(pubkey[2:], 16, 256, minlen=64)
        pubkey_bin = b'\x02\xca\x00 ' + pubkey_raw[:32] + b'\x00 ' + pubkey_raw[32:]
        logger.debug("DEBUG: Converted hex pubkey to binary")
        return pubkey_bin
    except Exception as e:
        logger.error("DEBUG: Error in hexToPubkey: %s", str(e))
        raise


def privToPub(privkey):
    """Converts hex private key into hex public key"""
    logger.debug("DEBUG: privToPub called")
    try:
        private_key = a.changebase(privkey, 16, 256, minlen=32)
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
        private_key = a.changebase(privkey, 16, 256, minlen=32)
        public_key = pointMult(private_key)
        cryptor = pyelliptic.ECC(
            pubkey_x=public_key[1:-32], pubkey_y=public_key[-32:],
            raw_privkey=private_key, curve=curve)
        logger.debug("DEBUG: Created cryptor successfully")
        return cryptor
    except Exception as e:
        logger.error("DEBUG: Error in makeCryptor: %s", str(e))
        raise


def makePubCryptor(pubkey):
    """Return a public `.pyelliptic.ECC` instance"""
    logger.debug("DEBUG: makePubCryptor called")
    try:
        pubkey_bin = hexToPubkey(pubkey)
        cryptor = pyelliptic.ECC(curve='secp256k1', pubkey=pubkey_bin)
        logger.debug("DEBUG: Created public cryptor successfully")
        return cryptor
    except Exception as e:
        logger.error("DEBUG: Error in makePubCryptor: %s", str(e))
        raise


def encrypt(msg, hexPubkey):
    """Encrypts message with hex public key"""
    logger.debug("DEBUG: encrypt called")
    try:
        result = pyelliptic.ECC(curve='secp256k1').encrypt(
            msg, hexToPubkey(hexPubkey))
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
        result = cryptor.sign(msg, digest_alg=_choose_digest_alg(digestAlg))
        logger.debug("DEBUG: Message signed successfully")
        return result
    except Exception as e:
        logger.error("DEBUG: Error in sign: %s", str(e))
        raise


def verify(msg, sig, hexPubkey, digestAlg=None):
    """Verifies with hex public key"""
    logger.debug("DEBUG: verify called with digestAlg: %s", digestAlg)
    try:
        if digestAlg is None:
            logger.debug("DEBUG: Trying SHA1 verification first")
            if verify(msg, sig, hexPubkey, "sha1"):
                logger.debug("DEBUG: SHA1 verification succeeded")
                return True
            logger.debug("DEBUG: SHA1 verification failed, trying SHA256")
            return verify(msg, sig, hexPubkey, "sha256")

        cryptor = makePubCryptor(hexPubkey)
        result = cryptor.verify(sig, msg, digest_alg=_choose_digest_alg(digestAlg))
        logger.debug("DEBUG: Verification result: %s", result)
        return result
    except:
        logger.debug("DEBUG: Verification failed")
        return False
