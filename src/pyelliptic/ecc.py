"""
Asymmetric cryptography using elliptic curves
"""
# pylint: disable=protected-access, too-many-branches, too-many-locals
#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.

from hashlib import sha512
from struct import pack, unpack
from ctypes import c_char_p
from binascii import hexlify
from .cipher import Cipher
from .hash import equals, hmac_sha256
from .openssl import OpenSSL
import sys
import logging
# Optional: Wenn noch kein Logger konfiguriert ist
if not logging.getLogger('pyelliptic').handlers:
    logging.basicConfig(level=logging.DEBUG)
    
class ECC(object):
    """
    Asymmetric encryption with Elliptic Curve Cryptography (ECC)
    ECDH, ECDSA and ECIES

        >>> from binascii import hexlify
        >>> import pyelliptic

        >>> alice = pyelliptic.ECC() # default curve: sect283r1
        >>> bob = pyelliptic.ECC(curve='sect571r1')

        >>> ciphertext = alice.encrypt("Hello Bob", bob.get_pubkey())
        >>> print(bob.decrypt(ciphertext))

        >>> signature = bob.sign("Hello Alice")
        >>> # alice's job :
        >>> print(pyelliptic.ECC(
        >>>     pubkey=bob.get_pubkey()).verify(signature, "Hello Alice"))

        >>> # ERROR !!!
        >>> try:
        >>>     key = alice.get_ecdh_key(bob.get_pubkey())
        >>> except:
        >>>     print(
                    "For ECDH key agreement, the keys must be defined"
                    " on the same curve!")

        >>> alice = pyelliptic.ECC(curve='sect571r1')
        >>> print(hexlify(alice.get_ecdh_key(bob.get_pubkey())))
        >>> print(hexlify(bob.get_ecdh_key(alice.get_pubkey())))

    """

    def __init__(
            self,
            pubkey=None,
            privkey=None,
            pubkey_x=None,
            pubkey_y=None,
            raw_privkey=None,
            curve='sect283r1',
    ):  # pylint: disable=too-many-arguments
        """
        For a normal and high level use, specifie pubkey,
        privkey (if you need) and the curve
        """
        if isinstance(curve, str):
            self.curve = OpenSSL.get_curve(curve)
        else:
            self.curve = curve

        if pubkey_x is not None and pubkey_y is not None:
            self._set_keys(pubkey_x, pubkey_y, raw_privkey)
        elif pubkey is not None:
            curve, pubkey_x, pubkey_y, _ = ECC._decode_pubkey(pubkey)
            if privkey is not None:
                curve2, raw_privkey, _ = ECC._decode_privkey(privkey)
                if curve != curve2:
                    raise Exception("Bad ECC keys ...")
            self.curve = curve
            self._set_keys(pubkey_x, pubkey_y, raw_privkey)
        else:
            self.privkey, self.pubkey_x, self.pubkey_y = self._generate()

    def _set_keys(self, pubkey_x, pubkey_y, privkey):
        if self.raw_check_key(privkey, pubkey_x, pubkey_y) < 0:
            self.pubkey_x = None
            self.pubkey_y = None
            self.privkey = None
            raise Exception("Bad ECC keys ...")
        self.pubkey_x = pubkey_x
        self.pubkey_y = pubkey_y
        self.privkey = privkey

    @staticmethod
    def get_curves():
        """
        Static method, returns the list of all the curves available
        """
        return OpenSSL.curves.keys()

    def get_curve(self):
        """The name of currently used curve"""
        return OpenSSL.get_curve_by_id(self.curve)

    def get_curve_id(self):
        """Currently used curve"""
        return self.curve

    def get_pubkey(self):
        """
        High level function which returns :
        curve(2) + len_of_pubkeyX(2) + pubkeyX + len_of_pubkeyY + pubkeyY
        """
        ctx = OpenSSL.BN_CTX_new()
        n = OpenSSL.BN_new()
        group = OpenSSL.EC_GROUP_new_by_curve_name(self.curve)
        OpenSSL.EC_GROUP_get_order(group, n, ctx)
        key_len = OpenSSL.BN_num_bytes(n)
        pubkey_x = self.pubkey_x.rjust(key_len, b'\x00')
        pubkey_y = self.pubkey_y.rjust(key_len, b'\x00')
        return b''.join((
            pack('!H', self.curve),
            pack('!H', len(pubkey_x)),
            pubkey_x,
            pack('!H', len(pubkey_y)),
            pubkey_y,
        ))

    def get_privkey(self):
        """
        High level function which returns
        curve(2) + len_of_privkey(2) + privkey
        """
        return b''.join((
            pack('!H', self.curve),
            pack('!H', len(self.privkey)),
            self.privkey,
        ))

    @staticmethod
    def _decode_pubkey(pubkey):
        i = 0
        curve = unpack('!H', pubkey[i:i + 2])[0]
        i += 2
        tmplen = unpack('!H', pubkey[i:i + 2])[0]
        i += 2
        pubkey_x = pubkey[i:i + tmplen]
        i += tmplen
        tmplen = unpack('!H', pubkey[i:i + 2])[0]
        i += 2
        pubkey_y = pubkey[i:i + tmplen]
        i += tmplen
        return curve, pubkey_x, pubkey_y, i

    @staticmethod
    def _decode_privkey(privkey):
        i = 0
        curve = unpack('!H', privkey[i:i + 2])[0]
        i += 2
        tmplen = unpack('!H', privkey[i:i + 2])[0]
        i += 2
        privkey = privkey[i:i + tmplen]
        i += tmplen
        return curve, privkey, i

    def _generate(self):
        try:
            pub_key_x = OpenSSL.BN_new()
            pub_key_y = OpenSSL.BN_new()

            key = OpenSSL.EC_KEY_new_by_curve_name(self.curve)
            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")
            if OpenSSL.EC_KEY_generate_key(key) == 0:
                raise Exception("[OpenSSL] EC_KEY_generate_key FAIL ...")
            if OpenSSL.EC_KEY_check_key(key) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")
            priv_key = OpenSSL.EC_KEY_get0_private_key(key)

            group = OpenSSL.EC_KEY_get0_group(key)
            pub_key = OpenSSL.EC_KEY_get0_public_key(key)

            if OpenSSL.EC_POINT_get_affine_coordinates_GFp(
                    group, pub_key, pub_key_x, pub_key_y, 0) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_get_affine_coordinates_GFp FAIL ...")

            privkey = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(priv_key))
            pubkeyx = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(pub_key_x))
            pubkeyy = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(pub_key_y))
            OpenSSL.BN_bn2bin(priv_key, privkey)
            privkey = privkey.raw
            OpenSSL.BN_bn2bin(pub_key_x, pubkeyx)
            pubkeyx = pubkeyx.raw
            OpenSSL.BN_bn2bin(pub_key_y, pubkeyy)
            pubkeyy = pubkeyy.raw
            self.raw_check_key(privkey, pubkeyx, pubkeyy)

            return privkey, pubkeyx, pubkeyy

        finally:
            OpenSSL.EC_KEY_free(key)
            OpenSSL.BN_free(pub_key_x)
            OpenSSL.BN_free(pub_key_y)

    def get_ecdh_key(self, pubkey):
        """
        High level function. Compute public key with the local private key
        and returns a 512bits shared key.
        """
        curve, pubkey_x, pubkey_y, _ = ECC._decode_pubkey(pubkey)
        if curve != self.curve:
            raise Exception("ECC keys must be from the same curve !")
        return sha512(self.raw_get_ecdh_key(pubkey_x, pubkey_y)).digest()

    def raw_get_ecdh_key(self, pubkey_x, pubkey_y):
        """ECDH key as binary data"""
        import logging
        logger = logging.getLogger('pyelliptic')
        
        # Initialisiere Variablen als None
        own_key = None
        other_key = None
        other_pub_key_x = None
        other_pub_key_y = None
        other_pub_key = None
        own_priv_key = None
        
        try:
            logger.debug(f"=== RAW_GET_ECDH_KEY DEBUG START ===")
            logger.debug(f"Self curve ID: {self.curve}, name: {self.get_curve()}")
            logger.debug(f"Self privkey exists: {self.privkey is not None}")
            if self.privkey:
                logger.debug(f"Self privkey length: {len(self.privkey)} bytes")
                logger.debug(f"Self privkey first 16: {hexlify(self.privkey[:16]).decode('ascii')}...")
            
            logger.debug(f"Input pubkey_x type: {type(pubkey_x)}, length: {len(pubkey_x) if pubkey_x else 0}")
            logger.debug(f"Input pubkey_y type: {type(pubkey_y)}, length: {len(pubkey_y) if pubkey_y else 0}")
            
            if pubkey_x:
                logger.debug(f"pubkey_x first 16: {hexlify(pubkey_x[:16]).decode('ascii')}...")
            if pubkey_y:
                logger.debug(f"pubkey_y first 16: {hexlify(pubkey_y[:16]).decode('ascii')}...")
            
            ecdh_keybuffer = OpenSSL.malloc(0, 32)
            logger.debug(f"Allocated ecdh_keybuffer: 32 bytes")

            # Other key (public key)
            logger.debug(f"\n--- Creating other_key (public key) ---")
            other_key = OpenSSL.EC_KEY_new_by_curve_name(self.curve)
            if other_key == 0:
                logger.error("EC_KEY_new_by_curve_name failed for other_key")
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")
            logger.debug(f"other_key created: {other_key}")

            # PYTHON 3 FIX: Ensure bytes
            if isinstance(pubkey_x, str):
                logger.debug(f"Converting pubkey_x from str to bytes")
                pubkey_x = pubkey_x.encode('latin-1')
            if isinstance(pubkey_y, str):
                logger.debug(f"Converting pubkey_y from str to bytes")
                pubkey_y = pubkey_y.encode('latin-1')
            
            logger.debug(f"After conversion - pubkey_x type: {type(pubkey_x)}, length: {len(pubkey_x)}")
            logger.debug(f"After conversion - pubkey_y type: {type(pubkey_y)}, length: {len(pubkey_y)}")
                
            # Convert pubkey components to BNs
            logger.debug(f"\n--- Converting pubkey to BNs ---")
            other_pub_key_x = OpenSSL.BN_bin2bn(c_char_p(bytes(pubkey_x)), len(pubkey_x), None)
            other_pub_key_y = OpenSSL.BN_bin2bn(c_char_p(bytes(pubkey_y)), len(pubkey_y), None)
            logger.debug(f"other_pub_key_x created: {other_pub_key_x}")
            logger.debug(f"other_pub_key_y created: {other_pub_key_y}")

            # Create public key point
            other_group = OpenSSL.EC_KEY_get0_group(other_key)
            other_pub_key = OpenSSL.EC_POINT_new(other_group)
            logger.debug(f"other_pub_key (EC_POINT) created: {other_pub_key}")

            logger.debug(f"\n--- Setting affine coordinates ---")
            if OpenSSL.EC_POINT_set_affine_coordinates_GFp(other_group,
                                                           other_pub_key,
                                                           other_pub_key_x,
                                                           other_pub_key_y,
                                                           0) == 0:
                logger.error("EC_POINT_set_affine_coordinates_GFp failed")
                raise Exception(
                    "[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ...")
            logger.debug("✓ Affine coordinates set successfully")

            logger.debug(f"\n--- Setting public key ---")
            if OpenSSL.EC_KEY_set_public_key(other_key, other_pub_key) == 0:
                logger.error("EC_KEY_set_public_key failed")
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ...")
            logger.debug("✓ Public key set successfully")

            logger.debug(f"\n--- Checking other key ---")
            if OpenSSL.EC_KEY_check_key(other_key) == 0:
                logger.error("EC_KEY_check_key failed for other_key")
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")
            logger.debug("✓ Other key checked successfully")

            # Own key (private key)
            logger.debug(f"\n--- Creating own_key (private key) ---")
            own_key = OpenSSL.EC_KEY_new_by_curve_name(self.curve)
            if own_key == 0:
                logger.error("EC_KEY_new_by_curve_name failed for own_key")
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")
            logger.debug(f"own_key created: {own_key}")

            # Convert private key to BN
            logger.debug(f"\n--- Converting private key to BN ---")
            if isinstance(self.privkey, str):
                logger.debug(f"Converting privkey from str to bytes")
                privkey_bytes = self.privkey.encode('latin-1')
            else:
                privkey_bytes = self.privkey
                
            logger.debug(f"privkey_bytes type: {type(privkey_bytes)}, length: {len(privkey_bytes)}")
            own_priv_key = OpenSSL.BN_bin2bn(privkey_bytes, len(privkey_bytes), None)
            logger.debug(f"own_priv_key created: {own_priv_key}")

            logger.debug(f"\n--- Setting private key ---")
            if OpenSSL.EC_KEY_set_private_key(own_key, own_priv_key) == 0:
                logger.error("EC_KEY_set_private_key failed")
                raise Exception("[OpenSSL] EC_KEY_set_private_key FAIL ...")
            logger.debug("✓ Private key set successfully")

            # Set ECDH method
            logger.debug(f"\n--- Setting ECDH method ---")
            if OpenSSL._hexversion > 0x10100000 and not OpenSSL._libreSSL:
                logger.debug(f"Using EC_KEY_set_method (OpenSSL > 1.1.0)")
                OpenSSL.EC_KEY_set_method(own_key, OpenSSL.EC_KEY_OpenSSL())
            else:
                logger.debug(f"Using ECDH_set_method (OpenSSL <= 1.1.0 or LibreSSL)")
                OpenSSL.ECDH_set_method(own_key, OpenSSL.ECDH_OpenSSL())

            # Compute ECDH key
            logger.debug(f"\n--- Computing ECDH key ---")
            ecdh_keylen = OpenSSL.ECDH_compute_key(
                ecdh_keybuffer, 32, other_pub_key, own_key, 0)
            logger.debug(f"ECDH_compute_key returned: {ecdh_keylen}")

            if ecdh_keylen != 32:
                logger.error(f"ECDH keylen is {ecdh_keylen}, expected 32")
                raise Exception("[OpenSSL] ECDH keylen FAIL ...")
            
            result = ecdh_keybuffer.raw
            logger.debug(f"ECDH key computed: {len(result)} bytes")
            logger.debug(f"ECDH key first 16: {hexlify(result[:16]).decode('ascii')}...")
            logger.debug("=== RAW_GET_ECDH_KEY DEBUG END ===")
            
            return result

        except Exception as e:
            logger.error(f"ECDH computation failed: {e}", exc_info=True)
            # Re-raise die Exception
            raise Exception(f"[OpenSSL] ECDH key computation failed: {e}")
            
        finally:
            # Cleanup - nur wenn Variablen definiert sind
            logger.debug(f"\n--- Cleaning up ---")
            if other_key is not None:
                OpenSSL.EC_KEY_free(other_key)
                logger.debug(f"Freed other_key")
            if other_pub_key_x is not None:
                OpenSSL.BN_free(other_pub_key_x)
                logger.debug(f"Freed other_pub_key_x")
            if other_pub_key_y is not None:
                OpenSSL.BN_free(other_pub_key_y)
                logger.debug(f"Freed other_pub_key_y")
            if other_pub_key is not None:
                OpenSSL.EC_POINT_free(other_pub_key)
                logger.debug(f"Freed other_pub_key")
            if own_key is not None:
                OpenSSL.EC_KEY_free(own_key)
                logger.debug(f"Freed own_key")
            if own_priv_key is not None:
                OpenSSL.BN_free(own_priv_key)
                logger.debug(f"Freed own_priv_key")

    def check_key(self, privkey, pubkey):
        """
        Check the public key and the private key.
        The private key is optional (replace by None).
        """
        curve, pubkey_x, pubkey_y, _ = ECC._decode_pubkey(pubkey)
        if privkey is None:
            raw_privkey = None
            curve2 = curve
        else:
            curve2, raw_privkey, _ = ECC._decode_privkey(privkey)
        if curve != curve2:
            raise Exception("Bad public and private key")
        return self.raw_check_key(raw_privkey, pubkey_x, pubkey_y, curve)

    def raw_check_key(self, privkey, pubkey_x, pubkey_y, curve=None):
        """Check key validity, key is supplied as binary data"""
        if curve is None:
            curve = self.curve
        elif isinstance(curve, str):
            curve = OpenSSL.get_curve(curve)
        
        try:
            key = OpenSSL.EC_KEY_new_by_curve_name(curve)
            if key == 0:
                return -1  # Failure
                
            if privkey is not None:
                # PYTHON 3 FIX: Ensure bytes
                if isinstance(privkey, str):
                    privkey = privkey.encode('latin-1')
                priv_key = OpenSSL.BN_bin2bn(privkey, len(privkey), None)
            
            # PYTHON 3 FIX: Ensure bytes for pubkey components
            if isinstance(pubkey_x, str):
                pubkey_x = pubkey_x.encode('latin-1')
            if isinstance(pubkey_y, str):
                pubkey_y = pubkey_y.encode('latin-1')
                
            pub_key_x = OpenSSL.BN_bin2bn(pubkey_x, len(pubkey_x), None)
            pub_key_y = OpenSSL.BN_bin2bn(pubkey_y, len(pubkey_y), None)

            if privkey is not None:
                if OpenSSL.EC_KEY_set_private_key(key, priv_key) == 0:
                    return -1  # Failure

            group = OpenSSL.EC_KEY_get0_group(key)
            pub_key = OpenSSL.EC_POINT_new(group)

            if OpenSSL.EC_POINT_set_affine_coordinates_GFp(group, pub_key,
                                                           pub_key_x,
                                                           pub_key_y,
                                                           0) == 0:
                return -1  # Failure
                
            if OpenSSL.EC_KEY_set_public_key(key, pub_key) == 0:
                return -1  # Failure
                
            if OpenSSL.EC_KEY_check_key(key) == 0:
                return -1  # Failure
                
            return 0  # Success

        finally:
            # Cleanup - but only if variables exist
            if 'key' in locals():
                OpenSSL.EC_KEY_free(key)
            if 'pub_key_x' in locals():
                OpenSSL.BN_free(pub_key_x)
            if 'pub_key_y' in locals():
                OpenSSL.BN_free(pub_key_y)
            if 'pub_key' in locals():
                OpenSSL.EC_POINT_free(pub_key)
            if privkey is not None and 'priv_key' in locals():
                OpenSSL.BN_free(priv_key)

    def sign(self, inputb, digest_alg=OpenSSL.digest_ecdsa_sha1):
        """
        Sign the input with ECDSA method and returns the signature
        """
        try:
            size = len(inputb)
            buff = OpenSSL.malloc(inputb, size)
            digest = OpenSSL.malloc(0, 64)
            if OpenSSL._hexversion > 0x10100000 and not OpenSSL._libreSSL:
                md_ctx = OpenSSL.EVP_MD_CTX_new()
            else:
                md_ctx = OpenSSL.EVP_MD_CTX_create()
            dgst_len = OpenSSL.pointer(OpenSSL.c_int(0))
            siglen = OpenSSL.pointer(OpenSSL.c_int(0))
            sig = OpenSSL.malloc(0, 151)

            key = OpenSSL.EC_KEY_new_by_curve_name(self.curve)
            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")

            priv_key = OpenSSL.BN_bin2bn(self.privkey, len(self.privkey), None)
            pub_key_x = OpenSSL.BN_bin2bn(self.pubkey_x, len(self.pubkey_x),
                                          None)
            pub_key_y = OpenSSL.BN_bin2bn(self.pubkey_y, len(self.pubkey_y),
                                          None)

            if OpenSSL.EC_KEY_set_private_key(key, priv_key) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_private_key FAIL ...")

            group = OpenSSL.EC_KEY_get0_group(key)
            pub_key = OpenSSL.EC_POINT_new(group)

            if OpenSSL.EC_POINT_set_affine_coordinates_GFp(group, pub_key,
                                                           pub_key_x,
                                                           pub_key_y,
                                                           0) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ...")
            if OpenSSL.EC_KEY_set_public_key(key, pub_key) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ...")
            if OpenSSL.EC_KEY_check_key(key) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")

            if OpenSSL._hexversion > 0x10100000 and not OpenSSL._libreSSL:
                OpenSSL.EVP_MD_CTX_new(md_ctx)
            else:
                OpenSSL.EVP_MD_CTX_init(md_ctx)
            OpenSSL.EVP_DigestInit_ex(md_ctx, digest_alg(), None)

            if OpenSSL.EVP_DigestUpdate(md_ctx, buff, size) == 0:
                raise Exception("[OpenSSL] EVP_DigestUpdate FAIL ...")
            OpenSSL.EVP_DigestFinal_ex(md_ctx, digest, dgst_len)
            OpenSSL.ECDSA_sign(0, digest, dgst_len.contents, sig, siglen, key)
            if OpenSSL.ECDSA_verify(
                0, digest, dgst_len.contents, sig, siglen.contents, key
            ) != 1:
                raise Exception("[OpenSSL] ECDSA_verify FAIL ...")

            return sig.raw[:siglen.contents.value]

        finally:
            OpenSSL.EC_KEY_free(key)
            OpenSSL.BN_free(pub_key_x)
            OpenSSL.BN_free(pub_key_y)
            OpenSSL.BN_free(priv_key)
            OpenSSL.EC_POINT_free(pub_key)
            if OpenSSL._hexversion > 0x10100000 and not OpenSSL._libreSSL:
                OpenSSL.EVP_MD_CTX_free(md_ctx)
            else:
                OpenSSL.EVP_MD_CTX_destroy(md_ctx)

    def verify(self, sig, inputb, digest_alg=OpenSSL.digest_ecdsa_sha1):
        """
        Verify the signature with the input and the local public key.
        Returns a boolean.
        """
        try:
            bsig = OpenSSL.malloc(sig, len(sig))
            binputb = OpenSSL.malloc(inputb, len(inputb))
            digest = OpenSSL.malloc(0, 64)
            dgst_len = OpenSSL.pointer(OpenSSL.c_int(0))
            if OpenSSL._hexversion > 0x10100000 and not OpenSSL._libreSSL:
                md_ctx = OpenSSL.EVP_MD_CTX_new()
            else:
                md_ctx = OpenSSL.EVP_MD_CTX_create()
            key = OpenSSL.EC_KEY_new_by_curve_name(self.curve)

            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ...")

            pub_key_x = OpenSSL.BN_bin2bn(self.pubkey_x, len(self.pubkey_x),
                                          None)
            pub_key_y = OpenSSL.BN_bin2bn(self.pubkey_y, len(self.pubkey_y),
                                          None)
            group = OpenSSL.EC_KEY_get0_group(key)
            pub_key = OpenSSL.EC_POINT_new(group)

            if OpenSSL.EC_POINT_set_affine_coordinates_GFp(group, pub_key,
                                                           pub_key_x,
                                                           pub_key_y,
                                                           0) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ...")
            if OpenSSL.EC_KEY_set_public_key(key, pub_key) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ...")
            if OpenSSL.EC_KEY_check_key(key) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ...")
            if OpenSSL._hexversion > 0x10100000 and not OpenSSL._libreSSL:
                OpenSSL.EVP_MD_CTX_new(md_ctx)
            else:
                OpenSSL.EVP_MD_CTX_init(md_ctx)
            OpenSSL.EVP_DigestInit_ex(md_ctx, digest_alg(), None)
            if OpenSSL.EVP_DigestUpdate(md_ctx, binputb, len(inputb)) == 0:
                raise Exception("[OpenSSL] EVP_DigestUpdate FAIL ...")

            OpenSSL.EVP_DigestFinal_ex(md_ctx, digest, dgst_len)
            ret = OpenSSL.ECDSA_verify(
                0, digest, dgst_len.contents, bsig, len(sig), key)

            if ret == -1:
                # Fail to Check
                return False
            if ret == 0:
                # Bad signature !
                return False
            # Good
            return True

        finally:
            OpenSSL.EC_KEY_free(key)
            OpenSSL.BN_free(pub_key_x)
            OpenSSL.BN_free(pub_key_y)
            OpenSSL.EC_POINT_free(pub_key)
            if OpenSSL._hexversion > 0x10100000 and not OpenSSL._libreSSL:
                OpenSSL.EVP_MD_CTX_free(md_ctx)
            else:
                OpenSSL.EVP_MD_CTX_destroy(md_ctx)
    @staticmethod
    def encrypt(data, pubkey, ephemcurve=None, ciphername='aes-256-cbc'):
        """
        Encrypt data with ECIES method using the public key of the recipient.
        """
        import logging
        logger = logging.getLogger('pyelliptic')
        
        logger.debug(f"=== ECC.ENCRYPT DEBUG START ===")
        logger.debug(f"Python version: {sys.version}")
        logger.debug(f"Input data type: {type(data)}, length: {len(data)}")
        
        # Daten als Bytes sicherstellen
        if isinstance(data, str):
            original_data = data
            data = data.encode('utf-8')
            logger.debug(f"Converted string to bytes: '{original_data[:50]}...' -> {len(data)} bytes")
        elif isinstance(data, bytearray):
            data = bytes(data)
            logger.debug(f"Converted bytearray to bytes")
        
        logger.debug(f"Data to encrypt: {len(data)} bytes, hex preview: {hexlify(data[:50]).decode('ascii')}...")
        
        curve, pubkey_x, pubkey_y, _ = ECC._decode_pubkey(pubkey)
        logger.debug(f"Recipient pubkey:")
        logger.debug(f"  Curve: {curve} ({OpenSSL.get_curve_by_id(curve)})")
        logger.debug(f"  Pubkey X: {len(pubkey_x)} bytes")
        logger.debug(f"  Pubkey Y: {len(pubkey_y)} bytes")
        
        result = ECC.raw_encrypt(data, pubkey_x, pubkey_y, curve=curve,
                               ephemcurve=ephemcurve, ciphername=ciphername)
        
        logger.debug(f"Encryption result: {len(result)} bytes")
        logger.debug(f"Result structure preview: IV({OpenSSL.get_cipher(ciphername).get_blocksize()}) + EphemPubkey + Ciphertext + MAC(32)")
        logger.debug(f"Result first 100 bytes hex: {hexlify(result[:100]).decode('ascii')}")
        logger.debug("=== ECC.ENCRYPT DEBUG END ===")
        
        return result
    @staticmethod
    def raw_encrypt(
            data,
            pubkey_x,
            pubkey_y,
            curve='sect283r1',
            ephemcurve=None,
            ciphername='aes-256-cbc',
    ):  # pylint: disable=too-many-arguments
        """ECDH encryption, keys supplied in binary data format"""
        import logging
        logger = logging.getLogger('pyelliptic')
        
        logger.debug(f"=== ECC.RAW_ENCRYPT DEBUG START ===")
        logger.debug(f"Input data length: {len(data)} bytes")
        logger.debug(f"Pubkey X length: {len(pubkey_x)} bytes")
        logger.debug(f"Pubkey Y length: {len(pubkey_y)} bytes")
        logger.debug(f"Curve: {curve}")
        logger.debug(f"Ephemcurve: {ephemcurve}")
        logger.debug(f"Ciphername: {ciphername}")
        
        # Parameter sicherstellen
        if isinstance(pubkey_x, str):
            pubkey_x = pubkey_x.encode('latin-1')
            logger.debug(f"Converted pubkey_x from str to bytes")
        if isinstance(pubkey_y, str):
            pubkey_y = pubkey_y.encode('latin-1')
            logger.debug(f"Converted pubkey_y from str to bytes")
        
        if ephemcurve is None:
            ephemcurve = curve
        
        # Ephemeraler Schlüssel
        logger.debug(f"\n=== GENERATING EPHEMERAL KEY ===")
        ephem = ECC(curve=ephemcurve)
        logger.debug(f"Ephemeral curve: {ephem.get_curve()}")
        logger.debug(f"Ephemeral pubkey length: {len(ephem.get_pubkey())} bytes")
        
        # ECDH Schlüssel
        logger.debug(f"\n=== COMPUTING ECDH KEY ===")
        try:
            raw_ecdh = ephem.raw_get_ecdh_key(pubkey_x, pubkey_y)
            logger.debug(f"Raw ECDH key: {len(raw_ecdh)} bytes, hex={hexlify(raw_ecdh[:32]).decode('ascii')}...")
        except Exception as e:
            logger.error(f"ECDH computation failed: {e}")
            raise
        
        key = sha512(raw_ecdh).digest()
        logger.debug(f"SHA512 of ECDH key: {len(key)} bytes")
        
        key_e, key_m = key[:32], key[32:]
        logger.debug(f"Encryption key (key_e): {len(key_e)} bytes")
        logger.debug(f"MAC key (key_m): {len(key_m)} bytes")
        
        # IV generieren
        logger.debug(f"\n=== GENERATING IV ===")
        _iv = Cipher.gen_IV(ciphername)
        logger.debug(f"IV: length={len(_iv)}, hex={hexlify(_iv).decode('ascii')}")
        
        # Verschlüsseln
        logger.debug(f"\n=== ENCRYPTING DATA ===")
        ctx = Cipher(key_e, _iv, 1, ciphername)
        ciphertext = ctx.ciphering(data)
        logger.debug(f"Ciphertext length: {len(ciphertext)} bytes")
        
        # MAC berechnen
        logger.debug(f"\n=== COMPUTING MAC ===")
        pubkey = ephem.get_pubkey()
        ciphertext_with_header = _iv + pubkey + ciphertext
        logger.debug(f"Data for MAC: IV({len(_iv)}) + Pubkey({len(pubkey)}) + Ciphertext({len(ciphertext)})")
        
        mac = hmac_sha256(key_m, ciphertext_with_header)
        logger.debug(f"MAC: length={len(mac)}, hex={hexlify(mac).decode('ascii')}")
        
        # Ergebnis zusammenbauen
        result = ciphertext_with_header + mac
        logger.debug(f"\n=== FINAL RESULT ===")
        logger.debug(f"Total length: {len(result)} bytes")
        logger.debug(f"Structure: IV({len(_iv)}) + EphemPubkey({len(pubkey)}) + Ciphertext({len(ciphertext)}) + MAC({len(mac)})")
        logger.debug(f"First 50 bytes hex: {hexlify(result[:50]).decode('ascii')}...")
        
        logger.debug("=== ECC.RAW_ENCRYPT DEBUG END ===")
        return result

    def decrypt(self, data, ciphername='aes-256-cbc'):
        """
        Decrypt data with ECIES method using the local private key
        """
        import logging
        logger = logging.getLogger('pyelliptic')
        
        try:
            logger.debug(f"=== ECC.DECRYPT DEBUG START ===")
            logger.debug(f"Python version: {sys.version}")
            logger.debug(f"Total input data length: {len(data)} bytes")
            logger.debug(f"Data type: {type(data)}")
            logger.debug(f"Ciphername: {ciphername}")
            
            # Daten als Bytes sicherstellen
            if isinstance(data, str):
                data = data.encode('latin-1')
                logger.debug(f"Converted string to bytes, new length: {len(data)}")
            elif isinstance(data, bytearray):
                data = bytes(data)
                logger.debug(f"Converted bytearray to bytes")
            
            blocksize = OpenSSL.get_cipher(ciphername).get_blocksize()
            logger.debug(f"Blocksize for {ciphername}: {blocksize}")
            
            if len(data) < blocksize:
                logger.error(f"Data too short ({len(data)} bytes) for IV ({blocksize} bytes)")
                raise RuntimeError("Data too short for IV")
            
            _iv = data[:blocksize]
            logger.debug(f"IV: length={len(_iv)}, hex={hexlify(_iv).decode('ascii')}")
            
            i = blocksize
            logger.debug(f"Position after IV: {i}")
            
            # Pubkey dekodieren
            try:
                curve, pubkey_x, pubkey_y, _i2 = ECC._decode_pubkey(data[i:])
                logger.debug(f"Decoded ephemeral pubkey:")
                logger.debug(f"  Curve ID: {curve} ({OpenSSL.get_curve_by_id(curve)})")
                logger.debug(f"  Pubkey X: {len(pubkey_x)} bytes, hex={hexlify(pubkey_x[:16]).decode('ascii')}...")
                logger.debug(f"  Pubkey Y: {len(pubkey_y)} bytes, hex={hexlify(pubkey_y[:16]).decode('ascii')}...")
                logger.debug(f"  Pubkey total bytes consumed: {_i2}")
            except Exception as e:
                logger.error(f"Failed to decode pubkey: {e}")
                logger.debug(f"Data at position {i} (first 100 bytes): {hexlify(data[i:i+100]).decode('ascii')}")
                raise
            
            i += _i2
            logger.debug(f"Position after pubkey: {i}")
            
            ciphertext = data[i:len(data) - 32]
            logger.debug(f"Ciphertext: length={len(ciphertext)} bytes")
            
            i += len(ciphertext)
            mac = data[i:]
            logger.debug(f"MAC: length={len(mac)}, hex={hexlify(mac).decode('ascii')}")
            
            logger.debug(f"Data structure: IV({blocksize}) + Pubkey({_i2}) + Ciphertext({len(ciphertext)}) + MAC({len(mac)})")
            
            # ECDH Schlüssel berechnen
            logger.debug(f"\n=== ECDH KEY COMPUTATION ===")
            logger.debug(f"Computing ECDH key with ephemeral pubkey...")
            logger.debug(f"Our curve: {self.get_curve()}")
            logger.debug(f"Ephemeral curve: {OpenSSL.get_curve_by_id(curve)}")
            
            try:
                ecdh_key = self.raw_get_ecdh_key(pubkey_x, pubkey_y)
                logger.debug(f"Raw ECDH key: {len(ecdh_key)} bytes, hex={hexlify(ecdh_key[:32]).decode('ascii')}...")
            except Exception as e:
                logger.error(f"Failed to compute ECDH key: {e}")
                raise
            
            key = sha512(ecdh_key).digest()
            logger.debug(f"SHA512 of ECDH key: {len(key)} bytes")
            
            key_e, key_m = key[:32], key[32:]
            logger.debug(f"Encryption key (key_e): {len(key_e)} bytes, first 16={hexlify(key_e[:16]).decode('ascii')}...")
            logger.debug(f"MAC key (key_m): {len(key_m)} bytes, first 16={hexlify(key_m[:16]).decode('ascii')}...")
            
            # MAC überprüfen
            logger.debug(f"\n=== HMAC VERIFICATION ===")
            data_for_mac = data[:len(data) - 32]
            logger.debug(f"Data for MAC: length={len(data_for_mac)} bytes")
            
            computed_mac = hmac_sha256(key_m, data_for_mac)
            logger.debug(f"Computed MAC: length={len(computed_mac)}, hex={hexlify(computed_mac).decode('ascii')}")
            logger.debug(f"Received MAC: length={len(mac)}, hex={hexlify(mac).decode('ascii')}")
            
            if not equals(computed_mac, mac):
                logger.error("HMAC VERIFICATION FAILED!")
                logger.error(f"Computed: {hexlify(computed_mac).decode('ascii')}")
                logger.error(f"Received: {hexlify(mac).decode('ascii')}")
                logger.error(f"Data for MAC (first 100): {hexlify(data_for_mac[:100]).decode('ascii')}")
                raise RuntimeError("Fail to verify data")
            
            logger.debug("✓ HMAC verification successful")
            
            # Entschlüsseln
            logger.debug(f"\n=== DECRYPTION ===")
            logger.debug(f"IV: {hexlify(_iv).decode('ascii')}")
            logger.debug(f"Key_e: {hexlify(key_e[:16]).decode('ascii')}...")
            logger.debug(f"Ciphertext length: {len(ciphertext)}")
            
            ctx = Cipher(key_e, _iv, 0, ciphername)
            decrypted = ctx.ciphering(ciphertext)
            
            logger.debug(f"Decrypted: length={len(decrypted)} bytes")
            logger.debug(f"Decrypted (first 100 bytes hex): {hexlify(decrypted[:100]).decode('ascii')}")
            try:
                logger.debug(f"Decrypted as UTF-8: {decrypted[:100].decode('utf-8', errors='replace')}")
            except:
                logger.debug(f"Could not decode as UTF-8 (binary data)")
            
            logger.debug("=== ECC.DECRYPT DEBUG END ===")
            return decrypted
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}", exc_info=True)
            raise
