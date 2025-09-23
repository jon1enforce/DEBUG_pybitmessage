#  Copyright (C) 2011 Yann GUIBET <yannguibet@gmail.com>
#  See LICENSE for details.
#
#  Software slightly changed by Jonathan Warren <bitmessage at-symbol jonwarren.org>
"""
This module loads openssl libs with ctypes and incapsulates
needed openssl functionality in class _OpenSSL.
"""
import ctypes
import sys
import six

# pylint: disable=protected-access

OpenSSL = None


class CipherName(object):
    """Class returns cipher name, pointer and blocksize"""

    def __init__(self, name, pointer, blocksize):
        self._name = name
        self._pointer = pointer
        self._blocksize = blocksize

    def __str__(self):
        return "Cipher : " + self._name + \
               " | Blocksize : " + str(self._blocksize) + \
               " | Function pointer : " + str(self._pointer)

    def get_pointer(self):
        """This method returns cipher pointer"""
        return self._pointer()

    def get_name(self):
        """This method returns cipher name"""
        return self._name

    def get_blocksize(self):
        """This method returns cipher blocksize"""
        return self._blocksize


def get_version(library):
    """This function return version, hexversion and cflages"""
    version = None
    hexversion = None
    cflags = None
    try:
        # OpenSSL 1.1
        OPENSSL_VERSION = 0
        OPENSSL_CFLAGS = 1
        library.OpenSSL_version.argtypes = [ctypes.c_int]
        library.OpenSSL_version.restype = ctypes.c_char_p
        version = library.OpenSSL_version(OPENSSL_VERSION)
        cflags = library.OpenSSL_version(OPENSSL_CFLAGS)
        library.OpenSSL_version_num.restype = ctypes.c_long
        hexversion = library.OpenSSL_version_num()
    except AttributeError:
        try:
            # OpenSSL 1.0
            SSLEAY_VERSION = 0
            SSLEAY_CFLAGS = 2
            library.SSLeay.restype = ctypes.c_long
            library.SSLeay_version.restype = ctypes.c_char_p
            library.SSLeay_version.argtypes = [ctypes.c_int]
            version = library.SSLeay_version(SSLEAY_VERSION)
            cflags = library.SSLeay_version(SSLEAY_CFLAGS)
            hexversion = library.SSLeay()
        except AttributeError:
            # raise NotImplementedError('Cannot determine version of this OpenSSL library.')
            pass
    return (version, hexversion, cflags)


class BIGNUM(ctypes.Structure):  # pylint: disable=too-few-public-methods
    """OpenSSL's BIGNUM struct"""
    _fields_ = [
        ('d', ctypes.POINTER(ctypes.c_ulong)),
        ('top', ctypes.c_int),
        ('dmax', ctypes.c_int),
        ('neg', ctypes.c_int),
        ('flags', ctypes.c_int),
    ]


class EC_POINT(ctypes.Structure):  # pylint: disable=too-few-public-methods
    """OpenSSL's EC_POINT struct"""
    _fields_ = [
        ('meth', ctypes.c_void_p),
        ('curve_name', ctypes.c_int),
        ('X', ctypes.POINTER(BIGNUM)),
        ('Y', ctypes.POINTER(BIGNUM)),
        ('Z', ctypes.POINTER(BIGNUM)),
        ('Z_is_one', ctypes.c_int),
    ]


class _OpenSSL(object):
    """
    Wrapper for OpenSSL using ctypes
    """
    # pylint: disable=too-many-statements, too-many-instance-attributes
    def __init__(self, library):
        """
        Build the wrapper
        """
        self._lib = ctypes.CDLL(library)
        self._version, self._hexversion, self._cflags = get_version(self._lib)
        self._libreSSL = self._version and self._version.startswith(b"LibreSSL")

        self.pointer = ctypes.pointer
        self.c_int = ctypes.c_int
        self.byref = ctypes.byref
        self.create_string_buffer = ctypes.create_string_buffer

        self.BN_new = self._lib.BN_new
        self.BN_new.restype = ctypes.POINTER(BIGNUM)
        self.BN_new.argtypes = []

        self.BN_free = self._lib.BN_free
        self.BN_free.restype = None
        self.BN_free.argtypes = [ctypes.POINTER(BIGNUM)]

        self.BN_clear_free = self._lib.BN_clear_free
        self.BN_clear_free.restype = None
        self.BN_clear_free.argtypes = [ctypes.POINTER(BIGNUM)]

        self.BN_num_bits = self._lib.BN_num_bits
        self.BN_num_bits.restype = ctypes.c_int
        self.BN_num_bits.argtypes = [ctypes.POINTER(BIGNUM)]

        self.BN_bn2bin = self._lib.BN_bn2bin
        self.BN_bn2bin.restype = ctypes.c_int
        self.BN_bn2bin.argtypes = [ctypes.POINTER(BIGNUM), ctypes.c_void_p]

        try:
            self.BN_bn2binpad = self._lib.BN_bn2binpad
            self.BN_bn2binpad.restype = ctypes.c_int
            self.BN_bn2binpad.argtypes = [ctypes.POINTER(BIGNUM), ctypes.c_void_p,
                                          ctypes.c_int]
        except AttributeError:
            # optional, we have a workaround
            pass

        self.BN_bin2bn = self._lib.BN_bin2bn
        self.BN_bin2bn.restype = ctypes.POINTER(BIGNUM)
        self.BN_bin2bn.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                   ctypes.POINTER(BIGNUM)]

        self.EC_KEY_free = self._lib.EC_KEY_free
        self.EC_KEY_free.restype = None
        self.EC_KEY_free.argtypes = [ctypes.c_void_p]

        self.EC_KEY_new_by_curve_name = self._lib.EC_KEY_new_by_curve_name
        self.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
        self.EC_KEY_new_by_curve_name.argtypes = [ctypes.c_int]

        self.EC_KEY_generate_key = self._lib.EC_KEY_generate_key
        self.EC_KEY_generate_key.restype = ctypes.c_int
        self.EC_KEY_generate_key.argtypes = [ctypes.c_void_p]

        self.EC_KEY_check_key = self._lib.EC_KEY_check_key
        self.EC_KEY_check_key.restype = ctypes.c_int
        self.EC_KEY_check_key.argtypes = [ctypes.c_void_p]

        self.EC_KEY_get0_private_key = self._lib.EC_KEY_get0_private_key
        self.EC_KEY_get0_private_key.restype = ctypes.POINTER(BIGNUM)
        self.EC_KEY_get0_private_key.argtypes = [ctypes.c_void_p]

        self.EC_KEY_get0_public_key = self._lib.EC_KEY_get0_public_key
        self.EC_KEY_get0_public_key.restype = ctypes.POINTER(EC_POINT)
        self.EC_KEY_get0_public_key.argtypes = [ctypes.c_void_p]

        # CRITICAL FIX: Handle missing EC_KEY_get0_group in LibreSSL
        try:
            self.EC_KEY_get0_group = self._lib.EC_KEY_get0_group
            self.EC_KEY_get0_group.restype = ctypes.c_void_p
            self.EC_KEY_get0_group.argtypes = [ctypes.c_void_p]
        except AttributeError:
            # LibreSSL compatibility - provide fallback
            print("WARNING: EC_KEY_get0_group not found in LibreSSL, using fallback")
            def EC_KEY_get0_group_fallback(ec_key):
                # Try alternative function names or return None
                try:
                    # Try EC_KEY_get_group if available
                    if hasattr(self, 'EC_KEY_get_group'):
                        return self.EC_KEY_get_group(ec_key)
                    # For LibreSSL, we may need to get group differently
                    return None
                except:
                    return None
            self.EC_KEY_get0_group = EC_KEY_get0_group_fallback

        self.EC_POINT_get_affine_coordinates_GFp = \
            self._lib.EC_POINT_get_affine_coordinates_GFp
        self.EC_POINT_get_affine_coordinates_GFp.restype = ctypes.c_int
        self.EC_POINT_get_affine_coordinates_GFp.argtypes = [ctypes.c_void_p,
                                                             ctypes.POINTER(EC_POINT),
                                                             ctypes.POINTER(BIGNUM),
                                                             ctypes.POINTER(BIGNUM),
                                                             ctypes.c_void_p]

        try:
            self.EC_POINT_get_affine_coordinates = \
                self._lib.EC_POINT_get_affine_coordinates
        except AttributeError:
            # OpenSSL docs say only use this for backwards compatibility
            self.EC_POINT_get_affine_coordinates = \
                self._lib.EC_POINT_get_affine_coordinates_GF2m
        self.EC_POINT_get_affine_coordinates.restype = ctypes.c_int
        self.EC_POINT_get_affine_coordinates.argtypes = [ctypes.c_void_p,
                                                         ctypes.POINTER(EC_POINT),
                                                         ctypes.POINTER(BIGNUM),
                                                         ctypes.POINTER(BIGNUM),
                                                         ctypes.c_void_p]

        self.EC_KEY_set_private_key = self._lib.EC_KEY_set_private_key
        self.EC_KEY_set_private_key.restype = ctypes.c_int
        self.EC_KEY_set_private_key.argtypes = [ctypes.c_void_p,
                                                ctypes.POINTER(BIGNUM)]

        self.EC_KEY_set_public_key = self._lib.EC_KEY_set_public_key
        self.EC_KEY_set_public_key.restype = ctypes.c_int
        self.EC_KEY_set_public_key.argtypes = [ctypes.c_void_p,
                                               ctypes.POINTER(EC_POINT)]

        self.EC_KEY_set_group = self._lib.EC_KEY_set_group
        self.EC_KEY_set_group.restype = ctypes.c_int
        self.EC_KEY_set_group.argtypes = [ctypes.c_void_p,
                                          ctypes.c_void_p]

        self.EC_POINT_set_affine_coordinates_GFp = \
            self._lib.EC_POINT_set_affine_coordinates_GFp
        self.EC_POINT_set_affine_coordinates_GFp.restype = ctypes.c_int
        self.EC_POINT_set_affine_coordinates_GFp.argtypes = [ctypes.c_void_p,
                                                             ctypes.POINTER(EC_POINT),
                                                             ctypes.POINTER(BIGNUM),
                                                             ctypes.POINTER(BIGNUM),
                                                             ctypes.c_void_p]

        try:
            self.EC_POINT_set_affine_coordinates = \
                self._lib.EC_POINT_set_affine_coordinates
        except AttributeError:
            # OpenSSL docs say only use this for backwards compatibility
            self.EC_POINT_set_affine_coordinates = \
                self._lib.EC_POINT_set_affine_coordinates_GF2m
        self.EC_POINT_set_affine_coordinates.restype = ctypes.c_int
        self.EC_POINT_set_affine_coordinates.argtypes = [ctypes.c_void_p,
                                                         ctypes.POINTER(EC_POINT),
                                                         ctypes.POINTER(BIGNUM),
                                                         ctypes.POINTER(BIGNUM),
                                                         ctypes.c_void_p]

        try:
            self.EC_POINT_set_compressed_coordinates = \
                self._lib.EC_POINT_set_compressed_coordinates
        except AttributeError:
            # OpenSSL docs say only use this for backwards compatibility
            self.EC_POINT_set_compressed_coordinates = \
                self._lib.EC_POINT_set_compressed_coordinates_GFp
        self.EC_POINT_set_compressed_coordinates.restype = ctypes.c_int
        self.EC_POINT_set_compressed_coordinates.argtypes = [ctypes.c_void_p,
                                                             ctypes.POINTER(EC_POINT),
                                                             ctypes.POINTER(BIGNUM),
                                                             ctypes.c_int,
                                                             ctypes.c_void_p]

        self.EC_POINT_new = self._lib.EC_POINT_new
        self.EC_POINT_new.restype = ctypes.POINTER(EC_POINT)
        self.EC_POINT_new.argtypes = [ctypes.c_void_p]

        self.EC_POINT_free = self._lib.EC_POINT_free
        self.EC_POINT_free.restype = None
        self.EC_POINT_free.argtypes = [ctypes.POINTER(EC_POINT)]

        self.BN_CTX_free = self._lib.BN_CTX_free
        self.BN_CTX_free.restype = None
        self.BN_CTX_free.argtypes = [ctypes.c_void_p]

        self.EC_POINT_mul = self._lib.EC_POINT_mul
        self.EC_POINT_mul.restype = ctypes.c_int
        self.EC_POINT_mul.argtypes = [ctypes.c_void_p,
                                      ctypes.POINTER(EC_POINT),
                                      ctypes.POINTER(BIGNUM),
                                      ctypes.POINTER(EC_POINT),
                                      ctypes.POINTER(BIGNUM),
                                      ctypes.c_void_p]

        self.EC_KEY_set_private_key = self._lib.EC_KEY_set_private_key
        self.EC_KEY_set_private_key.restype = ctypes.c_int
        self.EC_KEY_set_private_key.argtypes = [ctypes.c_void_p,
                                                ctypes.POINTER(BIGNUM)]

        if self._hexversion and self._hexversion >= 0x10100000 and not self._libreSSL:
            self.EC_KEY_OpenSSL = self._lib.EC_KEY_OpenSSL
            self._lib.EC_KEY_OpenSSL.restype = ctypes.c_void_p
            self._lib.EC_KEY_OpenSSL.argtypes = []

            self.EC_KEY_set_method = self._lib.EC_KEY_set_method
            self._lib.EC_KEY_set_method.restype = ctypes.c_int
            self._lib.EC_KEY_set_method.argtypes = [ctypes.c_void_p,
                                                    ctypes.c_void_p]
        else:
            # LibreSSL-Kompatibilität: ECDH-Methoden-Handling
            try:
                self.ECDH_OpenSSL = self._lib.ECDH_OpenSSL
                self._lib.ECDH_OpenSSL.restype = ctypes.c_void_p
                self._lib.ECDH_OpenSSL.argtypes = []
            except AttributeError:
                try:
                    # Fallback für neuere LibreSSL
                    self.ECDH_OpenSSL = self._lib.ECDH_libressl
                    self._lib.ECDH_libressl.restype = ctypes.c_void_p
                    self._lib.ECDH_libressl.argtypes = []
                except AttributeError:
                    # LibreSSL 4.1.0 hat keine ECDH_METHOD
                    print("🔧 LibreSSL: Verwende ECDH_compute_key anstelle von ECDH_METHOD")
                    
                    def dummy_ecdh_method():
                        return ctypes.c_void_p(0)
                    
                    self.ECDH_OpenSSL = dummy_ecdh_method

            # ECDH_set_method Handling - KORRIGIERT
            try:
                # ZUERST prüfen ob die Funktion existiert
                self._lib.ECDH_set_method
                self.ECDH_set_method = self._lib.ECDH_set_method
                self.ECDH_set_method.restype = ctypes.c_int
                self.ECDH_set_method.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            except AttributeError:
                # LibreSSL: ECDH_set_method nicht verfügbar
                print("🔧 LibreSSL: ECDH_set_method nicht verfügbar, verwende direkten ECDH")
                
                def dummy_ecdh_set_method(ec_key, method):
                    # Bei LibreSSL ist keine spezielle ECDH-Methode nötig
                    return 1  # Erfolg zurückgeben
                
                self.ECDH_set_method = dummy_ecdh_set_method

            # ECDH_compute_key sicherstellen
            try:
                self.ECDH_compute_key = self._lib.ECDH_compute_key
                self.ECDH_compute_key.restype = ctypes.c_int
                self.ECDH_compute_key.argtypes = [
                    ctypes.c_void_p,  # out
                    ctypes.c_int,     # outlen
                    ctypes.c_void_p,  # pub_key
                    ctypes.c_void_p   # ecdh
                ]
                print("✅ ECDH_compute_key erfolgreich geladen")
            except AttributeError:
                print("❌ KRITISCH: ECDH_compute_key nicht verfügbar!")
                # Hier sollte ein Fallback implementiert werden

            # ECDH_size für Puffer-Größenberechnung
            try:
                self.ECDH_size = self._lib.ECDH_size
                self.ECDH_size.restype = ctypes.c_int
                self.ECDH_size.argtypes = [ctypes.c_void_p]
            except AttributeError:
                print("⚠️  ECDH_size nicht verfügbar")
                # Fallback: Feste Größe annehmen (z.B. 256 für EC256)
                def dummy_ecdh_size(ec_key):
                    return 256
                self.ECDH_size = dummy_ecdh_size

        self.ECDH_compute_key = self._lib.ECDH_compute_key
        self.ECDH_compute_key.restype = ctypes.c_int
        self.ECDH_compute_key.argtypes = [ctypes.c_void_p,
                                          ctypes.c_int,
                                          ctypes.c_void_p,
                                          ctypes.c_void_p]

        self.EVP_CipherInit_ex = self._lib.EVP_CipherInit_ex
        self.EVP_CipherInit_ex.restype = ctypes.c_int
        self.EVP_CipherInit_ex.argtypes = [ctypes.c_void_p,
                                           ctypes.c_void_p,
                                           ctypes.c_void_p]

        self.EVP_CIPHER_CTX_new = self._lib.EVP_CIPHER_CTX_new
        self.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        self.EVP_CIPHER_CTX_new.argtypes = []

        # Cipher
        self.EVP_aes_128_cfb128 = self._lib.EVP_aes_128_cfb128
        self.EVP_aes_128_cfb128.restype = ctypes.c_void_p
        self.EVP_aes_128_cfb128.argtypes = []

        self.EVP_aes_256_cfb128 = self._lib.EVP_aes_256_cfb128
        self.EVP_aes_256_cfb128.restype = ctypes.c_void_p
        self.EVP_aes_256_cfb128.argtypes = []

        self.EVP_aes_128_cbc = self._lib.EVP_aes_128_cbc
        self.EVP_aes_128_cbc.restype = ctypes.c_void_p
        self.EVP_aes_128_cbc.argtypes = []

        self.EVP_aes_256_cbc = self._lib.EVP_aes_256_cbc
        self.EVP_aes_256_cbc.restype = ctypes.c_void_p
        self.EVP_aes_256_cbc.argtypes = []

        self.EVP_aes_128_ofb = self._lib.EVP_aes_128_ofb
        self.EVP_aes_128_ofb.restype = ctypes.c_void_p
        self.EVP_aes_128_ofb.argtypes = []

        self.EVP_aes_256_ofb = self._lib.EVP_aes_256_ofb
        self.EVP_aes_256_ofb.restype = ctypes.c_void_p
        self.EVP_aes_256_ofb.argtypes = []

        self.EVP_bf_cbc = self._lib.EVP_bf_cbc
        self.EVP_bf_cbc.restype = ctypes.c_void_p
        self.EVP_bf_cbc.argtypes = []

        self.EVP_bf_cfb64 = self._lib.EVP_bf_cfb64
        self.EVP_bf_cfb64.restype = ctypes.c_void_p
        self.EVP_bf_cfb64.argtypes = []

        self.EVP_rc4 = self._lib.EVP_rc4
        self.EVP_rc4.restype = ctypes.c_void_p
        self.EVP_rc4.argtypes = []

        if self._hexversion and self._hexversion >= 0x10100000 and not self._libreSSL:
            self.EVP_CIPHER_CTX_reset = self._lib.EVP_CIPHER_CTX_reset
            self.EVP_CIPHER_CTX_reset.restype = ctypes.c_int
            self.EVP_CIPHER_CTX_reset.argtypes = [ctypes.c_void_p]
        else:
            self.EVP_CIPHER_CTX_cleanup = self._lib.EVP_CIPHER_CTX_cleanup
            self.EVP_CIPHER_CTX_cleanup.restype = ctypes.c_int
            self.EVP_CIPHER_CTX_cleanup.argtypes = [ctypes.c_void_p]

        self.EVP_CIPHER_CTX_free = self._lib.EVP_CIPHER_CTX_free
        self.EVP_CIPHER_CTX_free.restype = None
        self.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

        self.EVP_CipherUpdate = self._lib.EVP_CipherUpdate
        self.EVP_CipherUpdate.restype = ctypes.c_int
        self.EVP_CipherUpdate.argtypes = [ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_int]

        self.EVP_CipherFinal_ex = self._lib.EVP_CipherFinal_ex
        self.EVP_CipherFinal_ex.restype = ctypes.c_int
        self.EVP_CipherFinal_ex.argtypes = [ctypes.c_void_p,
                                            ctypes.c_void_p, ctypes.c_void_p]

        self.EVP_DigestInit = self._lib.EVP_DigestInit
        self.EVP_DigestInit.restype = ctypes.c_int
        self._lib.EVP_DigestInit.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        self.EVP_DigestInit_ex = self._lib.EVP_DigestInit_ex
        self.EVP_DigestInit_ex.restype = ctypes.c_int
        self._lib.EVP_DigestInit_ex.argtypes = 3 * [ctypes.c_void_p]

        self.EVP_DigestUpdate = self._lib.EVP_DigestUpdate
        self.EVP_DigestUpdate.restype = ctypes.c_int
        self.EVP_DigestUpdate.argtypes = [ctypes.c_void_p,
                                          ctypes.c_void_p, ctypes.c_size_t]

        self.EVP_DigestFinal = self._lib.EVP_DigestFinal
        self.EVP_DigestFinal.restype = ctypes.c_int
        self.EVP_DigestFinal.argtypes = [ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_void_p]

        self.EVP_DigestFinal_ex = self._lib.EVP_DigestFinal_ex
        self.EVP_DigestFinal_ex.restype = ctypes.c_int
        self.EVP_DigestFinal_ex.argtypes = [ctypes.c_void_p,
                                            ctypes.c_void_p, ctypes.c_void_p]

        self.ECDSA_sign = self._lib.ECDSA_sign
        self.ECDSA_sign.restype = ctypes.c_int
        self.ECDSA_sign.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                    ctypes.c_int, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_void_p]

        self.ECDSA_verify = self._lib.ECDSA_verify
        self.ECDSA_verify.restype = ctypes.c_int
        self.ECDSA_verify.argtypes = [ctypes.c_int, ctypes.c_void_p,
                                      ctypes.c_int, ctypes.c_void_p,
                                      ctypes.c_int, ctypes.c_void_p]

        if self._hexversion and self._hexversion >= 0x10100000 and not self._libreSSL:
            self.EVP_MD_CTX_new = self._lib.EVP_MD_CTX_new
            self.EVP_MD_CTX_new.restype = ctypes.c_void_p
            self.EVP_MD_CTX_new.argtypes = []

            self.EVP_MD_CTX_reset = self._lib.EVP_MD_CTX_reset
            self.EVP_MD_CTX_reset.restype = None
            self.EVP_MD_CTX_reset.argtypes = [ctypes.c_void_p]

            self.EVP_MD_CTX_free = self._lib.EVP_MD_CTX_free
            self.EVP_MD_CTX_free.restype = None
            self.EVP_MD_CTX_free.argtypes = [ctypes.c_void_p]

            self.EVP_sha1 = self._lib.EVP_sha1
            self.EVP_sha1.restype = ctypes.c_void_p
            self.EVP_sha1.argtypes = []

            self.digest_ecdsa_sha1 = self.EVP_sha1
        else:
            self.EVP_MD_CTX_create = self._lib.EVP_MD_CTX_create
            self.EVP_MD_CTX_create.restype = ctypes.c_void_p
            self.EVP_MD_CTX_create.argtypes = []

            self.EVP_MD_CTX_init = self._lib.EVP_MD_CTX_init
            self.EVP_MD_CTX_init.restype = None
            self.EVP_MD_CTX_init.argtypes = [ctypes.c_void_p]

            self.EVP_MD_CTX_destroy = self._lib.EVP_MD_CTX_destroy
            self.EVP_MD_CTX_destroy.restype = None
            self.EVP_MD_CTX_destroy.argtypes = [ctypes.c_void_p]

            # LibreSSL compatibility for digest functions
            try:
                self.EVP_ecdsa = self._lib.EVP_ecdsa
                self._lib.EVP_ecdsa.restype = ctypes.c_void_p
                self._lib.EVP_ecdsa.argtypes = []
                self.digest_ecdsa_sha1 = self.EVP_ecdsa
            except AttributeError:
                # Fallback to regular SHA1 for LibreSSL
                self.EVP_sha1 = self._lib.EVP_sha1
                self.EVP_sha1.restype = ctypes.c_void_p
                self.EVP_sha1.argtypes = []
                self.digest_ecdsa_sha1 = self.EVP_sha1

        self.RAND_bytes = self._lib.RAND_bytes
        self.RAND_bytes.restype = ctypes.c_int
        self.RAND_bytes.argtypes = [ctypes.c_void_p, ctypes.c_int]

        self.EVP_sha256 = self._lib.EVP_sha256
        self.EVP_sha256.restype = ctypes.c_void_p
        self.EVP_sha256.argtypes = []

        self.i2o_ECPublicKey = self._lib.i2o_ECPublicKey
        self.i2o_ECPublicKey.restype = ctypes.c_void_p
        self.i2o_ECPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        self.EVP_sha512 = self._lib.EVP_sha512
        self.EVP_sha512.restype = ctypes.c_void_p
        self.EVP_sha512.argtypes = []

        self.HMAC = self._lib.HMAC
        self.HMAC.restype = ctypes.c_void_p
        self.HMAC.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
                              ctypes.c_void_p, ctypes.c_size_t,
                              ctypes.c_void_p, ctypes.c_void_p]

        try:
            self.PKCS5_PBKDF2_HMAC = self._lib.PKCS5_PBKDF2_HMAC
        except Exception:
            # The above is not compatible with all versions of OSX.
            self.PKCS5_PBKDF2_HMAC = self._lib.PKCS5_PBKDF2_HMAC_SHA1

        self.PKCS5_PBKDF2_HMAC.restype = ctypes.c_int
        self.PKCS5_PBKDF2_HMAC.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                           ctypes.c_void_p, ctypes.c_int,
                                           ctypes.c_int, ctypes.c_void_p,
                                           ctypes.c_int, ctypes.c_void_p]

        # Blind signature requirements
        self.BN_CTX_new = self._lib.BN_CTX_new
        self.BN_CTX_new.restype = ctypes.c_void_p
        self.BN_CTX_new.argtypes = []

        self.BN_dup = self._lib.BN_dup
        self.BN_dup.restype = ctypes.POINTER(BIGNUM)
        self.BN_dup.argtypes = [ctypes.POINTER(BIGNUM)]

        self.BN_rand = self._lib.BN_rand
        self.BN_rand.restype = ctypes.c_int
        self.BN_rand.argtypes = [ctypes.POINTER(BIGNUM),
                                 ctypes.c_int,
                                 ctypes.c_int,
                                 ctypes.c_int]

        self.BN_set_word = self._lib.BN_set_word
        self.BN_set_word.restype = ctypes.c_int
        self.BN_set_word.argtypes = [ctypes.POINTER(BIGNUM),
                                     ctypes.c_ulong]

        self.BN_mul = self._lib.BN_mul
        self.BN_mul.restype = ctypes.c_int
        self.BN_mul.argtypes = [ctypes.POINTER(BIGNUM),
                                ctypes.POINTER(BIGNUM),
                                ctypes.POINTER(BIGNUM),
                                ctypes.c_void_p]

        self.BN_mod_add = self._lib.BN_mod_add
        self.BN_mod_add.restype = ctypes.c_int
        self.BN_mod_add.argtypes = [ctypes.POINTER(BIGNUM),
                                    ctypes.POINTER(BIGNUM),
                                    ctypes.POINTER(BIGNUM),
                                    ctypes.POINTER(BIGNUM),
                                    ctypes.c_void_p]

        self.BN_mod_inverse = self._lib.BN_mod_inverse
        self.BN_mod_inverse.restype = ctypes.POINTER(BIGNUM)
        self.BN_mod_inverse.argtypes = [ctypes.POINTER(BIGNUM),
                                        ctypes.POINTER(BIGNUM),
                                        ctypes.POINTER(BIGNUM),
                                        ctypes.c_void_p]

        self.BN_mod_mul = self._lib.BN_mod_mul
        self.BN_mod_mul.restype = ctypes.c_int
        self.BN_mod_mul.argtypes = [ctypes.POINTER(BIGNUM),
                                    ctypes.POINTER(BIGNUM),
                                    ctypes.POINTER(BIGNUM),
                                    ctypes.POINTER(BIGNUM),
                                    ctypes.c_void_p]

        self.BN_lshift = self._lib.BN_lshift
        self.BN_lshift.restype = ctypes.c_int
        self.BN_lshift.argtypes = [ctypes.POINTER(BIGNUM),
                                   ctypes.POINTER(BIGNUM),
                                   ctypes.c_int]

        self.BN_sub_word = self._lib.BN_sub_word
        self.BN_sub_word.restype = ctypes.c_int
        self.BN_sub_word.argtypes = [ctypes.POINTER(BIGNUM),
                                     ctypes.c_ulong]

        self.BN_cmp = self._lib.BN_cmp
        self.BN_cmp.restype = ctypes.c_int
        self.BN_cmp.argtypes = [ctypes.POINTER(BIGNUM),
                                ctypes.POINTER(BIGNUM)]

        try:
            self.BN_is_odd = self._lib.BN_is_odd
            self.BN_is_odd.restype = ctypes.c_int
            self.BN_is_odd.argtypes = [ctypes.POINTER(BIGNUM)]
        except AttributeError:
            # OpenSSL 1.1.0 implements this as a function, but earlier
            # versions as macro, so we need to workaround
            self.BN_is_odd = self.BN_is_odd_compatible

        self.BN_bn2dec = self._lib.BN_bn2dec
        self.BN_bn2dec.restype = ctypes.c_char_p
        self.BN_bn2dec.argtypes = [ctypes.POINTER(BIGNUM)]

        self.EC_GROUP_new_by_curve_name = self._lib.EC_GROUP_new_by_curve_name
        self.EC_GROUP_new_by_curve_name.restype = ctypes.c_void_p
        self.EC_GROUP_new_by_curve_name.argtypes = [ctypes.c_int]

        self.EC_GROUP_get_order = self._lib.EC_GROUP_get_order
        self.EC_GROUP_get_order.restype = ctypes.c_int
        self.EC_GROUP_get_order.argtypes = [ctypes.c_void_p,
                                            ctypes.POINTER(BIGNUM),
                                            ctypes.c_void_p]

        self.EC_GROUP_get_cofactor = self._lib.EC_GROUP_get_cofactor
        self.EC_GROUP_get_cofactor.restype = ctypes.c_int
        self.EC_GROUP_get_cofactor.argtypes = [ctypes.c_void_p,
                                               ctypes.POINTER(BIGNUM),
                                               ctypes.c_void_p]

        self.EC_GROUP_get0_generator = self._lib.EC_GROUP_get0_generator
        self.EC_GROUP_get0_generator.restype = ctypes.POINTER(EC_POINT)
        self.EC_GROUP_get0_generator.argtypes = [ctypes.c_void_p]

        self.EC_POINT_copy = self._lib.EC_POINT_copy
        self.EC_POINT_copy.restype = ctypes.c_int
        self.EC_POINT_copy.argtypes = [ctypes.POINTER(EC_POINT),
                                       ctypes.POINTER(EC_POINT)]

        self.EC_POINT_add = self._lib.EC_POINT_add
        self.EC_POINT_add.restype = ctypes.c_int
        self.EC_POINT_add.argtypes = [ctypes.c_void_p,
                                      ctypes.POINTER(EC_POINT),
                                      ctypes.POINTER(EC_POINT),
                                      ctypes.POINTER(EC_POINT),
                                      ctypes.c_void_p]

        self.EC_POINT_cmp = self._lib.EC_POINT_cmp
        self.EC_POINT_cmp.restype = ctypes.c_int
        self.EC_POINT_cmp.argtypes = [ctypes.c_void_p,
                                      ctypes.POINTER(EC_POINT),
                                      ctypes.POINTER(EC_POINT),
                                      ctypes.c_void_p]

        self.EC_POINT_set_to_infinity = self._lib.EC_POINT_set_to_infinity
        self.EC_POINT_set_to_infinity.restype = ctypes.c_int
        self.EC_POINT_set_to_infinity.argtypes = [ctypes.c_void_p,
                                                  ctypes.POINTER(EC_POINT)]

        self._set_ciphers()
        self._set_curves()

    def _set_ciphers(self):
        self.cipher_algo = {
            'aes-128-cbc': CipherName(
                'aes-128-cbc', self.EVP_aes_128_cbc, 16),
            'aes-256-cbc': CipherName(
                'aes-256-cbc', self.EVP_aes_256_cbc, 16),
            'aes-128-cfb': CipherName(
                'aes-128-cfb', self.EVP_aes_128_cfb128, 16),
            'aes-256-cfb': CipherName(
                'aes-256-cfb', self.EVP_aes_256_cfb128, 16),
            'aes-128-ofb': CipherName(
                'aes-128-ofb', self._lib.EVP_aes_128_ofb, 16),
            'aes-256-ofb': CipherName(
                'aes-256-ofb', self._lib.EVP_aes_256_ofb, 16),
            'bf-cfb': CipherName(
                'bf-cfb', self.EVP_bf_cfb64, 8),
            'bf-cbc': CipherName(
                'bf-cbc', self.EVP_bf_cbc, 8),
            # 128 is the initialisation size not block size
            'rc4': CipherName(
                'rc4', self.EVP_rc4, 128),
        }

    def _set_curves(self):
        self.curves = {
            'secp112r1': 704,
            'secp112r2': 705,
            'secp128r1': 706,
            'secp128r2': 707,
            'secp160k1': 708,
            'secp160r1': 709,
            'secp160r2': 710,
            'secp192k1': 711,
            'secp224k1': 712,
            'secp224r1': 713,
            'secp256k1': 714,
            'secp384r1': 715,
            'secp521r1': 716,
            'sect113r1': 717,
            'sect113r2': 718,
            'sect131r1': 719,
            'sect131r2': 720,
            'sect163k1': 721,
            'sect163r1': 722,
            'sect163r2': 723,
            'sect193r1': 724,
            'sect193r2': 725,
            'sect233k1': 726,
            'sect233r1': 727,
            'sect239k1': 728,
            'sect283k1': 729,
            'sect283r1': 730,
            'sect409k1': 731,
            'sect409r1': 732,
            'sect571k1': 733,
            'sect571r1': 734,
        }

    def BN_num_bytes(self, x):
        """
        returns the length of a BN (OpenSSl API)
        """
        return int((self.BN_num_bits(x) + 7) / 8)

    def BN_is_odd_compatible(self, x):
        """
        returns if BN is odd
        we assume big endianness, and that BN is initialised
        """
        length = self.BN_num_bytes(x)
        data = self.malloc(0, length)
        OpenSSL.BN_bn2bin(x, data)
        return six.byte2int(data[length - 1]) & 1

    def get_cipher(self, name):
        """
        returns the OpenSSL cipher instance
        """
        if name not in self.cipher_algo:
            raise Exception("Unknown cipher")
        return self.cipher_algo[name]

    def get_curve(self, name):
        """
        returns the id of a elliptic curve
        """
        if name not in self.curves:
            raise Exception("Unknown curve")
        return self.curves[name]

    def get_curve_by_id(self, id_):
        """
        returns the name of a elliptic curve with his id
        """
        res = None
        for i in self.curves:
            if self.curves[i] == id_:
                res = i
                break
        if res is None:
            raise Exception("Unknown curve")
        return res

    def rand(self, size):
        """
        OpenSSL random function
        """
        buffer_ = self.malloc(0, size)
        # This pyelliptic library, by default, didn't check the return value
        # of RAND_bytes. It is evidently possible that it returned an error
        # and not-actually-random data. However, in tests on various
        # operating systems, while generating hundreds of gigabytes of random
        # strings of various sizes I could not get an error to occur.
        # Also Bitcoin doesn't check the return value of RAND_bytes either.
        # Fixed in Bitmessage version 0.4.2 (in source code on 2013-10-13)
        while self.RAND_bytes(buffer_, size) != 1:
            import time
            time.sleep(1)
        return buffer_.raw

    def malloc(self, data, size):
        """
        returns a create_string_buffer (ctypes)
        """
        buffer_ = None
        if data != 0:
            if six.PY3 and isinstance(data, type('')):
                data = data.encode()
            buffer_ = self.create_string_buffer(data, size)
        else:
            buffer_ = self.create_string_buffer(size)
        return buffer_


def loadOpenSSL():
    """This function finds and load the OpenSSL library on any platform"""
    # pylint: disable=global-statement
    global OpenSSL
    from os import path, environ
    from ctypes.util import find_library
    import subprocess
    import sys
    import os

    libdir = []
    
    # Platform detection
    is_openbsd = sys.platform.startswith('openbsd')
    is_linux = sys.platform.startswith('linux')
    is_darwin = sys.platform.startswith('darwin')
    is_windows = sys.platform.startswith('win')
    is_freebsd = sys.platform.startswith('freebsd')
    is_netbsd = sys.platform.startswith('netbsd')
    
    # PRIORITY 1: USER-COMPILED LIBRESSL IN /HOME - HIGHEST PRIORITY
    custom_libressl_paths = [
        # Your compiled LibreSSL 4.1.0 - HIGHEST PRIORITY
        "/home/libressl-4.1.0/build/ssl/libssl.so.59.1.0",
        "/home/libressl-4.1.0/build/crypto/libcrypto.so.58.1.0",
        "/home/libressl-4.1.0/build/ssl/libssl.so",
        "/home/libressl-4.1.0/build/crypto/libcrypto.so",
        "/home/libressl-4.1.0/build/ssl/libssl.so.59",
        "/home/libressl-4.1.0/build/crypto/libcrypto.so.58",
        
        # Alternative build paths
        "/home/libressl-4.1.0/ssl/.libs/libssl.so",
        "/home/libressl-4.1.0/crypto/.libs/libcrypto.so",
    ]
    
    # Add custom paths first (highest priority)
    for custom_path in custom_libressl_paths:
        if path.exists(custom_path):
            libdir.append(custom_path)
            print(f"🚀 PRIORITY: Found custom LibreSSL at {custom_path}")
    
    # PRIORITY 2: PLATFORM-SPECIFIC PATHS
    # LINUX PATHS
    if is_linux:
        libdir.extend([
            '/usr/lib/x86_64-linux-gnu/libssl.so',
            '/usr/lib/x86_64-linux-gnu/libcrypto.so',
            '/usr/lib/aarch64-linux-gnu/libssl.so',
            '/usr/lib/aarch64-linux-gnu/libcrypto.so',
            '/usr/lib/arm-linux-gnueabihf/libssl.so',
            '/usr/lib/arm-linux-gnueabihf/libcrypto.so',
            '/usr/lib/libssl.so',
            '/usr/lib/libcrypto.so',
            '/usr/local/lib/libssl.so',
            '/usr/local/lib/libcrypto.so',
            '/lib/libssl.so',
            '/lib/libcrypto.so',
            # Versioned paths
            '/usr/lib/x86_64-linux-gnu/libssl.so.1.1',
            '/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1',
            '/usr/lib/x86_64-linux-gnu/libssl.so.1.0.0',
            '/usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.0',
            '/usr/lib/x86_64-linux-gnu/libssl.so.3',
            '/usr/lib/x86_64-linux-gnu/libcrypto.so.3',
        ])
    
    # OPENBSD PATHS
    elif is_openbsd:
        libdir.extend([
            # System LibreSSL
            '/usr/lib/libssl.so',
            '/usr/lib/libcrypto.so',
            '/usr/local/lib/libssl.so',
            '/usr/local/lib/libcrypto.so',
            # Versioned LibreSSL
            '/usr/lib/libssl.so.26.0',
            '/usr/lib/libcrypto.so.26.0',
            '/usr/lib/libssl.so.25.0',
            '/usr/lib/libcrypto.so.25.0',
            '/usr/lib/libssl.so.24.0',
            '/usr/lib/libcrypto.so.24.0',
        ])
    
    # macOS PATHS
    elif is_darwin:
        libdir.extend([
            '/usr/local/opt/openssl/lib/libssl.dylib',
            '/usr/local/opt/openssl/lib/libcrypto.dylib',
            '/usr/local/lib/libssl.dylib',
            '/usr/local/lib/libcrypto.dylib',
            '/opt/homebrew/opt/openssl/lib/libssl.dylib',
            '/opt/homebrew/opt/openssl/lib/libcrypto.dylib',
            '/usr/lib/libssl.dylib',
            '/usr/lib/libcrypto.dylib',
        ])
    
    # WINDOWS PATHS
    elif is_windows:
        libdir.extend([
            'C:\\OpenSSL-Win64\\bin\\libssl.dll',
            'C:\\OpenSSL-Win64\\bin\\libcrypto.dll',
            'C:\\OpenSSL-Win32\\bin\\libssl.dll',
            'C:\\OpenSSL-Win32\\bin\\libcrypto.dll',
            'libeay32.dll',
            'ssleay32.dll',
        ])
    
    # OTHER BSD PATHS
    elif is_freebsd or is_netbsd:
        libdir.extend([
            '/usr/local/lib/libssl.so',
            '/usr/local/lib/libcrypto.so',
            '/usr/lib/libssl.so',
            '/usr/lib/libcrypto.so',
            '/usr/pkg/lib/libssl.so',  # NetBSD pkgsrc
            '/usr/pkg/lib/libcrypto.so',
        ])
    
    # PRIORITY 3: GENERIC LIBRARY NAMES (system resolver)
    generic_names = [
        'libssl.so',      # Linux/BSD
        'libcrypto.so',   # Linux/BSD
        'libssl.dylib',   # macOS
        'libcrypto.dylib', # macOS
        'libeay32.dll',   # Windows
        'ssleay32.dll',   # Windows
    ]
    
    # Use ctypes.util.find_library for system-wide search
    ssl_lib = find_library('ssl')
    crypto_lib = find_library('crypto')
    
    if ssl_lib:
        libdir.append(ssl_lib)
    if crypto_lib:
        libdir.append(crypto_lib)
    
    # Also try to find Windows libraries
    if is_windows:
        libeay_lib = find_library('libeay32')
        if libeay_lib:
            libdir.append(libeay_lib)
    
    # Add generic names last (lowest priority)
    libdir.extend(generic_names)
    
    # Remove duplicates while preserving order
    seen = set()
    libdir = [lib for lib in libdir if lib not in seen and not seen.add(lib)]
    
    # Debug: Show search paths
    print("DEBUG: OpenSSL library search order:")
    for i, lib_path in enumerate(libdir):
        priority = "HIGH" if lib_path in custom_libressl_paths else "LOW"
        exists = "EXISTS" if path.exists(lib_path) else "MISSING" if lib_path.startswith(('/', '\\', 'C:', 'D:')) else "SYSTEM"
        print(f"  {i+1}. [{priority}] {lib_path} ({exists})")

    # Try to load the library with detailed debugging
    successful_loads = []
    for library in libdir:
        try:
            # Skip non-absolute paths that don't exist (let ctypes handle them)
            if not library.startswith(('/', '\\', 'C:', 'D:')) and not path.exists(library):
                # This might be a library name like "libssl.so" that ctypes can find
                pass
            
            print(f"DEBUG: Trying to load from: {library}")
            OpenSSL = _OpenSSL(library)
            print(f"SUCCESS: Loaded OpenSSL from: {library}")
            
            # Test basic functionality
            try:
                # Try different version functions
                version = None
                if hasattr(OpenSSL, 'OpenSSL_version'):
                    version = OpenSSL.OpenSSL_version(0)
                elif hasattr(OpenSSL, 'SSLeay_version'):
                    version = OpenSSL.SSLeay_version(0)
                
                if version:
                    version_str = version.decode() if hasattr(version, 'decode') else str(version)
                    print(f"✓ OpenSSL version: {version_str}")
                    
                    # Check if it's LibreSSL
                    if 'LibreSSL' in version_str:
                        print("✓ LibreSSL detected")
                    else:
                        print("✓ OpenSSL detected")
                else:
                    print("✓ OpenSSL loaded but version unknown")
                
                successful_loads.append((library, version))
                
                # Test basic BN functionality
                test_bn = OpenSSL.BN_new()
                if test_bn:
                    OpenSSL.BN_free(test_bn)
                    print("✓ Basic functionality test passed")
                
                # Test that the critical EC_KEY_get0_group function is available
                if hasattr(OpenSSL, 'EC_KEY_get0_group'):
                    print("✓ EC_KEY_get0_group function available")
                else:
                    print("✗ EC_KEY_get0_group function missing - this will cause issues")
                
            except Exception as test_error:
                print(f"WARNING: Library loaded but test failed: {test_error}")
                continue
                
            return
            
        except Exception as e:
            print(f"FAILED: {library} - {str(e)}")
            continue
    
    # Enhanced system-wide search as fallback
    print("Performing enhanced system-wide library search...")
    
    # Platform-specific search commands
    search_commands = {
        'linux': [
            ['find', '/usr', '-name', 'libssl.so*', '-type', 'f', '2>/dev/null'],
            ['find', '/lib', '-name', 'libssl.so*', '-type', 'f', '2>/dev/null'],
            ['find', '/usr/local', '-name', 'libssl.so*', '-type', 'f', '2>/dev/null'],
            ['find', '/opt', '-name', 'libssl.so*', '-type', 'f', '2>/dev/null'],
        ],
        'openbsd': [
            ['find', '/usr', '-name', 'libssl.so*', '-type', 'f', '2>/dev/null'],
            ['find', '/usr/local', '-name', 'libssl.so*', '-type', 'f', '2>/dev/null'],
        ],
        'darwin': [
            ['find', '/usr', '-name', 'libssl.dylib', '-type', 'f', '2>/dev/null'],
            ['find', '/usr/local', '-name', 'libssl.dylib', '-type', 'f', '2>/dev/null'],
            ['find', '/opt', '-name', 'libssl.dylib', '-type', 'f', '2>/dev/null'],
            ['find', '/Applications', '-name', 'libssl.dylib', '-type', 'f', '2>/dev/null'],
        ]
    }
    
    current_platform = None
    if is_linux:
        current_platform = 'linux'
    elif is_openbsd:
        current_platform = 'openbsd'
    elif is_darwin:
        current_platform = 'darwin'
    
    if current_platform and current_platform in search_commands:
        for cmd in search_commands[current_platform]:
            try:
                result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                      timeout=15, shell=False)
                found_libs = result.stdout.decode().splitlines()
                
                for library in found_libs:
                    try:
                        if path.exists(library) and library not in libdir:
                            print(f"Trying discovered library: {library}")
                            OpenSSL = _OpenSSL(library)
                            print(f"SUCCESS with discovered library: {library}")
                            return
                    except Exception as fallback_error:
                        print(f"Discovered library failed: {library} - {fallback_error}")
                        continue
                        
            except (subprocess.TimeoutExpired, subprocess.SubprocessError, FileNotFoundError):
                continue
    
    # Final diagnostic with helpful instructions
    print("\n=== OPENSSL LOADING FAILED ===")
    print(f"Platform: {sys.platform}")
    print(f"Python version: {sys.version}")
    
    # Check if custom LibreSSL exists but failed to load
    custom_exists = any(path.exists(p) for p in custom_libressl_paths)
    if custom_exists:
        print("\n⚠️  Custom LibreSSL found but failed to load!")
        print("This could indicate:")
        print("  - Library version incompatibility")
        print("  - Missing dependencies")
        print("  - Architecture mismatch")
        print("  - Corrupted build")
    
    # Test if openssl command is available
    try:
        result = subprocess.run(['openssl', 'version'], 
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        if result.returncode == 0:
            print(f"✓ OpenSSL command available: {result.stdout.decode().strip()}")
        else:
            print("✗ OpenSSL command not working")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("✗ OpenSSL command not found")
    
    # Platform-specific installation instructions
    print("\n💡 INSTALLATION INSTRUCTIONS:")
    if is_linux:
        print("  Debian/Ubuntu: sudo apt-get install libssl-dev")
        print("  RedHat/CentOS: sudo yum install openssl-devel")
        print("  Arch: sudo pacman -S openssl")
        print("  Or use your compiled LibreSSL in /home/libressl-4.1.0/")
    elif is_openbsd:
        print("  OpenBSD: sudo pkg_add libressl")
        print("  Or use your compiled LibreSSL in /home/libressl-4.1.0/")
    elif is_darwin:
        print("  macOS: brew install openssl")
    elif is_windows:
        print("  Windows: Install OpenSSL from https://slproweb.com/products/Win32OpenSSL.html")
    else:
        print("  Please install OpenSSL or LibreSSL development packages")
    
    # Show what was found but failed
    if successful_loads:
        print("\n📋 Libraries that loaded but failed tests:")
        for lib, ver in successful_loads:
            print(f"  - {lib} (version: {ver})")
    
    raise Exception(
        "Couldn't find and load a compatible OpenSSL/LibreSSL library.\n"
        "Please install development packages or compile a compatible version.")


# Load OpenSSL when module is imported
loadOpenSSL()
