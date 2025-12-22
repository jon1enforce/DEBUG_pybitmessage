# -*- coding: utf-8 -*-
# Copyright (c) 2011 Yann GUIBET
"""
Arithmetic Expressions
"""
import hashlib
import re

P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 - 1
A = 0
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx, Gy)


def inv(a, n):
    """Inversion"""
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        r = high // low
        nm, new = hm - lm * r, high - low * r
        lm, low, hm, high = nm, new, lm, low
    return lm % n


def get_code_string(base):
    """Returns string according to base value"""
    if base == 2:
        return b'01'
    if base == 10:
        return b'0123456789'
    if base == 16:
        return b'0123456789abcdef'
    if base == 58:
        return b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    if base == 256:
        return bytes(range(256))
    raise ValueError("Invalid base!")


def encode(val, base, minlen=0):
    """Returns the encoded string"""
    code_string = get_code_string(base)
    result = b''
    while val > 0:
        val, i = divmod(val, base)
        result = code_string[i:i + 1] + result
    if len(result) < minlen:
        result = code_string[0:1] * (minlen - len(result)) + result
    return result


def decode(string, base):
    """Returns the decoded string"""
    code_string = get_code_string(base)
    result = 0
    
    # Python 3 compatibility: handle string/bytes properly
    if isinstance(string, str) and base != 256:
        # String input for non-binary bases
        string = string.encode('ascii')
    
    # Handle base 16 (hex) case
    if base == 16 and isinstance(string, bytes):
        string = string.lower()
    
    # Process each byte/character
    for char in string:
        if isinstance(char, int):  # Python 3: bytes iteration yields int
            # Directly use the integer value for base 256
            if base == 256:
                result = result * base + char
            else:
                # For other bases, find character in code_string
                try:
                    # char is int, convert to bytes
                    char_byte = bytes([char])
                    index = code_string.find(char_byte)
                    if index == -1:
                        # Try as ASCII character
                        char_str = chr(char)
                        index = code_string.find(char_str.encode('ascii'))
                    result = result * base + index
                except:
                    result = result * base + char
        else:
            # Python 2 or already bytes
            result = result * base + code_string.find(char)
    
    return result


def changebase(string, frm, to, minlen=0):
    """Change base of the string"""
    if frm == to:
        # Ensure consistent type for padding
        if isinstance(string, str):
            string = string.encode('ascii')
        return lpad(string, minlen, b'0')
    
    # Convert input to appropriate type
    if isinstance(string, str):
        if frm == 256:
            string = string.encode('latin-1')
        else:
            string = string.encode('ascii')
    
    return encode(decode(string, frm), to, minlen)


def lpad(s, n, fillchar):
    """Left pad a string/bytes"""
    if isinstance(s, bytes):
        if len(s) < n:
            s = fillchar * (n - len(s)) + s
    else:  # str
        if len(s) < n:
            s = fillchar.decode('ascii') * (n - len(s)) + s
    return s


def base10_add(a, b):
    """Adding the numbers that are of base10"""
    # pylint: disable=too-many-function-args
    if a is None:
        return b[0], b[1]
    if b is None:
        return a[0], a[1]
    if a[0] == b[0]:
        if a[1] == b[1]:
            return base10_double(a[0], a[1])
        return None
    m = ((b[1] - a[1]) * inv(b[0] - a[0], P)) % P
    x = (m * m - a[0] - b[0]) % P
    y = (m * (a[0] - x) - a[1]) % P
    return (x, y)


def base10_double(a):
    """Double the numbers that are of base10"""
    if a is None:
        return None
    m = ((3 * a[0] * a[0] + A) * inv(2 * a[1], P)) % P
    x = (m * m - 2 * a[0]) % P
    y = (m * (a[0] - x) - a[1]) % P
    return (x, y)


def base10_multiply(a, n):
    """Multiply the numbers that are of base10"""
    if n == 0:
        return G
    if n == 1:
        return a
    n, m = divmod(n, 2)
    if m == 0:
        return base10_double(base10_multiply(a, n))
    if m == 1:
        return base10_add(base10_double(base10_multiply(a, n)), a)
    return None


def hex_to_point(h):
    """Converting hexadecimal to point value"""
    return (decode(h[2:66], 16), decode(h[66:], 16))


def point_to_hex(p):
    """Converting point value to hexadecimal"""
    return b'04' + encode(p[0], 16, 64) + encode(p[1], 16, 64)


def multiply(privkey, pubkey):
    """Multiplying keys"""
    return point_to_hex(base10_multiply(
        hex_to_point(pubkey), decode(privkey, 16)))


def privtopub(privkey):
    """Converting key from private to public"""
    return point_to_hex(base10_multiply(G, decode(privkey, 16)))


def add(p1, p2):
    """Adding two public keys"""
    if len(p1) == 32:
        return encode(decode(p1, 16) + decode(p2, 16) % P, 16, 32)
    return point_to_hex(base10_add(hex_to_point(p1), hex_to_point(p2)))


def hash_160(string):
    """Hashed version of public key"""
    intermed = hashlib.sha256(string).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(intermed)
    return ripemd160.digest()


def dbl_sha256(string):
    """Double hashing (SHA256)"""
    return hashlib.sha256(hashlib.sha256(string).digest()).digest()


def bin_to_b58check(inp):
    """Convert binary to base58"""
    if isinstance(inp, str):
        inp = inp.encode('latin-1')
    
    inp_fmtd = b'\x00' + inp
    # Count leading zeros
    leadingzbytes = 0
    for b in inp_fmtd:
        if b == 0:
            leadingzbytes += 1
        else:
            break
    
    checksum = dbl_sha256(inp_fmtd)[:4]
    result = changebase(inp_fmtd + checksum, 256, 58)
    
    # Add leading '1's for each zero byte
    if isinstance(result, bytes):
        result = result.decode('ascii')
    return '1' * leadingzbytes + result


def pubkey_to_address(pubkey):
    """Convert a public key (in hex) to a Bitcoin address"""
    return bin_to_b58check(hash_160(changebase(pubkey, 16, 256)))
