"""
Operations with addresses
"""
# pylint: disable=inconsistent-return-statements

import logging
from binascii import hexlify, unhexlify
from struct import pack, unpack

try:
    from highlevelcrypto import double_sha512
except ImportError:
    from .highlevelcrypto import double_sha512


logger = logging.getLogger('default')

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def encodeBase58(num):
    """Encode a number in Base X

    Args:
      num: The number to encode
      alphabet: The alphabet to use for encoding
    """
    logger.debug("DEBUG: encodeBase58 called with num: %d", num)
    if num < 0:
        logger.debug("DEBUG: Negative number provided to encodeBase58")
        return None
    if num == 0:
        logger.debug("DEBUG: Zero provided to encodeBase58")
        return ALPHABET[0]
    arr = []
    base = len(ALPHABET)
    while num:
        num, rem = divmod(num, base)
        arr.append(ALPHABET[rem])
    arr.reverse()
    result = ''.join(arr)
    logger.debug("DEBUG: encodeBase58 result: %s", result)
    return result


def decodeBase58(string):
    """Decode a Base X encoded string into the number

    Args:
      string: The encoded string
      alphabet: The alphabet to use for encoding
    """
    logger.debug("DEBUG: decodeBase58 called with string: %s", string)
    base = len(ALPHABET)
    num = 0

    try:
        for char in string:
            num *= base
            num += ALPHABET.index(char)
    except ValueError as e:
        logger.debug("DEBUG: ValueError in decodeBase58: %s", str(e))
        # character not found (like a space character or a 0)
        return 0
    logger.debug("DEBUG: decodeBase58 result: %d", num)
    return num


class varintEncodeError(Exception):
    """Exception class for encoding varint"""
    pass


class varintDecodeError(Exception):
    """Exception class for decoding varint data"""
    pass


def encodeVarint(integer):
    """Convert integer into varint bytes"""
    logger.debug("DEBUG: encodeVarint called with integer: %d", integer)
    if integer < 0:
        logger.debug("DEBUG: Negative integer in encodeVarint")
        raise varintEncodeError('varint cannot be < 0')
    if integer < 253:
        result = pack('>B', integer)
    elif integer >= 253 and integer < 65536:
        result = pack('>B', 253) + pack('>H', integer)
    elif integer >= 65536 and integer < 4294967296:
        result = pack('>B', 254) + pack('>I', integer)
    elif integer >= 4294967296 and integer < 18446744073709551616:
        result = pack('>B', 255) + pack('>Q', integer)
    elif integer >= 18446744073709551616:
        logger.debug("DEBUG: Integer too large in encodeVarint")
        raise varintEncodeError('varint cannot be >= 18446744073709551616')
    
    logger.debug("DEBUG: encodeVarint result: %s", hexlify(result))
    return result


def decodeVarint(data):
    """
    Decodes an encoded varint to an integer and returns it.
    Per protocol v3, the encoded value must be encoded with
    the minimum amount of data possible or else it is malformed.
    Returns a tuple: (theEncodedValue, theSizeOfTheVarintInBytes)
    """
    logger.debug("DEBUG: decodeVarint called with data: %s", hexlify(data) if data else "None")

    if not data:
        logger.debug("DEBUG: Empty data in decodeVarint")
        return (0, 0)
    
    firstByte, = unpack('>B', data[0:1])
    logger.debug("DEBUG: First byte: %d", firstByte)
    
    if firstByte < 253:
        # encodes 0 to 252
        logger.debug("DEBUG: Single byte varint")
        return (firstByte, 1)  # the 1 is the length of the varint
    
    if firstByte == 253:
        # encodes 253 to 65535
        if len(data) < 3:
            logger.debug("DEBUG: Insufficient data for 2-byte varint")
            raise varintDecodeError(
                'The first byte of this varint as an integer is %s'
                ' but the total length is only %s. It needs to be'
                ' at least 3.' % (firstByte, len(data)))
        encodedValue, = unpack('>H', data[1:3])
        if encodedValue < 253:
            logger.debug("DEBUG: Non-minimal varint encoding")
            raise varintDecodeError(
                'This varint does not encode the value with the lowest'
                ' possible number of bytes.')
        logger.debug("DEBUG: 2-byte varint value: %d", encodedValue)
        return (encodedValue, 3)
    
    if firstByte == 254:
        # encodes 65536 to 4294967295
        if len(data) < 5:
            logger.debug("DEBUG: Insufficient data for 4-byte varint")
            raise varintDecodeError(
                'The first byte of this varint as an integer is %s'
                ' but the total length is only %s. It needs to be'
                ' at least 5.' % (firstByte, len(data)))
        encodedValue, = unpack('>I', data[1:5])
        if encodedValue < 65536:
            logger.debug("DEBUG: Non-minimal varint encoding")
            raise varintDecodeError(
                'This varint does not encode the value with the lowest'
                ' possible number of bytes.')
        logger.debug("DEBUG: 4-byte varint value: %d", encodedValue)
        return (encodedValue, 5)
    
    if firstByte == 255:
        # encodes 4294967296 to 18446744073709551615
        if len(data) < 9:
            logger.debug("DEBUG: Insufficient data for 8-byte varint")
            raise varintDecodeError(
                'The first byte of this varint as an integer is %s'
                ' but the total length is only %s. It needs to be'
                ' at least 9.' % (firstByte, len(data)))
        encodedValue, = unpack('>Q', data[1:9])
        if encodedValue < 4294967296:
            logger.debug("DEBUG: Non-minimal varint encoding")
            raise varintDecodeError(
                'This varint does not encode the value with the lowest'
                ' possible number of bytes.')
        logger.debug("DEBUG: 8-byte varint value: %d", encodedValue)
        return (encodedValue, 9)


def encodeAddress(version, stream, ripe):
    """Convert ripe to address"""
    logger.debug("DEBUG: encodeAddress called with version: %d, stream: %d, ripe: %s", 
                version, stream, hexlify(ripe))
    
    if version >= 2 and version < 4:
        if len(ripe) != 20:
            logger.debug("DEBUG: Invalid RIPE length for version %d", version)
            raise Exception(
                'Programming error in encodeAddress: The length of'
                ' a given ripe hash was not 20.'
            )

        if ripe[:2] == b'\x00\x00':
            ripe = ripe[2:]
            logger.debug("DEBUG: Stripped 2 NULL bytes from RIPE")
        elif ripe[:1] == b'\x00':
            ripe = ripe[1:]
            logger.debug("DEBUG: Stripped 1 NULL byte from RIPE")
    elif version == 4:
        if len(ripe) != 20:
            logger.debug("DEBUG: Invalid RIPE length for version 4")
            raise Exception(
                'Programming error in encodeAddress: The length of'
                ' a given ripe hash was not 20.')
        ripe = ripe.lstrip(b'\x00')
        logger.debug("DEBUG: Stripped leading NULL bytes from RIPE for version 4")

    storedBinaryData = encodeVarint(version) + encodeVarint(stream) + ripe
    logger.debug("DEBUG: Stored binary data: %s", hexlify(storedBinaryData))

    # Generate the checksum
    checksum = double_sha512(storedBinaryData)[0:4]
    logger.debug("DEBUG: Generated checksum: %s", hexlify(checksum))

    # FIXME: encodeBase58 should take binary data, to reduce conversions
    # encodeBase58(storedBinaryData + checksum)
    asInt = int(hexlify(storedBinaryData) + hexlify(checksum), 16)
    address = 'BM-' + encodeBase58(asInt)
    logger.debug("DEBUG: Generated address: %s", address)
    return address


def decodeAddress(address):
    """
    returns (status, address version number, stream number,
    data (almost certainly a ripe hash))
    """
    # pylint: disable=too-many-return-statements,too-many-statements
    # pylint: disable=too-many-branches
    
    logger.debug("DEBUG: decodeAddress called with address: %s", address)
    address = str(address).strip()

    if address[:3] == 'BM-':
        logger.debug("DEBUG: Address has BM- prefix")
        integer = decodeBase58(address[3:])
    else:
        logger.debug("DEBUG: Address does not have BM- prefix")
        integer = decodeBase58(address)
    
    if integer == 0:
        logger.debug("DEBUG: Invalid characters in address")
        status = 'invalidcharacters'
        return status, 0, 0, b''
    
    # after converting to hex, the string will be prepended
    # with a 0x and appended with a L in python2
    hexdata = hex(integer)[2:].rstrip('L')
    logger.debug("DEBUG: Hex data: %s", hexdata)

    if len(hexdata) % 2 != 0:
        hexdata = '0' + hexdata
        logger.debug("DEBUG: Padded hex data: %s", hexdata)

    data = unhexlify(hexdata)
    logger.debug("DEBUG: Unhexlified data: %s", hexlify(data))
    
    checksum = data[-4:]
    logger.debug("DEBUG: Extracted checksum: %s", hexlify(checksum))
    
    calculated_checksum = double_sha512(data[:-4])[0:4]
    logger.debug("DEBUG: Calculated checksum: %s", hexlify(calculated_checksum))
    
    if checksum != calculated_checksum:
        logger.debug("DEBUG: Checksum mismatch")
        status = 'checksumfailed'
        return status, 0, 0, b''

    try:
        addressVersionNumber, bytesUsedByVersionNumber = decodeVarint(data[:9])
        logger.debug("DEBUG: Decoded version: %d, bytes used: %d", 
                    addressVersionNumber, bytesUsedByVersionNumber)
    except varintDecodeError as e:
        logger.error("DEBUG: Varint decode error for version: %s", str(e))
        status = 'varintmalformed'
        return status, 0, 0, b''

    if addressVersionNumber > 4:
        logger.error('DEBUG: Address version too high: %d', addressVersionNumber)
        status = 'versiontoohigh'
        return status, 0, 0, b''
    elif addressVersionNumber == 0:
        logger.error('DEBUG: Address version cannot be zero')
        status = 'versiontoohigh'
        return status, 0, 0, b''

    try:
        streamNumber, bytesUsedByStreamNumber = \
            decodeVarint(data[bytesUsedByVersionNumber:])
        logger.debug("DEBUG: Decoded stream: %d, bytes used: %d", 
                    streamNumber, bytesUsedByStreamNumber)
    except varintDecodeError as e:
        logger.error("DEBUG: Varint decode error for stream: %s", str(e))
        status = 'varintmalformed'
        return status, 0, 0, b''

    status = 'success'
    ripeDataStart = bytesUsedByVersionNumber + bytesUsedByStreamNumber
    embeddedRipeData = data[ripeDataStart:-4]
    logger.debug("DEBUG: Embedded RIPE data: %s (length: %d)", 
                hexlify(embeddedRipeData), len(embeddedRipeData))
    
    if addressVersionNumber == 1:
        logger.debug("DEBUG: Version 1 address")
        return status, addressVersionNumber, streamNumber, data[-24:-4]
    elif addressVersionNumber == 2 or addressVersionNumber == 3:
        logger.debug("DEBUG: Version %d address", addressVersionNumber)
        if len(embeddedRipeData) == 19:
            return status, addressVersionNumber, streamNumber, \
                b'\x00' + embeddedRipeData
        elif len(embeddedRipeData) == 20:
            return status, addressVersionNumber, streamNumber, \
                embeddedRipeData
        elif len(embeddedRipeData) == 18:
            return status, addressVersionNumber, streamNumber, \
                b'\x00\x00' + embeddedRipeData
        elif len(embeddedRipeData) < 18:
            logger.debug("DEBUG: RIPE data too short")
            return 'ripetooshort', 0, 0, b''
        elif len(embeddedRipeData) > 20:
            logger.debug("DEBUG: RIPE data too long")
            return 'ripetoolong', 0, 0, b''
        logger.debug("DEBUG: Unknown problem with RIPE data")
        return 'otherproblem', 0, 0, b''
    elif addressVersionNumber == 4:
        logger.debug("DEBUG: Version 4 address")
        if embeddedRipeData[0:1] == b'\x00':
            logger.debug("DEBUG: Leading NULL in version 4 RIPE data")
            return 'encodingproblem', 0, 0, b''
        elif len(embeddedRipeData) > 20:
            logger.debug("DEBUG: RIPE data too long for version 4")
            return 'ripetoolong', 0, 0, b''
        elif len(embeddedRipeData) < 4:
            logger.debug("DEBUG: RIPE data too short for version 4")
            return 'ripetooshort', 0, 0, b''
        x00string = b'\x00' * (20 - len(embeddedRipeData))
        return status, addressVersionNumber, streamNumber, \
            x00string + embeddedRipeData


def addBMIfNotPresent(address):
    """Prepend BM- to an address if it doesn't already have it"""
    logger.debug("DEBUG: addBMIfNotPresent called with address: %s", address)
    address = str(address).strip()
    result = address if address[:3] == 'BM-' else 'BM-' + address
    logger.debug("DEBUG: addBMIfNotPresent result: %s", result)
    return result
