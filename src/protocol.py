"""
Low-level protocol-related functions.
"""
# pylint: disable=too-many-boolean-expressions,too-many-return-statements
# pylint: disable=too-many-locals,too-many-statements

import base64
import hashlib
import random
import socket
import sys
import time
from binascii import hexlify
from struct import Struct, pack, unpack
import six
import sqlite3
import logging
import defaults
import highlevelcrypto
import state
from addresses import (
    encodeVarint, decodeVarint, decodeAddress, varintDecodeError)
from bmconfigparser import config
from debug import logger
from helper_sql import sqlExecute
from network.node import Peer
from version import softwareVersion
from dbcompat import dbstr

# Network constants
magic = 0xE9BEB4D9
#: protocol specification says max 1000 addresses in one addr command
MAX_ADDR_COUNT = 1000
#: address is online if online less than this many seconds ago
ADDRESS_ALIVE = 10800
#: ~1.6 MB which is the maximum possible size of an inv message.
MAX_MESSAGE_SIZE = 1600100
#: 2**18 = 256kB is the maximum size of an object payload
MAX_OBJECT_PAYLOAD_SIZE = 2**18
#: protocol specification says max 50000 objects in one inv command
MAX_OBJECT_COUNT = 50000
#: maximum time offset
MAX_TIME_OFFSET = 3600

# Service flags
#: This is a normal network node
NODE_NETWORK = 1
#: This node supports SSL/TLS in the current connect (python < 2.7.9
#: only supports an SSL client, so in that case it would only have this
#: on when the connection is a client).
NODE_SSL = 2
# (Proposal) This node may do PoW on behalf of some its peers
# (PoW offloading/delegating), but it doesn't have to. Clients may have
# to meet additional requirements (e.g. TLS authentication)
# NODE_POW = 4
#: Node supports dandelion
NODE_DANDELION = 8

# Bitfield flags
BITFIELD_DOESACK = 1

# Error types
STATUS_WARNING = 0
STATUS_ERROR = 1
STATUS_FATAL = 2

# Object types
OBJECT_GETPUBKEY = 0
OBJECT_PUBKEY = 1
OBJECT_MSG = 2
OBJECT_BROADCAST = 3
OBJECT_ONIONPEER = 0x746f72
OBJECT_I2P = 0x493250
OBJECT_ADDR = 0x61646472

eightBytesOfRandomDataUsedToDetectConnectionsToSelf = pack(
    '>Q', random.randrange(1, 18446744073709551615))  # nosec B311

# Compiled struct for packing/unpacking headers
# New code should use CreatePacket instead of Header.pack
Header = Struct('!L12sL4s')

VersionPacket = Struct('>LqQ20s4s36sH')

# Bitfield


def getBitfield(address):
    """Get a bitfield from an address"""
    # bitfield of features supported by me (see the wiki).
    bitfield = 0
    # send ack
    if not config.safeGetBoolean(address, 'dontsendack'):
        bitfield |= BITFIELD_DOESACK
    return pack('>I', bitfield)


def checkBitfield(bitfieldBinary, flags):
    """Check if a bitfield matches the given flags"""
    bitfield, = unpack('>I', bitfieldBinary)
    return (bitfield & flags) == flags


def isBitSetWithinBitfield(fourByteString, n):
    """Check if a particular bit is set in a bitfeld"""
    # Uses MSB 0 bit numbering across 4 bytes of data
    n = 31 - n
    x, = unpack('>L', fourByteString)
    return x & 2**n != 0

# Streams


MIN_VALID_STREAM = 1
MAX_VALID_STREAM = 2**63 - 1

# IP addresses


def encodeHost(host):
    """Encode a given host to be used in low-level socket operations"""
    if host.endswith('.onion'):
        return b'\xfd\x87\xd8\x7e\xeb\x43' + base64.b32decode(
            host.split(".")[0], True)
    elif host.find(':') == -1:
        return b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF' + \
            socket.inet_aton(host)
    return socket.inet_pton(socket.AF_INET6, host)


def networkType(host):
    """Determine if a host is IPv4, IPv6 or an onion address"""
    if host.endswith('.onion'):
        return 'onion'
    elif host.find(':') == -1:
        return 'IPv4'
    return 'IPv6'


def network_group(host):
    """Canonical identifier of network group
       simplified, borrowed from
       GetGroup() in src/netaddresses.cpp in bitcoin core"""
    if not isinstance(host, str):
        return None
    network_type = networkType(host)
    try:
        raw_host = encodeHost(host)
    except socket.error:
        return host
    if network_type == 'IPv4':
        decoded_host = checkIPv4Address(raw_host[12:], True)
        if decoded_host:
            # /16 subnet
            return raw_host[12:14]
    elif network_type == 'IPv6':
        decoded_host = checkIPv6Address(raw_host, True)
        if decoded_host:
            # /32 subnet
            return raw_host[0:12]
    else:
        # just host, e.g. for tor
        return host
    # global network type group for local, private, unroutable
    return network_type


def checkIPAddress(host, private=False):
    """
    Returns hostStandardFormat if it is a valid IP address,
    otherwise returns False
    """
    if host[0:12] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF':
        hostStandardFormat = socket.inet_ntop(socket.AF_INET, bytes(host[12:]))
        return checkIPv4Address(host[12:], hostStandardFormat, private)
    elif host[0:6] == b'\xfd\x87\xd8\x7e\xeb\x43':
        # Onion, based on BMD/bitcoind
        hostStandardFormat = base64.b32encode(host[6:]).lower() + b".onion"
        if private:
            return False
        return hostStandardFormat
    else:
        try:
            hostStandardFormat = socket.inet_ntop(socket.AF_INET6, host)
        except ValueError:
            return False
        if len(hostStandardFormat) == 0:
            # This can happen on Windows systems which are
            # not 64-bit compatible so let us drop the IPv6 address.
            return False
        return checkIPv6Address(host, hostStandardFormat, private)


def checkIPv4Address(host, hostStandardFormat, private=False):
    """
    Returns hostStandardFormat if it is an IPv4 address,
    otherwise returns False
    """
    if host[0:1] == b'\x7F':  # 127/8
        if not private:
            logger.debug(
                'Ignoring IP address in loopback range: %s',
                hostStandardFormat)
        return hostStandardFormat if private else False
    if host[0:1] == b'\x0A':  # 10/8
        if not private:
            logger.debug(
                'Ignoring IP address in private range: %s', hostStandardFormat)
        return hostStandardFormat if private else False
    if host[0:2] == b'\xC0\xA8':  # 192.168/16
        if not private:
            logger.debug(
                'Ignoring IP address in private range: %s', hostStandardFormat)
        return hostStandardFormat if private else False
    if host[0:2] >= b'\xAC\x10' and host[0:2] < b'\xAC\x20':  # 172.16/12
        if not private:
            logger.debug(
                'Ignoring IP address in private range: %s', hostStandardFormat)
        return hostStandardFormat if private else False
    return False if private else hostStandardFormat


def checkIPv6Address(host, hostStandardFormat, private=False):
    """
    Returns hostStandardFormat if it is an IPv6 address,
    otherwise returns False
    """
    if host == b'\x00' * 15 + b'\x01':
        if not private:
            logger.debug('Ignoring loopback address: %s', hostStandardFormat)
        return False
    try:
        host = [six.byte2int(c) for c in host[:2]]
    except TypeError:  # python3 has ints already
        pass
    if host[0] == 0xfe and host[1] & 0xc0 == 0x80:
        if not private:
            logger.debug('Ignoring local address: %s', hostStandardFormat)
        return hostStandardFormat if private else False
    if host[0] & 0xfe == 0xfc:
        if not private:
            logger.debug(
                'Ignoring unique local address: %s', hostStandardFormat)
        return hostStandardFormat if private else False
    return False if private else hostStandardFormat


def haveSSL(server=False):
    """
    Predicate to check if ECDSA server support is required and available

    python < 2.7.9's ssl library does not support ECDSA server due to
    missing initialisation of available curves, but client works ok
    """
    if not server:
        return True
    elif sys.version_info >= (2, 7, 9):
        return True
    return False


def checkSocksIP(host):
    """Predicate to check if we're using a SOCKS proxy"""
    sockshostname = config.safeGet(
        'bitmessagesettings', 'sockshostname')
    try:
        if not state.socksIP:
            state.socksIP = socket.gethostbyname(sockshostname)
    except NameError:  # uninitialised
        state.socksIP = socket.gethostbyname(sockshostname)
    except (TypeError, socket.gaierror):  # None, resolving failure
        state.socksIP = sockshostname
    return state.socksIP == host


def isProofOfWorkSufficient(
        data, nonceTrialsPerByte=0, payloadLengthExtraBytes=0, recvTime=0):
    """
    Validate an object's Proof of Work using method described
    :doc:`here </pow>`

    Arguments:
        int nonceTrialsPerByte (default: from `.defaults`)
        int payloadLengthExtraBytes (default: from `.defaults`)
        float recvTime (optional) UNIX epoch time when object was
          received from the network (default: current system time)
    Returns:
        True if PoW valid and sufficient, False in all other cases
    """
    if nonceTrialsPerByte < defaults.networkDefaultProofOfWorkNonceTrialsPerByte:
        nonceTrialsPerByte = defaults.networkDefaultProofOfWorkNonceTrialsPerByte
    if payloadLengthExtraBytes < defaults.networkDefaultPayloadLengthExtraBytes:
        payloadLengthExtraBytes = defaults.networkDefaultPayloadLengthExtraBytes
    endOfLifeTime, = unpack('>Q', data[8:16])
    TTL = endOfLifeTime - int(recvTime if recvTime else time.time())
    if TTL < 300:
        TTL = 300
    POW, = unpack('>Q', highlevelcrypto.double_sha512(
        bytes(data[:8]) + hashlib.sha512(data[8:]).digest())[0:8])
    return POW <= 2 ** 64 / (
        nonceTrialsPerByte * (
            len(data) + payloadLengthExtraBytes
            + ((TTL * (len(data) + payloadLengthExtraBytes)) / (2 ** 16))))


# Packet creation


def CreatePacket(command, payload=b''):
    """Construct and return a packet"""
    payload_length = len(payload)
    
    # PYTHON 3 FIX: Ensure payload is bytes before hashing
    if isinstance(payload, str):
        payload = payload.encode('utf-8')
    elif isinstance(payload, bytearray):
        payload = bytes(payload)
    
    checksum = hashlib.sha512(payload).digest()[0:4]

    b = bytearray(Header.size + payload_length)
    Header.pack_into(b, 0, magic, command, payload_length, checksum)
    b[Header.size:] = payload
    return bytes(b)


def assembleAddrMessage(peerList):
    """Create address command"""
    if isinstance(peerList, Peer):
        peerList = [peerList]
    if not peerList:
        return b''
    retval = b''
    for i in range(0, len(peerList), MAX_ADDR_COUNT):
        payload = encodeVarint(len(peerList[i:i + MAX_ADDR_COUNT]))
        for stream, peer, timestamp in peerList[i:i + MAX_ADDR_COUNT]:
            # 64-bit time
            payload += pack('>Q', timestamp)
            payload += pack('>I', stream)
            # service bit flags offered by this node
            payload += pack('>q', 1)
            payload += encodeHost(peer.host)
            # remote port
            payload += pack('>H', peer.port)
        retval += CreatePacket(b'addr', payload)
    return retval


def assembleVersionMessage(  # pylint: disable=too-many-arguments
    remoteHost, remotePort, participatingStreams, dandelion_enabled=True, server=False, nodeid=None,
):
    """
    Construct the payload of a version message,
    return the resulting bytes of running `CreatePacket` on it
    """
    payload = b''
    payload += pack('>L', 3)  # protocol version.
    # bitflags of the services I offer.
    payload += pack(
        '>q',
        NODE_NETWORK
        | (NODE_SSL if haveSSL(server) else 0)
        | (NODE_DANDELION if dandelion_enabled else 0)
    )
    payload += pack('>q', int(time.time()))

    # boolservices of remote connection; ignored by the remote host.
    payload += pack('>q', 1)
    if checkSocksIP(remoteHost) and server:
        # prevent leaking of tor outbound IP
        payload += encodeHost('127.0.0.1')
        payload += pack('>H', 8444)
    else:
        # use first 16 bytes if host data is longer
        # for example in case of onion v3 service
        try:
            payload += encodeHost(remoteHost)[:16]
        except socket.error:
            payload += encodeHost('127.0.0.1')
        payload += pack('>H', remotePort)  # remote IPv6 and port

    # bitflags of the services I offer.
    payload += pack(
        '>q',
        NODE_NETWORK
        | (NODE_SSL if haveSSL(server) else 0)
        | (NODE_DANDELION if dandelion_enabled else 0)
    )
    # = 127.0.0.1. This will be ignored by the remote host.
    # The actual remote connected IP will be used.
    payload += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF' + pack(
        '>L', 2130706433)
    # we have a separate extPort and incoming over clearnet
    # or outgoing through clearnet
    extport = config.safeGetInt('bitmessagesettings', 'extport')
    if (
        extport and ((server and not checkSocksIP(remoteHost)) or (
            config.get('bitmessagesettings', 'socksproxytype')
            == 'none' and not server))
    ):
        payload += pack('>H', extport)
    elif checkSocksIP(remoteHost) and server:  # incoming connection over Tor
        payload += pack(
            '>H', config.getint('bitmessagesettings', 'onionport'))
    else:  # no extport and not incoming over Tor
        payload += pack(
            '>H', config.getint('bitmessagesettings', 'port'))

    if nodeid is not None:
        payload += nodeid[0:8]
    else:
        payload += eightBytesOfRandomDataUsedToDetectConnectionsToSelf
    userAgent = ('/PyBitmessage:%s/' % softwareVersion).encode('utf-8')
    payload += encodeVarint(len(userAgent))
    payload += userAgent

    # Streams
    payload += encodeVarint(len(participatingStreams))
    count = 0
    for stream in sorted(participatingStreams):
        payload += encodeVarint(stream)
        count += 1
        # protocol limit, see specification
        if count >= 160000:
            break

    return CreatePacket(b'version', payload)


def assembleErrorMessage(fatal=0, banTime=0, inventoryVector=b'', errorText=''):
    """
    Construct the payload of an error message,
    return the resulting bytes of running `CreatePacket` on it
    """
    payload = encodeVarint(fatal)
    payload += encodeVarint(banTime)
    payload += encodeVarint(len(inventoryVector))
    payload += inventoryVector
    if isinstance(errorText, str):
        errorText = errorText.encode("utf-8", "replace")
    payload += encodeVarint(len(errorText))
    payload += errorText
    return CreatePacket(b'error', payload)


# Packet decoding

def decodeObjectParameters(data):
    """Decode the parameters of a raw object needed to put it in inventory"""
    # BMProto.decode_payload_content("QQIvv")
    # Konvertiere zu bytes falls bytearray
    if isinstance(data, bytearray):
        data = bytes(data)
    
    expiresTime = unpack('>Q', data[8:16])[0]
    objectType = unpack('>I', data[16:20])[0]
    parserPos = 20 + decodeVarint(data[20:30])[1]
    toStreamNumber = decodeVarint(data[parserPos:parserPos + 10])[0]

    return objectType, toStreamNumber, expiresTime


def decryptAndCheckPubkeyPayload(data, address):
    """
    Version 4 pubkeys are encrypted. This function is run when we
    already have the address to which we want to try to send a message.
    The 'data' may come either off of the wire or we might have had it
    already in our inventory when we tried to send a msg to this
    particular address.
    
    EXTENSIVE DEBUG VERSION FOR PYTHON 3
    """
    
    print("\n" + "="*100)
    print("🔍 DEBUG: decryptAndCheckPubkeyPayload START")
    print(f"  Address: {address}")
    print(f"  Data type: {type(data)}, length: {len(data)}")
    print("="*100)
    
    try:
        # 1. ADDRESS DECODING
        print(f"\n📋 [1] ADDRESS DECODING:")
        print(f"  Input address: {address}")
        
        decode_result = decodeAddress(address)
        print(f"  decodeAddress result: {decode_result}")
        print(f"  decodeAddress result type: {type(decode_result)}")
        print(f"  decodeAddress result length: {len(decode_result)}")
        
        if decode_result[0] != 'success':
            print(f"  ❌ Address decode failed: {decode_result[0]}")
            return 'failed'
            
        addressVersion, streamNumber, ripe = decode_result[1:]
        print(f"  ✅ Decoded successfully:")
        print(f"    Version: {addressVersion}")
        print(f"    Stream: {streamNumber}")
        print(f"    RIPE type: {type(ripe)}, length: {len(ripe)}")
        print(f"    RIPE hex: {hexlify(ripe)}")
        
        # 2. INITIAL DATA PARSING
        print(f"\n📋 [2] INITIAL DATA PARSING:")
        print(f"  Data length: {len(data)} bytes")
        print(f"  First 50 bytes hex: {hexlify(data[:50])}")
        
        readPosition = 20  # bypass the nonce (8), time (8), and object type (4)
        print(f"  Start readPosition: {readPosition}")
        
        # Embedded address version
        embeddedAddressVersion, varintLength = decodeVarint(
            data[readPosition:readPosition + 10])
        print(f"  embeddedAddressVersion: {embeddedAddressVersion}, varintLength: {varintLength}")
        readPosition += varintLength
        
        # Embedded stream number
        embeddedStreamNumber, varintLength = decodeVarint(
            data[readPosition:readPosition + 10])
        print(f"  embeddedStreamNumber: {embeddedStreamNumber}, varintLength: {varintLength}")
        readPosition += varintLength
        
        # Version/Stream validation
        print(f"\n📋 [3] VERSION/STREAM VALIDATION:")
        print(f"  Expected: Version={addressVersion}, Stream={streamNumber}")
        print(f"  Actual:   Version={embeddedAddressVersion}, Stream={embeddedStreamNumber}")
        
        if addressVersion != embeddedAddressVersion:
            print(f"  ❌ VERSION MISMATCH!")
            return 'failed'
        if streamNumber != embeddedStreamNumber:
            print(f"  ❌ STREAM MISMATCH!")
            return 'failed'
        
        print(f"  ✅ Version/Stream match OK")
        
        storedData = data[20:readPosition]
        print(f"  storedData type: {type(storedData)}, length: {len(storedData)}")
        
        # 3. TAG EXTRACTION
        print(f"\n📋 [4] TAG EXTRACTION:")
        print(f"  Current readPosition: {readPosition}")
        
        tag = data[readPosition:readPosition + 32]
        print(f"  tag type: {type(tag)}, length: {len(tag)}")
        print(f"  tag hex: {hexlify(tag)}")
        readPosition += 32
        
        # Python 3 CRITICAL: tag is bytes, but neededPubkeys might have different key types
        tag_bytes = bytes(tag)
        print(f"  tag_bytes type: {type(tag_bytes)}")
        
        signedData = data[8:readPosition]
        encryptedData = data[readPosition:]
        
        print(f"  signedData length: {len(signedData)}")
        print(f"  encryptedData length: {len(encryptedData)}")
        print(f"  encryptedData first 50 bytes: {hexlify(encryptedData[:50])}")
        
        # 4. NEEDEDPUBKEYS LOOKUP
        print(f"\n📋 [5] NEEDEDPUBKEYS LOOKUP:")
        print(f"  State.neededPubkeys size: {len(state.neededPubkeys)}")
        
        # Try multiple key types
        found = False
        cryptorObject = None
        toAddress = None
        
        # List all keys in neededPubkeys for debugging
        print(f"  All keys in neededPubkeys (first 5):")
        keys_list = list(state.neededPubkeys.keys())
        for i, key in enumerate(keys_list[:5]):
            print(f"    [{i}] Key type: {type(key)}, value: {key}")
            if isinstance(key, bytes):
                print(f"         Hex: {hexlify(key)}")
        
        # Try different key representations
        possible_keys = []
        
        # 1. Direct bytes
        possible_keys.append(tag_bytes)
        print(f"  Trying key type 1: bytes, hex: {hexlify(tag_bytes)}")
        
        # 2. Hex string (common in Python 2/3 mix)
        tag_hex = hexlify(tag_bytes).decode('ascii')
        possible_keys.append(tag_hex)
        print(f"  Trying key type 2: hex string, value: {tag_hex}")
        
        # 3. Latin-1 decoded string
        try:
            tag_latin1 = tag_bytes.decode('latin-1')
            possible_keys.append(tag_latin1)
            print(f"  Trying key type 3: latin-1 string, value: {repr(tag_latin1)}")
        except:
            print(f"  Cannot decode tag as latin-1")
            
        # 4. Raw bytes as memoryview (if neededPubkeys uses memoryview)
        try:
            tag_memoryview = memoryview(tag_bytes)
            possible_keys.append(tag_memoryview)
            print(f"  Trying key type 4: memoryview")
        except:
            pass
        
        for key in possible_keys:
            if key in state.neededPubkeys:
                toAddress, cryptorObject = state.neededPubkeys[key]
                found = True
                print(f"  ✅ FOUND in neededPubkeys with key type: {type(key)}")
                print(f"     toAddress: {toAddress}")
                print(f"     cryptorObject type: {type(cryptorObject)}")
                break
        
        if not found:
            print(f"  ❌ TAG NOT FOUND in neededPubkeys!")
            print(f"  Tag hex we're looking for: {hexlify(tag_bytes)}")
            print(f"  Tag hex as string: {tag_hex}")
            return 'failed'
        
        # Address comparison
        print(f"\n📋 [6] ADDRESS COMPARISON:")
        print(f"  Expected address: {address}")
        print(f"  Found address: {toAddress}")
        
        if toAddress != address:
            print(f"  ❌ ADDRESS MISMATCH!")
            return 'failed'
        
        print(f"  ✅ Address match OK")
        
        # 5. DECRYPTION
        print(f"\n📋 [7] DECRYPTION ATTEMPT:")
        print(f"  encryptedData type: {type(encryptedData)}, length: {len(encryptedData)}")
        print(f"  cryptorObject type: {type(cryptorObject)}")
        
        try:
            decryptedData = cryptorObject.decrypt(encryptedData)
            print(f"  ✅ Decryption successful!")
            print(f"  decryptedData type: {type(decryptedData)}, length: {len(decryptedData)}")
            print(f"  First 100 bytes hex: {hexlify(decryptedData[:100])}")
        except Exception as e:
            print(f"  ❌ Decryption failed: {e}")
            print(f"  Error type: {type(e)}")
            import traceback
            traceback.print_exc()
            return 'failed'
        
        # 6. DECRYPTED DATA PARSING
        print(f"\n📋 [8] DECRYPTED DATA PARSING:")
        
        # Ensure decryptedData is bytes
        if isinstance(decryptedData, str):
            print(f"  WARNING: decryptedData is string, converting to bytes")
            decryptedData = decryptedData.encode('latin-1')
        elif isinstance(decryptedData, bytearray):
            decryptedData = bytes(decryptedData)
        
        print(f"  Final decryptedData type: {type(decryptedData)}")
        
        readPosition = 0
        
        # Bitfield (4 bytes)
        bitfieldBehaviors = decryptedData[readPosition:readPosition + 4]
        print(f"  bitfieldBehaviors: {hexlify(bitfieldBehaviors)}")
        readPosition += 4
        
        # Public Signing Key (64 bytes + 1 byte prefix)
        pubSigningKey_raw = decryptedData[readPosition:readPosition + 64]
        print(f"  pubSigningKey_raw (64 bytes): {hexlify(pubSigningKey_raw)}")
        
        # CRITICAL FIX: Python 3 needs bytes, not string
        pubSigningKey = b'\x04' + pubSigningKey_raw
        print(f"  pubSigningKey (with 0x04 prefix): {hexlify(pubSigningKey)}")
        print(f"  pubSigningKey type: {type(pubSigningKey)}, length: {len(pubSigningKey)}")
        readPosition += 64
        
        # Public Encryption Key (64 bytes + 1 byte prefix)
        pubEncryptionKey_raw = decryptedData[readPosition:readPosition + 64]
        pubEncryptionKey = b'\x04' + pubEncryptionKey_raw
        print(f"  pubEncryptionKey (with 0x04 prefix): {hexlify(pubEncryptionKey[:20])}...")
        readPosition += 64
        
        # Nonce trials per byte
        specifiedNonceTrialsPerByte, varintLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        print(f"  specifiedNonceTrialsPerByte: {specifiedNonceTrialsPerByte}")
        readPosition += varintLength
        
        # Payload length extra bytes
        specifiedPayloadLengthExtraBytes, varintLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        print(f"  specifiedPayloadLengthExtraBytes: {specifiedPayloadLengthExtraBytes}")
        readPosition += varintLength
        
        # Update stored and signed data
        storedData += decryptedData[:readPosition]
        signedData += decryptedData[:readPosition]
        
        print(f"  signedData final length: {len(signedData)}")
        
        # 7. SIGNATURE
        print(f"\n📋 [9] SIGNATURE:")
        
        signatureLength, varintLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        print(f"  signatureLength: {signatureLength}")
        readPosition += varintLength
        
        signature = decryptedData[readPosition:readPosition + signatureLength]
        print(f"  signature type: {type(signature)}, length: {len(signature)}")
        print(f"  signature hex (first 50): {hexlify(signature[:50])}")
        
        # 8. ECDSA VERIFICATION
        print(f"\n📋 [10] ECDSA VERIFICATION:")
        print(f"  signedData type: {type(signedData)}, length: {len(signedData)}")
        print(f"  signature type: {type(signature)}")
        
        # Convert pubSigningKey to hex string for highlevelcrypto.verify
        pubSigningKeyHex = hexlify(pubSigningKey).decode('ascii')
        print(f"  pubSigningKeyHex type: {type(pubSigningKeyHex)}, length: {len(pubSigningKeyHex)}")
        print(f"  pubSigningKeyHex (first 100): {pubSigningKeyHex[:100]}")
        
        # Try verification with bytes signature first
        print(f"\n  Attempt 1: signature as bytes")
        verify_result = highlevelcrypto.verify(
            signedData, 
            signature, 
            pubSigningKeyHex
        )
        print(f"    Result: {verify_result}")
        
        if not verify_result:
            # Try with signature as hex string
            print(f"\n  Attempt 2: signature as hex string")
            signature_hex = hexlify(signature).decode('ascii')
            verify_result = highlevelcrypto.verify(
                signedData,
                signature_hex,
                pubSigningKeyHex
            )
            print(f"    Result: {verify_result}")
        
        if not verify_result:
            print(f"  ❌ ECDSA VERIFICATION FAILED!")
            return 'failed'
        
        print(f"  ✅ ECDSA verification passed!")
        
        # 9. RIPE CALCULATION AND COMPARISON
        print(f"\n📋 [11] RIPE CALCULATION & COMPARISON:")
        print(f"  pubSigningKey type: {type(pubSigningKey)}, length: {len(pubSigningKey)}")
        print(f"  pubEncryptionKey type: {type(pubEncryptionKey)}, length: {len(pubEncryptionKey)}")
        
        # Call highlevelcrypto.to_ripe
        print(f"  Calling highlevelcrypto.to_ripe()...")
        embeddedRipe = highlevelcrypto.to_ripe(pubSigningKey, pubEncryptionKey)
        print(f"  embeddedRipe type: {type(embeddedRipe)}, length: {len(embeddedRipe)}")
        print(f"  embeddedRipe hex: {hexlify(embeddedRipe)}")
        
        print(f"\n  RIPE COMPARISON:")
        print(f"  Expected RIPE (from address): {hexlify(ripe)}")
        print(f"  Calculated RIPE (from keys):   {hexlify(embeddedRipe)}")
        
        if embeddedRipe != ripe:
            print(f"\n  ❌ RIPE MISMATCH!")
            print(f"  Expected: {hexlify(ripe)}")
            print(f"  Got:      {hexlify(embeddedRipe)}")
            print(f"  Equal? {embeddedRipe == ripe}")
            
            # Debug the actual bytes
            print(f"\n  Byte-by-byte comparison:")
            ripe_bytes = bytes(ripe) if not isinstance(ripe, bytes) else ripe
            embedded_bytes = bytes(embeddedRipe) if not isinstance(embeddedRipe, bytes) else embeddedRipe
            
            if len(ripe_bytes) != len(embedded_bytes):
                print(f"    Length mismatch: {len(ripe_bytes)} vs {len(embedded_bytes)}")
            else:
                for i in range(min(len(ripe_bytes), len(embedded_bytes))):
                    if ripe_bytes[i] != embedded_bytes[i]:
                        print(f"    Byte {i}: Expected {ripe_bytes[i]:02x}, Got {embedded_bytes[i]:02x}")
            
            return 'failed'
        
        print(f"  ✅ RIPE match OK!")
        
        # 10. DATABASE INSERTION
        print(f"\n📋 [12] DATABASE INSERTION:")
        print(f"  Address: {address}")
        print(f"  AddressVersion: {addressVersion}")
        print(f"  storedData type: {type(storedData)}, length: {len(storedData)}")
        print(f"  storedData hex (first 50): {hexlify(storedData[:50])}")
        
        t = (address, addressVersion, sqlite3.Binary(storedData), 
             int(time.time()), 'yes')
        
        print(f"  Executing SQL INSERT...")
        sqlExecute('''INSERT INTO pubkeys VALUES (?,?,?,?,?)''', *t)
        
        print(f"\n✅ SUCCESS! Pubkey decryption and verification complete!")
        print(f"  Pubkey stored for address: {address}")
        
        return 'successful'
        
    except varintDecodeError as e:
        print(f"\n❌ VARINT DECODE ERROR: {e}")
        print(f"  readPosition at error: {readPosition}")
        return 'failed'
    except Exception as e:
        print(f"\n❌ UNHANDLED EXCEPTION: {type(e).__name__}: {e}")
        import traceback
        print(f"  Traceback:")
        traceback.print_exc()
        print(f"  readPosition at error: {readPosition}")
        return 'failed'
    
    finally:
        print("\n" + "="*100)
        print("🔍 DEBUG: decryptAndCheckPubkeyPayload END")
        print("="*100 + "\n")


# Getpubkey creation functions - DEBUG VERSION
def createGetpubkeyPayload(address):
    """
    Create a getpubkey request for the given address.
    EXTENSIVE DEBUG VERSION.
    """
    print("\n" + "="*100)
    print("🔍 DEBUG: createGetpubkeyPayload START")
    print(f"  Creating getpubkey for address: {address}")
    print("="*100)
    
    try:
        # Decode the address
        decode_result = decodeAddress(address)
        print(f"\n📋 [1] ADDRESS DECODING:")
        print(f"  decodeAddress result: {decode_result}")
        
        if decode_result[0] != 'success':
            print(f"  ❌ Address decode failed: {decode_result[0]}")
            return None
            
        addressVersion, streamNumber, ripe = decode_result[1:]
        print(f"  ✅ Decoded successfully:")
        print(f"    Version: {addressVersion}")
        print(f"    Stream: {streamNumber}")
        print(f"    RIPE hex: {hexlify(ripe)}")
        
        # Create payload based on address version
        payload = b''
        
        if addressVersion <= 3:
            # Version 2/3 uses RIPE hash
            print(f"\n📋 [2] CREATING V{addressVersion} GETPUBKEY:")
            print(f"  Using RIPE hash (20 bytes): {hexlify(ripe)}")
            
            payload += encodeVarint(addressVersion)
            payload += encodeVarint(streamNumber)
            payload += ripe  # 20 bytes
            
            print(f"  Payload created: {len(payload)} bytes")
            print(f"  Payload hex: {hexlify(payload)}")
            
        elif addressVersion >= 4:
            # Version 4 uses tag
            print(f"\n📋 [2] CREATING V{addressVersion} GETPUBKEY:")
            
            # Calculate tag
            print(f"  Calculating tag from:")
            print(f"    Version: {addressVersion}")
            print(f"    Stream: {streamNumber}")
            print(f"    RIPE: {hexlify(ripe)}")
            
            tag = highlevelcrypto.double_sha512(
                encodeVarint(addressVersion) + encodeVarint(streamNumber) + ripe
            )[32:]
            
            print(f"  Tag calculated: {hexlify(tag)}")
            print(f"  Tag length: {len(tag)} bytes")
            
            payload += encodeVarint(addressVersion)
            payload += encodeVarint(streamNumber)
            payload += tag  # 32 bytes
            
            print(f"  Payload created: {len(payload)} bytes")
            print(f"  Payload hex: {hexlify(payload)}")
            
        else:
            print(f"\n❌ UNSUPPORTED ADDRESS VERSION: {addressVersion}")
            return None
        
        print(f"\n✅ SUCCESS: getpubkey payload created")
        print(f"  Total size: {len(payload)} bytes")
        print("="*100)
        
        return payload
        
    except Exception as e:
        print(f"\n❌ ERROR in createGetpubkeyPayload: {e}")
        import traceback
        traceback.print_exc()
        print("="*100)
        return None


def assembleGetpubkeyMessage(address):
    """
    Create a complete getpubkey object for the given address.
    Includes nonce, time, and object type.
    EXTENSIVE DEBUG VERSION.
    """
    print("\n" + "="*100)
    print("🚀 DEBUG: assembleGetpubkeyMessage START")
    print(f"  Assembling getpubkey message for: {address}")
    print("="*100)
    
    try:
        # Get the payload
        payload = createGetpubkeyPayload(address)
        if not payload:
            print(f"❌ Failed to create payload")
            return None
        
        print(f"\n📋 [3] ASSEMBLING COMPLETE GETPUBKEY OBJECT:")
        
        # Create the complete object
        data = b''
        
        # Nonce (8 bytes - will be filled during PoW)
        nonce = b'\x00\x00\x00\x00\x00\x00\x00\x00'
        data += nonce
        print(f"  Nonce placeholder: 8 bytes")
        
        # Expiration time (8 bytes)
        expires_time = int(time.time()) + 86400  # 1 day
        data += pack('>Q', expires_time)
        print(f"  Expires time: {expires_time} ({time.ctime(expires_time)})")
        
        # Object type (4 bytes)
        object_type = pack('>I', OBJECT_GETPUBKEY)
        data += object_type
        print(f"  Object type: GETPUBKEY (0x{OBJECT_GETPUBKEY:08X})")
        
        # Version (varint)
        decode_result = decodeAddress(address)
        if decode_result[0] != 'success':
            print(f"❌ Cannot decode address for version")
            return None
            
        addressVersion = decode_result[1]
        data += encodeVarint(addressVersion)
        print(f"  Address version varint: {addressVersion}")
        
        # Stream number (varint)
        streamNumber = decode_result[2]
        data += encodeVarint(streamNumber)
        print(f"  Stream number varint: {streamNumber}")
        
        # Add the payload (hash or tag)
        data += payload[len(encodeVarint(addressVersion)) + len(encodeVarint(streamNumber)):]
        
        print(f"\n✅ COMPLETE GETPUBKEY OBJECT CREATED:")
        print(f"  Total size: {len(data)} bytes")
        print(f"  First 50 bytes hex: {hexlify(data[:50])}")
        print("="*100)
        
        return data
        
    except Exception as e:
        print(f"\n❌ ERROR in assembleGetpubkeyMessage: {e}")
        import traceback
        traceback.print_exc()
        print("="*100)
        return None


def createAndSendGetpubkey(address, stream):
    """
    High-level function to create and queue a getpubkey request.
    This is what should be called when we need a pubkey.
    EXTENSIVE DEBUG VERSION.
    """
    print("\n" + "="*100)
    print("🚀🚀🚀 DEBUG: createAndSendGetpubkey START 🚀🚀🚀")
    print(f"  Creating and sending getpubkey request for:")
    print(f"    Address: {address}")
    print(f"    Stream: {stream}")
    print("="*100)
    
    try:
        # First, check if we already have the pubkey
        print(f"\n📋 [1] CHECKING IF WE ALREADY HAVE PUBKEY:")
        query = "SELECT address FROM pubkeys WHERE address = ?"
        from helper_sql import sqlQuery
        result = sqlQuery(query, address)
        
        if result:
            print(f"  ✅ Pubkey already in database!")
            return True
        else:
            print(f"  ❌ Pubkey not found in database")
        
        # Check if we're already waiting for this pubkey
        print(f"\n📋 [2] CHECKING state.neededPubkeys:")
        print(f"  Current neededPubkeys size: {len(state.neededPubkeys)}")
        
        # Calculate tag for v4 addresses
        decode_result = decodeAddress(address)
        if decode_result[0] != 'success':
            print(f"❌ Cannot decode address")
            return False
            
        addressVersion = decode_result[1]
        
        if addressVersion >= 4:
            streamNumber, ripe = decode_result[2], decode_result[3]
            tag = highlevelcrypto.double_sha512(
                encodeVarint(addressVersion) + encodeVarint(streamNumber) + ripe
            )[32:]
            tag_hex = hexlify(tag).decode('ascii')
            
            print(f"  Calculated tag for v{addressVersion}: {hexlify(tag)}")
            print(f"  Tag hex string: {tag_hex}")
            
            # Check if already in neededPubkeys
            if tag in state.neededPubkeys or tag_hex in state.neededPubkeys:
                print(f"  ℹ️ Already waiting for this pubkey")
                return True
        else:
            # For v2/v3, check by address
            if address in state.neededPubkeys:
                print(f"  ℹ️ Already waiting for this pubkey")
                return True
        
        # Create the getpubkey object
        print(f"\n📋 [3] CREATING GETPUBKEY OBJECT:")
        getpubkey_data = assembleGetpubkeyMessage(address)
        if not getpubkey_data:
            print(f"❌ Failed to create getpubkey object")
            return False
        
        # Calculate inventory hash
        print(f"\n📋 [4] CALCULATING INVENTORY HASH:")
        inventory_hash = highlevelcrypto.calculateInventoryHash(getpubkey_data)
        print(f"  Inventory hash: {hexlify(inventory_hash)}")
        
        # Add to inventory
        print(f"\n📋 [5] ADDING TO INVENTORY:")
        print(f"  Adding to state.Inventory...")
        expires_time = unpack('>Q', getpubkey_data[8:16])[0]
        state.Inventory[inventory_hash] = (
            OBJECT_GETPUBKEY, stream, getpubkey_data, expires_time, b''
        )
        print(f"  Inventory size now: {len(state.Inventory)}")
        
        # Add to invQueue to send to peers
        print(f"\n📋 [6] QUEUING FOR NETWORK:")
        from network import invQueue
        invQueue.put((stream, inventory_hash))
        print(f"  Added to invQueue for stream {stream}")
        
        # Update neededPubkeys
        print(f"\n📋 [7] UPDATING state.neededPubkeys:")
        if addressVersion >= 4:
            # For v4, we need a cryptor object
            print(f"  Creating cryptor object for v{addressVersion}...")
            try:
                from highlevelcrypto import makeCryptor
                cryptorObject = makeCryptor(hexlify(ripe))
                state.neededPubkeys[tag] = (address, cryptorObject)
                print(f"  ✅ Added to neededPubkeys with bytes key")
                print(f"    Key (bytes): {hexlify(tag)}")
                print(f"    Value: ({address}, cryptorObject)")
            except Exception as e:
                print(f"  ❌ Failed to create cryptor object: {e}")
                # Fallback: store without cryptor
                state.neededPubkeys[tag] = (address, None)
                print(f"  ℹ️ Added without cryptor object")
        else:
            # For v2/v3, store address directly
            state.neededPubkeys[address] = 0
            print(f"  ✅ Added to neededPubkeys:")
            print(f"    Key: {address}")
            print(f"    Value: 0")
        
        print(f"\n🎉 SUCCESS! Getpubkey request created and queued!")
        print(f"  neededPubkeys size: {len(state.neededPubkeys)}")
        print("="*100)
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR in createAndSendGetpubkey: {e}")
        import traceback
        traceback.print_exc()
        print("="*100)
        return False


# Helper function to debug the current state
def debugPubkeyState():
    """Print debug information about pubkey state"""
    print("\n" + "="*100)
    print("🔍 DEBUG: CURRENT PUBKEY STATE")
    print("="*100)
    
    print(f"\n📊 DATABASE STATS:")
    from helper_sql import sqlQuery
    pubkey_count = sqlQuery("SELECT COUNT(*) FROM pubkeys")[0][0]
    print(f"  Pubkeys in database: {pubkey_count}")
    
    print(f"\n📊 STATE.NEEDEDPUBKEYS:")
    print(f"  Size: {len(state.neededPubkeys)}")
    if state.neededPubkeys:
        print(f"  Keys:")
        for i, (key, value) in enumerate(list(state.neededPubkeys.items())[:10]):
            if isinstance(key, str):
                key_disp = f"str: {key[:30]}..." if len(key) > 30 else f"str: {key}"
            elif isinstance(key, bytes):
                key_disp = f"bytes: {hexlify(key[:10])}..."
            else:
                key_disp = f"{type(key)}: {key}"
            print(f"    [{i}] Key: {key_disp}")
            print(f"        Value type: {type(value)}")
            if isinstance(value, tuple) and len(value) >= 2:
                print(f"        Address: {value[0]}")
    
    print(f"\n📊 STATE.INVENTORY:")
    print(f"  Size: {len(state.Inventory)}")
    if state.Inventory:
        print(f"  First 3 items:")
        for i, (inv_hash, inv_data) in enumerate(list(state.Inventory.items())[:3]):
            object_type = inv_data[0]
            object_type_name = {
                OBJECT_GETPUBKEY: "GETPUBKEY",
                OBJECT_PUBKEY: "PUBKEY",
                OBJECT_MSG: "MSG",
                OBJECT_BROADCAST: "BROADCAST"
            }.get(object_type, f"UNKNOWN(0x{object_type:08X})")
            print(f"    [{i}] Hash: {hexlify(inv_hash[:10])}...")
            print(f"        Type: {object_type_name}")
    
    print("="*100)
