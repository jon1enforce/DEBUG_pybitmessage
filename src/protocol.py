"""
Low-level protocol-related functions.
"""
# pylint: disable=too-many-boolean-expressions,too-many-return-statements
# pylint: disable=too-many-locals,too-many-statements

import base64
import hashlib
import helper_random as random
import socket
import sys
import time
from binascii import hexlify
from struct import Struct, pack, unpack
import six
import sqlite3
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
from network.helpers import is_openbsd  # Hinzufügen dieses Imports
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

# Helper function for OpenBSD compatibility
def resolve_hostname(hostname):
    """Resolve hostname in a cross-platform compatible way"""
    if not hostname:
        return hostname
    
    try:
        # Prefer getaddrinfo for IPv4/IPv6 compatibility
        addr_info = socket.getaddrinfo(hostname, None)
        return addr_info[0][4][0]  # Return first IPv4/IPv6 address
    except (socket.gaierror, IndexError, TypeError, OSError):
        # Fallback für OpenBSD und andere Systeme
        try:
            # Versuche verschiedene Methoden für OpenBSD-Kompatibilität
            if is_openbsd():
                # Spezielle Behandlung für OpenBSD
                if hostname == socket.gethostname():
                    return "127.0.0.1"  # Localhost für Hostname
                # Für externe Hostnames weiterhin versuchen
                return socket.gethostbyname(hostname)
            else:
                return socket.gethostbyname(hostname)
        except (socket.error, TypeError, OSError, socket.gaierror):
            # Final fallback - return hostname as is
            return hostname

def inet_aton_openbsd(host):
    """OpenBSD compatible inet_aton replacement"""
    if is_openbsd():
        try:
            # Try modern approach first
            return socket.inet_pton(socket.AF_INET, host)
        except (socket.error, OSError, AttributeError):
            # Fallback to traditional method
            try:
                return socket.inet_aton(host)
            except (socket.error, OSError):
                # Final fallback - manual parsing
                parts = host.split('.')
                if len(parts) == 4:
                    try:
                        return pack('!BBBB', *[int(p) for p in parts])
                    except (ValueError, TypeError):
                        pass
                raise
    else:
        # On Linux and other platforms, use standard function
        try:
            return socket.inet_aton(host)
        except (socket.error, OSError):
            raise

def inet_ntoa_openbsd(data):
    """OpenBSD compatible inet_ntoa replacement"""
    if is_openbsd():
        try:
            return socket.inet_ntop(socket.AF_INET, data)
        except (socket.error, OSError, AttributeError):
            # Fallback to traditional method
            try:
                return socket.inet_ntoa(data)
            except (socket.error, OSError):
                # Final fallback - manual conversion
                if len(data) == 4:
                    return '.'.join(str(b) for b in data)
                raise
    else:
        # On Linux and other platforms, use standard function
        try:
            return socket.inet_ntoa(data)
        except (socket.error, OSError):
            if len(data) == 4:
                return '.'.join(str(b) for b in data)
            raise

def inet_pton_openbsd(family, host):
    """OpenBSD compatible inet_pton replacement"""
    if is_openbsd():
        try:
            return socket.inet_pton(family, host)
        except (socket.error, OSError, AttributeError):
            if family == socket.AF_INET:
                return inet_aton_openbsd(host)
            elif family == socket.AF_INET6:
                # Simplified IPv6 handling for OpenBSD
                if host == '::1':
                    return b'\x00' * 15 + b'\x01'
                elif host.startswith('::ffff:'):
                    ipv4_part = host[7:]
                    return b'\x00' * 10 + b'\xff\xff' + inet_aton_openbsd(ipv4_part)
            raise
    else:
        # On Linux and other platforms, use standard function
        try:
            return socket.inet_pton(family, host)
        except (socket.error, OSError, AttributeError):
            raise

def inet_ntop_openbsd(family, data):
    """OpenBSD compatible inet_ntop replacement"""
    if is_openbsd():
        try:
            return socket.inet_ntop(family, data)
        except (socket.error, OSError, AttributeError):
            if family == socket.AF_INET:
                return inet_ntoa_openbsd(data)
            elif family == socket.AF_INET6:
                # Simplified IPv6 to string conversion
                if data == b'\x00' * 15 + b'\x01':
                    return '::1'
                elif data.startswith(b'\x00' * 10 + b'\xff\xff'):
                    return '::ffff:' + inet_ntoa_openbsd(data[12:])
            raise
    else:
        # On Linux and other platforms, use standard function
        try:
            return socket.inet_ntop(family, data)
        except (socket.error, OSError, AttributeError):
            raise

# Bitfield
def getBitfield(address):
    """Get a bitfield from an address"""
    logger.debug("DEBUG: getBitfield called for address: %s", address)
    # bitfield of features supported by me (see the wiki).
    bitfield = 0
    # send ack
    if not config.safeGetBoolean(address, 'dontsendack'):
        bitfield |= BITFIELD_DOESACK
    result = pack('>I', bitfield)
    logger.debug("DEBUG: getBitfield result: %s", hexlify(result))
    return result


def checkBitfield(bitfieldBinary, flags):
    """Check if a bitfield matches the given flags"""
    logger.debug("DEBUG: checkBitfield called with bitfield: %s, flags: %s", 
                hexlify(bitfieldBinary), flags)
    bitfield, = unpack('>I', bitfieldBinary)
    result = (bitfield & flags) == flags
    logger.debug("DEBUG: checkBitfield result: %s", result)
    return result


def isBitSetWithinBitfield(fourByteString, n):
    """Check if a particular bit is set in a bitfeld"""
    logger.debug("DEBUG: isBitSetWithinBitfield called with data: %s, bit: %d", 
                hexlify(fourByteString), n)
    # Uses MSB 0 bit numbering across 4 bytes of data
    n = 31 - n
    x, = unpack('>L', fourByteString)
    result = x & 2**n != 0
    logger.debug("DEBUG: isBitSetWithinBitfield result: %s", result)
    return result

# Streams
MIN_VALID_STREAM = 1
MAX_VALID_STREAM = 2**63 - 1

# IP addresses
def encodeHost(host):
    """Encode a given host to be used in low-level socket operations"""
    logger.debug("DEBUG: encodeHost called with host: %s", host)
    if host.endswith('.onion'):
        result = b'\xfd\x87\xd8\x7e\xeb\x43' + base64.b32decode(
            host.split(".")[0], True)
    elif host.find(':') == -1:
        try:
            # ✅ Konsistente Verwendung der OpenBSD-Hilfsfunktion
            ip_bytes = inet_aton_openbsd(host)
            result = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF' + ip_bytes
        except (socket.error, OSError, ValueError):
            logger.debug("DEBUG: encodeHost - IPv4 conversion failed, using fallback")
            result = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF' + b'\x00\x00\x00\x00'
    else:
        try:
            # ✅ Konsistente Verwendung der OpenBSD-Hilfsfunktion
            result = inet_pton_openbsd(socket.AF_INET6, host)
        except (socket.error, OSError, ValueError):
            logger.debug("DEBUG: encodeHost - IPv6 conversion failed, using fallback")
            result = b'\x00' * 16
    return result


def networkType(host):
    """Determine if a host is IPv4, IPv6 or an onion address"""
    logger.debug("DEBUG: networkType called with host: %s", host)
    if host.endswith('.onion'):
        result = 'onion'
    elif host.find(':') == -1:
        result = 'IPv4'
    else:
        result = 'IPv6'
    logger.debug("DEBUG: networkType result: %s", result)
    return result


def network_group(host):
    """Canonical identifier of network group
       simplified, borrowed from
       GetGroup() in src/netaddresses.cpp in bitcoin core"""
    logger.debug("DEBUG: network_group called with host: %s", host)
    if not isinstance(host, str):
        logger.debug("DEBUG: network_group - host is not string, returning None")
        return None
    network_type = networkType(host)
    try:
        raw_host = encodeHost(host)
    except (socket.error, OSError, ValueError):
        logger.debug("DEBUG: network_group - socket error, returning host")
        return host
    if network_type == 'IPv4':
        decoded_host = checkIPv4Address(raw_host[12:], True)
        if decoded_host:
            # /16 subnet
            result = raw_host[12:14]
            logger.debug("DEBUG: network_group IPv4 result: %s", hexlify(result))
            return result
    elif network_type == 'IPv6':
        decoded_host = checkIPv6Address(raw_host, True)
        if decoded_host:
            # /32 subnet
            result = raw_host[0:12]
            logger.debug("DEBUG: network_group IPv6 result: %s", hexlify(result))
            return result
    else:
        # just host, e.g. for tor
        logger.debug("DEBUG: network_group returning host: %s", host)
        return host
    # global network type group for local, private, unroutable
    logger.debug("DEBUG: network_group returning network_type: %s", network_type)
    return network_type


def checkIPAddress(host, private=False):
    """
    Returns hostStandardFormat if it is a valid IP address,
    otherwise returns False
    """
    logger.debug("DEBUG: checkIPAddress called with host: %s, private: %s", 
                hexlify(host), private)
    
    try:
        if host[0:12] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF':
            try:
                hostStandardFormat = inet_ntop_openbsd(socket.AF_INET, bytes(host[12:]))
            except (socket.error, OSError, ValueError):
                hostStandardFormat = inet_ntoa_openbsd(bytes(host[12:]))
            result = checkIPv4Address(host[12:], hostStandardFormat, private)
        elif host[0:6] == b'\xfd\x87\xd8\x7e\xeb\x43':
            # Onion, based on BMD/bitcoind
            hostStandardFormat = base64.b32encode(host[6:]).lower() + b".onion"
            if private:
                result = False
            else:
                result = hostStandardFormat
        else:
            try:
                hostStandardFormat = inet_ntop_openbsd(socket.AF_INET6, host)
            except (socket.error, OSError, ValueError):
                logger.debug("DEBUG: checkIPAddress - IPv6 conversion error, returning False")
                return False
            if len(hostStandardFormat) == 0:
                # This can happen on Windows systems which are
                # not 64-bit compatible so let us drop the IPv6 address.
                logger.debug("DEBUG: checkIPAddress - empty host, returning False")
                return False
            result = checkIPv6Address(host, hostStandardFormat, private)
    except (IndexError, TypeError, ValueError, socket.error, OSError) as e:
        logger.debug("DEBUG: checkIPAddress - error: %s, returning False", e)
        return False
    
    logger.debug("DEBUG: checkIPAddress result: %s", result)
    return result


def checkIPv4Address(host, hostStandardFormat, private=False):
    """
    Returns hostStandardFormat if it is an IPv4 address,
    otherwise returns False
    """
    logger.debug("DEBUG: checkIPv4Address called with host: %s, format: %s, private: %s",
                hexlify(host), hostStandardFormat, private)
    
    try:
        if host[0:1] == b'\x7F':  # 127/8
            if not private:
                logger.debug(
                    'Ignoring IP address in loopback range: %s',
                    hostStandardFormat)
            result = hostStandardFormat if private else False
        elif host[0:1] == b'\x0A':  # 10/8
            if not private:
                logger.debug(
                    'Ignoring IP address in private range: %s', hostStandardFormat)
            result = hostStandardFormat if private else False
        elif host[0:2] == b'\xC0\xA8':  # 192.168/16
            if not private:
                logger.debug(
                    'Ignoring IP address in private range: %s', hostStandardFormat)
            result = hostStandardFormat if private else False
        elif host[0:2] >= b'\xAC\x10' and host[0:2] < b'\xAC\x20':  # 172.16/12
            if not private:
                logger.debug(
                    'Ignoring IP address in private range: %s', hostStandardFormat)
            result = hostStandardFormat if private else False
        else:
            result = False if private else hostStandardFormat
    except (IndexError, TypeError) as e:
        logger.debug("DEBUG: checkIPv4Address - error: %s, returning False", e)
        result = False
    
    logger.debug("DEBUG: checkIPv4Address result: %s", result)
    return result


def checkIPv6Address(host, hostStandardFormat, private=False):
    """
    Returns hostStandardFormat if it is an IPv6 address,
    otherwise returns False
    """
    logger.debug("DEBUG: checkIPv6Address called with host: %s, format: %s, private: %s",
                hexlify(host), hostStandardFormat, private)
    
    try:
        if host == b'\x00' * 15 + b'\x01':
            if not private:
                logger.debug('Ignoring loopback address: %s', hostStandardFormat)
            result = False
        else:
            try:
                host_bytes = [six.byte2int(c) for c in host[:2]]
            except TypeError:  # python3 has ints already
                host_bytes = list(host[:2])
            
            if host_bytes[0] == 0xfe and host_bytes[1] & 0xc0 == 0x80:
                if not private:
                    logger.debug('Ignoring local address: %s', hostStandardFormat)
                result = hostStandardFormat if private else False
            elif host_bytes[0] & 0xfe == 0xfc:
                if not private:
                    logger.debug(
                        'Ignoring unique local address: %s', hostStandardFormat)
                result = hostStandardFormat if private else False
            else:
                result = False if private else hostStandardFormat
    except (IndexError, TypeError, ValueError) as e:
        logger.debug("DEBUG: checkIPv6Address - error: %s, returning False", e)
        result = False
    
    logger.debug("DEBUG: checkIPv6Address result: %s", result)
    return result


def haveSSL(server=False):
    """
    Predicate to check if ECDSA server support is required and available

    python < 2.7.9's ssl library does not support ECDSA server due to
    missing initialisation of available curves, but client works ok
    """
    logger.debug("DEBUG: haveSSL called with server: %s", server)
    if not server:
        result = True
    elif sys.version_info >= (2, 7, 9):
        result = True
    else:
        result = False
    
    logger.debug("DEBUG: haveSSL result: %s", result)
    return result


def checkSocksIP(host):
    """Predicate to check if we're using a SOCKS proxy"""
    logger.debug("DEBUG: checkSocksIP called with host: %s", host)
    sockshostname = config.safeGet(
        'bitmessagesettings', 'sockshostname')
    
    try:
        if not state.socksIP:
            state.socksIP = resolve_hostname(sockshostname)
    except NameError:  # uninitialised
        state.socksIP = resolve_hostname(sockshostname)
    except (TypeError, socket.gaierror, OSError):  # None, resolving failure
        state.socksIP = sockshostname
    
    result = state.socksIP == host
    logger.debug("DEBUG: checkSocksIP result: %s", result)
    return result


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
    logger.debug("DEBUG: isProofOfWorkSufficient called with data length: %d, "
                "nonceTrialsPerByte: %d, payloadLengthExtraBytes: %d, recvTime: %s",
                len(data), nonceTrialsPerByte, payloadLengthExtraBytes, recvTime)
    
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
    result = POW <= 2 ** 64 / (
        nonceTrialsPerByte * (
            len(data) + payloadLengthExtraBytes
            + ((TTL * (len(data) + payloadLengthExtraBytes)) / (2 ** 16))))
    
    logger.debug("DEBUG: isProofOfWorkSufficient result: %s", result)
    return result


# Packet creation
def CreatePacket(command, payload=b''):
    """Construct and return a packet"""
    logger.debug("DEBUG: CreatePacket called with command: %s, payload length: %d",
                command, len(payload))
    payload_length = len(payload)
    checksum = hashlib.sha512(payload).digest()[0:4]

    b = bytearray(Header.size + payload_length)
    Header.pack_into(b, 0, magic, command, payload_length, checksum)
    b[Header.size:] = payload
    
    logger.debug("DEBUG: CreatePacket result length: %d", len(b))
    return bytes(b)


def assembleAddrMessage(peerList):
    """Create address command"""
    logger.debug("DEBUG: assembleAddrMessage called with peerList length: %d",
                0 if peerList is None else len(peerList))
    if isinstance(peerList, Peer):
        peerList = [peerList]
    if not peerList:
        logger.debug("DEBUG: assembleAddrMessage - empty peerList, returning empty bytes")
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
    
    logger.debug("DEBUG: assembleAddrMessage result length: %d", len(retval))
    return retval


def assembleVersionMessage(  # pylint: disable=too-many-arguments
    remoteHost, remotePort, participatingStreams, dandelion_enabled=True, server=False, nodeid=None,
):
    """
    Construct the payload of a version message,
    return the resulting bytes of running `CreatePacket` on it
    """
    logger.debug("DEBUG: assembleVersionMessage called with remoteHost: %s, remotePort: %d, "
                "participatingStreams count: %d, dandelion_enabled: %s, server: %s, nodeid: %s",
                remoteHost, remotePort, len(participatingStreams), dandelion_enabled, server,
                hexlify(nodeid) if nodeid else None)
    
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
        except (socket.error, OSError, ValueError):
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
            logger.debug("DEBUG: assembleVersionMessage - reached max stream count")
            break

    result = CreatePacket(b'version', payload)
    logger.debug("DEBUG: assembleVersionMessage result length: %d", len(result))
    return result


def assembleErrorMessage(fatal=0, banTime=0, inventoryVector=b'', errorText=''):
    """
    Construct the payload of an error message,
    return the resulting bytes of running `CreatePacket` on it
    """
    logger.debug("DEBUG: assembleErrorMessage called with fatal: %d, banTime: %d, "
                "inventoryVector length: %d, errorText: %s",
                fatal, banTime, len(inventoryVector), errorText)
    
    payload = encodeVarint(fatal)
    payload += encodeVarint(banTime)
    payload += encodeVarint(len(inventoryVector))
    payload += inventoryVector
    if isinstance(errorText, str):
        errorText = errorText.encode("utf-8", "replace")
    payload += encodeVarint(len(errorText))
    payload += errorText
    
    result = CreatePacket(b'error', payload)
    logger.debug("DEBUG: assembleErrorMessage result length: %d", len(result))
    return result


# Packet decoding
def decodeObjectParameters(data):
    """Decode the parameters of a raw object needed to put it in inventory"""
    logger.debug("DEBUG: decodeObjectParameters called with data length: %d", len(data))
    # BMProto.decode_payload_content("QQIvv")
    expiresTime = unpack('>Q', data[8:16])[0]
    objectType = unpack('>I', data[16:20])[0]
    parserPos = 20 + decodeVarint(data[20:30])[1]
    toStreamNumber = decodeVarint(data[parserPos:parserPos + 10])[0]

    logger.debug("DEBUG: decodeObjectParameters result - objectType: %d, "
                "toStreamNumber: %d, expiresTime: %d",
                objectType, toStreamNumber, expiresTime)
    return objectType, toStreamNumber, expiresTime


def decryptAndCheckPubkeyPayload(data, address):
    """
    Version 4 pubkeys are encrypted. This function is run when we
    already have the address to which we want to try to send a message.
    The 'data' may come either off of the wire or we might have had it
    already in our inventory when we tried to send a msg to this
    particular address.
    """
    logger.debug("DEBUG: decryptAndCheckPubkeyPayload called with data length: %d, address: %s",
                len(data), address)
    try:
        addressVersion, streamNumber, ripe = decodeAddress(address)[1:]

        readPosition = 20  # bypass the nonce, time, and object type
        embeddedAddressVersion, varintLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += varintLength
        embeddedStreamNumber, varintLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += varintLength
        # We'll store the address version and stream number
        # (and some more) in the pubkeys table.
        storedData = bytes(data[20:readPosition])

        if addressVersion != embeddedAddressVersion:
            logger.info(
                'Pubkey decryption was UNsuccessful'
                ' due to address version mismatch.')
            logger.debug("DEBUG: decryptAndCheckPubkeyPayload - address version mismatch: "
                        "expected %d, got %d", addressVersion, embeddedAddressVersion)
            return 'failed'
        if streamNumber != embeddedStreamNumber:
            logger.info(
                'Pubkey decryption was UNsuccessful'
                ' due to stream number mismatch.')
            logger.debug("DEBUG: decryptAndCheckPubkeyPayload - stream number mismatch: "
                        "expected %d, got %d", streamNumber, embeddedStreamNumber)
            return 'failed'

        tag = data[readPosition:readPosition + 32]
        readPosition += 32
        # the time through the tag. More data is appended onto
        # signedData below after the decryption.
        signedData = bytes(data[8:readPosition])
        encryptedData = data[readPosition:]

        # Let us try to decrypt the pubkey
        toAddress, cryptorObject = state.neededPubkeys[bytes(tag)]
        if toAddress != address:
            logger.critical(
                'decryptAndCheckPubkeyPayload failed due to toAddress'
                ' mismatch. This is very peculiar.'
                ' toAddress: %s, address %s',
                toAddress, address
            )
            logger.debug("DEBUG: decryptAndCheckPubkeyPayload - address mismatch: "
                        "expected %s, got %s", toAddress, address)
            return 'failed'
        try:
            decryptedData = cryptorObject.decrypt(encryptedData)
        except:  # noqa:E722
            # FIXME: use a proper exception after `pyelliptic.ecc` is refactored.
            logger.info('Pubkey decryption was unsuccessful.')
            logger.debug("DEBUG: decryptAndCheckPubkeyPayload - decryption failed", exc_info=True)
            return 'failed'

        readPosition = 0
        # bitfieldBehaviors = decryptedData[readPosition:readPosition + 4]
        readPosition += 4
        pubSigningKey = b'\x04' + decryptedData[readPosition:readPosition + 64]
        readPosition += 64
        pubEncryptionKey = b'\x04' + decryptedData[readPosition:readPosition + 64]
        readPosition += 64
        specifiedNonceTrialsPerByteLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])[1]
        readPosition += specifiedNonceTrialsPerByteLength
        specifiedPayloadLengthExtraBytesLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])[1]
        readPosition += specifiedPayloadLengthExtraBytesLength
        storedData += decryptedData[:readPosition]
        signedData += decryptedData[:readPosition]
        signatureLength, signatureLengthLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        readPosition += signatureLengthLength
        signature = decryptedData[readPosition:readPosition + signatureLength]

        if not highlevelcrypto.verify(
                signedData, signature, hexlify(pubSigningKey)):
            logger.info(
                'ECDSA verify failed (within decryptAndCheckPubkeyPayload)')
            logger.debug("DEBUG: decryptAndCheckPubkeyPayload - ECDSA verification failed")
            return 'failed'

        logger.info(
            'ECDSA verify passed (within decryptAndCheckPubkeyPayload)')
        logger.debug("DEBUG: decryptAndCheckPubkeyPayload - ECDSA verification passed")

        embeddedRipe = highlevelcrypto.to_ripe(pubSigningKey, pubEncryptionKey)

        if embeddedRipe != ripe:
            logger.info(
                'Pubkey decryption was UNsuccessful due to RIPE mismatch.')
            logger.debug("DEBUG: decryptAndCheckPubkeyPayload - RIPE mismatch: "
                        "expected %s, got %s", hexlify(ripe), hexlify(embeddedRipe))
            return 'failed'

        # Everything checked out. Insert it into the pubkeys table.

        logger.info(
            'within decryptAndCheckPubkeyPayload, '
            'addressVersion: %s, streamNumber: %s\nripe %s\n'
            'publicSigningKey in hex: %s\npublicEncryptionKey in hex: %s',
            addressVersion, streamNumber, hexlify(ripe),
            hexlify(pubSigningKey), hexlify(pubEncryptionKey)
        )

        t = (dbstr(address), addressVersion, sqlite3.Binary(storedData), int(time.time()), dbstr('yes'))
        sqlExecute('''INSERT INTO pubkeys VALUES (?,?,?,?,?)''', *t)
        logger.debug("DEBUG: decryptAndCheckPubkeyPayload - successfully stored pubkey")
        return 'successful'
    except varintDecodeError:
        logger.info(
            'Pubkey decryption was UNsuccessful due to a malformed varint.')
        logger.debug("DEBUG: decryptAndCheckPubkeyPayload - varint decode error", exc_info=True)
        return 'failed'
    except Exception:
        logger.critical(
            'Pubkey decryption was UNsuccessful because of'
            ' an unhandled exception! This is definitely a bug!',
            exc_info=True
        )
        return 'failed'
