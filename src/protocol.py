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
import re
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

# ============ SECURITY MODULE ============ #
# Whitelist patterns für sichere Eingaben mit LaTeX-Unterstützung
SAFE_PATTERNS = {
    'hostname': re.compile(r'^[a-zA-Z0-9\-\.]+$'),
    'onion_address': re.compile(r'^[a-z2-7]{16,56}\.onion$'),
    'port': re.compile(r'^\d{1,5}$'),
    'stream_number': re.compile(r'^\d+$'),
    'user_agent': re.compile(r'^[a-zA-Z0-9\-\.\/:_ ]+$'),
    'message_content': re.compile(r'^[\s\S]*$'),  # Alles erlauben für Nachrichten
}

# Maximale Längen für verschiedene Input-Typen
MAX_LENGTHS = {
    'hostname': 253,  # DNS max length (253 chars)
    'onion_address': 62,  # .onion max (56 chars + 6 for ".onion")
    'user_agent': 256,
    'error_text': 1024,
    'message_content': 2**20,  # 1MB für Nachrichten (inkl. LaTeX)
    'stream_number': 10,  # Max 10 Ziffern für Stream-Nummern
    'general': 4096,  # Default max für andere Strings
}

# Blacklist für kritische Pfad/Command-Injection Muster
BLACKLIST_PATTERNS = [
    re.compile(r'(\.\.\/)+'),  # Path traversal
    re.compile(r'^\/|^[A-Za-z]:\\\\'),  # Absolute Pfade (Unix/Windows)
    re.compile(r'[\x00-\x1f\x7f-\xff]'),  # Kontrollzeichen und nicht-ASCII
    re.compile(r'[`|;&<>]'),  # Command injection chars
    re.compile(r'\$\('),  # Command substitution
    re.compile(r'%[0-9a-fA-F]{2}'),  #URL encoding attempts
]

# Erlaubte LaTeX Commands (basierend auf common LaTeX packages)
ALLOWED_LATEX_COMMANDS = re.compile(
    r'(\\[a-zA-Z]+|\\[^a-zA-Z]|'  # LaTeX commands
    r'\\begin\{[^}]+\}|\\end\{[^}]+\}|'  # Environments
    r'\$[^$]*\$|\\\[[^\]]*\\\]|'  # Math mode
    r'\\[a-zA-Z]*[+\-*/=()\[\]{},.;:!?]|'  # Math symbols
    r'[^\\]*'  # Normal text
    r')'
)

def validate_input(value, input_type='general', is_message_content=False):
    """
    Erweiterte Validierung mit Whitelist und Längenlimits.
    
    Args:
        value: Zu validierender Wert
        input_type: Typ der Eingabe für spezifische Validierung
        is_message_content: True wenn es sich um Nachrichteninhalt handelt
    
    Returns:
        True wenn sicher, False wenn potenziell gefährlich
    """
    if value is None:
        return True
    
    # Bytes in String umwandeln wenn nötig
    if isinstance(value, bytes):
        try:
            # Für Nachrichteninhalte: UTF-8 oder Latin-1 für LaTeX
            if is_message_content:
                try:
                    value = value.decode('utf-8', 'replace')
                except:
                    value = value.decode('latin-1', 'replace')
            else:
                value = value.decode('utf-8', 'ignore')
        except (UnicodeDecodeError, AttributeError):
            return False
    
    if not isinstance(value, str):
        # Für nicht-String-Typen: Längencheck basierend auf String-Repräsentation
        str_value = str(value)
        if input_type in MAX_LENGTHS and len(str_value) > MAX_LENGTHS[input_type]:
            return False
        return True
    
    # Spezielle Behandlung für Nachrichteninhalte (LaTeX)
    if is_message_content:
        # Längencheck
        if len(value) > MAX_LENGTHS.get('message_content', 2**20):
            return False
        
        # Für LaTeX: Einfache Validierung, erlaube fast alles außer kritischen Injection-Patterns
        # Erlaube LaTeX spezifische Zeichen: { } [ ] $ \ ~ ^ _ % & # |
        # Aber blockiere kritische Kombinationen
        
        # Check 1: Keine NUL bytes
        if '\x00' in value:
            return False
        
        # Check 2: Keine extrem langen Zeilen (verhindert DoS durch extrem lange Zeilen)
        lines = value.split('\n')
        if any(len(line) > 10000 for line in lines):
            return False
        
        # Check 3: Keine kritischen System-Commands
        dangerous_patterns = [
            r'\\write18\{',  # LaTeX shell escape
            r'\\input\{.*/etc/',  # Path traversal in \input
            r'\\include\{.*\.\./',  # Path traversal in \include
            r'\\usepackage\{.*shell_escape',  # Shell escape packages
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return False
        
        return True
    
    # Für nicht-Nachrichteninhalte: Striktere Validierung
    
    # Längenvalidierung
    max_len = MAX_LENGTHS.get(input_type, MAX_LENGTHS['general'])
    if len(value) > max_len:
        return False
    
    # Pattern-basierte Validierung
    if input_type in SAFE_PATTERNS:
        if not SAFE_PATTERNS[input_type].match(value):
            return False
    
    # Blacklist-Check für nicht-Nachrichten
    if not is_message_content:
        for pattern in BLACKLIST_PATTERNS:
            if pattern.search(value):
                return False
    
    return True


def sanitize_host(host):
    """Hostname/Adresse sanitizen und validieren"""
    if host is None:
        return None
    
    if isinstance(host, bytes):
        try:
            host = host.decode('ascii')
        except UnicodeDecodeError:
            return None
    
    if not validate_input(host, 'hostname'):
        # Für .onion Adressen spezielle Validierung
        if isinstance(host, str) and host.endswith('.onion'):
            if validate_input(host, 'onion_address'):
                return host
        return None
    
    return host


def sanitize_port(port):
    """Portnummer validieren"""
    if port is None:
        return None
    
    if isinstance(port, str):
        if not validate_input(port, 'port'):
            return None
        try:
            port = int(port)
        except ValueError:
            return None
    
    if not isinstance(port, int):
        return None
    
    if 1 <= port <= 65535:
        return port
    
    return None


def sanitize_streams(streams):
    """Stream-Nummern validieren"""
    if streams is None:
        return []
    
    valid_streams = []
    try:
        iter(streams)
    except TypeError:
        return []
    
    for stream in streams:
        if isinstance(stream, (int, str)):
            stream_str = str(stream)
            if validate_input(stream_str, 'stream_number'):
                try:
                    stream_int = int(stream_str)
                    # Stream-Nummern Bereich laut Protokoll
                    if 1 <= stream_int <= (2**63 - 1):
                        valid_streams.append(stream_int)
                except ValueError:
                    continue
    
    return valid_streams


def sanitize_user_agent(user_agent):
    """User-Agent validieren"""
    if user_agent is None:
        return ''
    
    if isinstance(user_agent, bytes):
        try:
            user_agent = user_agent.decode('utf-8', 'ignore')
        except UnicodeDecodeError:
            return ''
    
    if not validate_input(user_agent, 'user_agent'):
        # Fallback auf Standard-User-Agent
        return '/PyBitmessage/'
    
    # Längenlimit
    if len(user_agent) > MAX_LENGTHS['user_agent']:
        return user_agent[:MAX_LENGTHS['user_agent']]
    
    return user_agent


def validate_message_content(content):
    """Nachrichteninhalt validieren (speziell für LaTeX)"""
    if content is None:
        return True
    
    # Bytes validieren
    if isinstance(content, bytes):
        # Größencheck für Bytes
        if len(content) > MAX_LENGTHS['message_content']:
            return False
        
        # Einfacher NUL-byte Check
        if b'\x00' in content:
            return False
        
        return True
    
    # String validieren
    if isinstance(content, str):
        return validate_input(content, 'general', is_message_content=True)
    
    return False
# ============ END SECURITY MODULE ============ #

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
    # Validierung hinzufügen
    sanitized_host = sanitize_host(host)
    if not sanitized_host:
        raise ValueError(f"Invalid host: {host}")
    
    if sanitized_host.endswith('.onion'):
        return b'\xfd\x87\xd8\x7e\xeb\x43' + base64.b32decode(
            sanitized_host.split(".")[0], True)
    elif sanitized_host.find(':') == -1:
        return b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF' + \
            socket.inet_aton(sanitized_host)
    
    try:
        return socket.inet_pton(socket.AF_INET6, sanitized_host)
    except socket.error:
        raise ValueError(f"Invalid IPv6 address: {sanitized_host}")


def networkType(host):
    """Determine if a host is IPv4, IPv6 or an onion address"""
    if host is None:
        return 'invalid'
    
    # Validierung hinzufügen
    if not validate_input(str(host), 'hostname'):
        return 'invalid'
    
    host_str = str(host)
    
    if host_str.endswith('.onion'):
        if not validate_input(host_str, 'onion_address'):
            return 'invalid'
        return 'onion'
    elif host_str.find(':') == -1:
        # IPv4 Validierung
        try:
            socket.inet_aton(host_str)
            return 'IPv4'
        except socket.error:
            return 'invalid'
    
    # IPv6 Validierung
    try:
        socket.inet_pton(socket.AF_INET6, host_str)
        return 'IPv6'
    except socket.error:
        return 'invalid'
def network_group(host):
    """Canonical identifier of network group
       simplified, borrowed from
       GetGroup() in src/netaddresses.cpp in bitcoin core"""
    if not isinstance(host, str):
        return None
    
    # Host validieren
    if not validate_input(host, 'hostname'):
        return host  # Bei ungültigem Host, einfach zurückgeben
    
    network_type = networkType(host)
    try:
        raw_host = encodeHost(host)
    except (socket.error, ValueError):
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
    if host is None:
        return False
    
    # Host validieren bevor verarbeitet
    if len(host) < 12:
        return False
    
    if host[0:12] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF':
        if len(host) < 16:
            return False
        hostStandardFormat = socket.inet_ntop(socket.AF_INET, bytes(host[12:16]))
        return checkIPv4Address(host[12:16], hostStandardFormat, private)
    elif host[0:6] == b'\xfd\x87\xd8\x7e\xeb\x43':
        # Onion, based on BMD/bitcoind
        if len(host) < 22:  # Minimum onion address length
            return False
        hostStandardFormat = base64.b32encode(host[6:]).lower() + b".onion"
        if private:
            return False
        
        # Onion-Adresse validieren
        if validate_input(hostStandardFormat.decode('ascii'), 'onion_address'):
            return hostStandardFormat
        return False
    else:
        try:
            if len(host) != 16:
                return False
            hostStandardFormat = socket.inet_ntop(socket.AF_INET6, host)
        except (ValueError, socket.error):
            return False
        
        if len(hostStandardFormat) == 0:
            return False
        
        return checkIPv6Address(host, hostStandardFormat, private)


def checkIPv4Address(host, hostStandardFormat, private=False):
    """
    Returns hostStandardFormat if it is an IPv4 address,
    otherwise returns False
    """
    if len(host) < 4:
        return False
    
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
    
    # Finale Validierung
    if not validate_input(hostStandardFormat, 'hostname'):
        return False
    
    return False if private else hostStandardFormat


def checkIPv6Address(host, hostStandardFormat, private=False):
    """
    Returns hostStandardFormat if it is an IPv6 address,
    otherwise returns False
    """
    if len(host) != 16:
        return False
    
    if host == b'\x00' * 15 + b'\x01':
        if not private:
            logger.debug('Ignoring loopback address: %s', hostStandardFormat)
        return False
    
    try:
        host_bytes = [six.byte2int(c) for c in host[:2]]
    except TypeError:  # python3 has ints already
        host_bytes = [c for c in host[:2]]
    
    if host_bytes[0] == 0xfe and host_bytes[1] & 0xc0 == 0x80:
        if not private:
            logger.debug('Ignoring local address: %s', hostStandardFormat)
        return hostStandardFormat if private else False
    
    if host_bytes[0] & 0xfe == 0xfc:
        if not private:
            logger.debug(
                'Ignoring unique local address: %s', hostStandardFormat)
        return hostStandardFormat if private else False
    
    # Finale Validierung
    if not validate_input(hostStandardFormat, 'hostname'):
        return False
    
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
    if host is None:
        return False
    
    sockshostname = config.safeGet(
        'bitmessagesettings', 'sockshostname')
    
    if not sockshostname:
        return False
    
    # Host validieren
    if not validate_input(str(host), 'hostname'):
        return False
    
    try:
        if not state.socksIP:
            # SOCKS Hostname validieren
            if not validate_input(sockshostname, 'hostname'):
                return False
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
    if data is None or len(data) < 16:
        return False
    
    if nonceTrialsPerByte < defaults.networkDefaultProofOfWorkNonceTrialsPerByte:
        nonceTrialsPerByte = defaults.networkDefaultProofOfWorkNonceTrialsPerByte
    if payloadLengthExtraBytes < defaults.networkDefaultPayloadLengthExtraBytes:
        payloadLengthExtraBytes = defaults.networkDefaultPayloadLengthExtraBytes
    
    try:
        endOfLifeTime, = unpack('>Q', data[8:16])
    except Exception:
        return False
    
    TTL = endOfLifeTime - int(recvTime if recvTime else time.time())
    if TTL < 300:
        TTL = 300
    
    try:
        POW, = unpack('>Q', highlevelcrypto.double_sha512(
            bytes(data[:8]) + hashlib.sha512(data[8:]).digest())[0:8])
    except Exception:
        return False
    
    try:
        return POW <= 2 ** 64 / (
            nonceTrialsPerByte * (
                len(data) + payloadLengthExtraBytes
                + ((TTL * (len(data) + payloadLengthExtraBytes)) / (2 ** 16))))
    except (ZeroDivisionError, OverflowError):
        return False


# Packet creation


def CreatePacket(command, payload=b''):
    """Construct and return a packet"""
    if command is None or payload is None:
        raise ValueError("Command and payload cannot be None")
    
    # Command validieren
    if isinstance(command, bytes):
        if len(command) > 12:
            raise ValueError("Command too long")
        if not validate_input(command.decode('ascii', 'ignore'), 'user_agent'):
            raise ValueError("Invalid command")
    
    payload_length = len(payload)
    
    # Payload Größenlimit
    if payload_length > MAX_MESSAGE_SIZE:
        raise ValueError(f"Payload too large: {payload_length} bytes")
    
    checksum = hashlib.sha512(payload).digest()[0:4]

    b = bytearray(Header.size + payload_length)
    Header.pack_into(b, 0, magic, command, payload_length, checksum)
    b[Header.size:] = payload
    return bytes(b)


def assembleAddrMessage(peerList):
    """Create address command"""
    if peerList is None:
        return b''
    
    if isinstance(peerList, Peer):
        peerList = [peerList]
    
    if not peerList:
        return b''
    
    # Sicherstellen, dass die Liste nicht zu groß ist
    if len(peerList) > MAX_ADDR_COUNT * 10:  # Sicherheitsmargin
        logger.warning(f"Peer list too large: {len(peerList)} items")
        peerList = peerList[:MAX_ADDR_COUNT * 10]
    
    retval = b''
    for i in range(0, len(peerList), MAX_ADDR_COUNT):
        chunk = peerList[i:i + MAX_ADDR_COUNT]
        valid_peers = []
        
        # Peers validieren
        for item in chunk:
            try:
                stream, peer, timestamp = item
                # Stream validieren
                if not isinstance(stream, int) or stream < 1 or stream > (2**63 - 1):
                    continue
                # Peer validieren
                if not isinstance(peer, Peer):
                    continue
                if not sanitize_host(peer.host):
                    continue
                if not sanitize_port(peer.port):
                    continue
                # Timestamp validieren
                if not isinstance(timestamp, (int, float)):
                    continue
                valid_peers.append(item)
            except (TypeError, ValueError):
                continue
        
        if not valid_peers:
            continue
        
        payload = encodeVarint(len(valid_peers))
        for stream, peer, timestamp in valid_peers:
            # 64-bit time
            payload += pack('>Q', timestamp)
            payload += pack('>I', stream)
            # service bit flags offered by this node
            payload += pack('>q', 1)
            
            # Host encodieren mit Validierung
            try:
                encoded_host = encodeHost(peer.host)
                payload += encoded_host
            except ValueError:
                continue
            
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
    # Validierung der Eingaben
    sanitized_host = sanitize_host(remoteHost)
    if not sanitized_host:
        raise ValueError(f"Invalid remote host: {remoteHost}")
    
    sanitized_port = sanitize_port(remotePort)
    if not sanitized_port:
        raise ValueError(f"Invalid port: {remotePort}")
    
    # Validierung der stream numbers
    valid_streams = sanitize_streams(participatingStreams)
    
    # Node ID validieren
    safe_nodeid = None
    if nodeid is not None:
        if isinstance(nodeid, bytes) and len(nodeid) >= 8:
            safe_nodeid = nodeid[:8]
        elif isinstance(nodeid, str) and len(nodeid) >= 8:
            safe_nodeid = nodeid[:8].encode('ascii', 'ignore')
    
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
    if checkSocksIP(sanitized_host) and server:
        # prevent leaking of tor outbound IP
        payload += encodeHost('127.0.0.1')
        payload += pack('>H', 8444)
    else:
        # use first 16 bytes if host data is longer
        # for example in case of onion v3 service
        try:
            encoded_host = encodeHost(sanitized_host)
            payload += encoded_host[:16]
        except (socket.error, ValueError):
            payload += encodeHost('127.0.0.1')
        payload += pack('>H', sanitized_port)  # remote IPv6 and port

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
        extport and ((server and not checkSocksIP(sanitized_host)) or (
            config.get('bitmessagesettings', 'socksproxytype')
            == 'none' and not server))
    ):
        payload += pack('>H', extport)
    elif checkSocksIP(sanitized_host) and server:  # incoming connection over Tor
        payload += pack(
            '>H', config.getint('bitmessagesettings', 'onionport'))
    else:  # no extport and not incoming over Tor
        payload += pack(
            '>H', config.getint('bitmessagesettings', 'port'))

    if safe_nodeid is not None:
        payload += safe_nodeid[0:8]
    else:
        payload += eightBytesOfRandomDataUsedToDetectConnectionsToSelf
    
    # User-Agent validieren
    userAgent = ('/PyBitmessage:%s/' % softwareVersion).encode('utf-8')
    safe_user_agent = sanitize_user_agent(userAgent.decode('utf-8', 'ignore'))
    if not safe_user_agent:
        safe_user_agent = '/PyBitmessage/'
    
    safe_user_agent_bytes = safe_user_agent.encode('utf-8', 'ignore')
    payload += encodeVarint(len(safe_user_agent_bytes))
    payload += safe_user_agent_bytes

    # Streams
    payload += encodeVarint(len(valid_streams))
    count = 0
    for stream in sorted(valid_streams):
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
    # Parameter validieren
    if not isinstance(fatal, int) or fatal not in (0, 1, 2):
        fatal = 0
    
    if not isinstance(banTime, (int, float)):
        banTime = 0
    banTime = max(0, min(banTime, 86400))  # Max 24 Stunden
    
    # Inventory Vector validieren
    if inventoryVector is None:
        inventoryVector = b''
    elif isinstance(inventoryVector, bytes):
        if len(inventoryVector) > 32:  #SHA256 hash length
            inventoryVector = inventoryVector[:32]
    else:
        inventoryVector = b''
    
    # Error Text validieren
    if errorText is None:
        errorText = ''
    
    if isinstance(errorText, str):
        if not validate_input(errorText, 'error_text'):
            errorText = ''
        # Längenlimit
        if len(errorText) > MAX_LENGTHS['error_text']:
            errorText = errorText[:MAX_LENGTHS['error_text']]
        errorText = errorText.encode("utf-8", "replace")
    elif isinstance(errorText, bytes):
        try:
            error_str = errorText.decode('utf-8', 'ignore')
            if not validate_input(error_str, 'error_text'):
                errorText = b''
        except UnicodeDecodeError:
            errorText = b''
    else:
        errorText = b''
    
    payload = encodeVarint(fatal)
    payload += encodeVarint(int(banTime))
    payload += encodeVarint(len(inventoryVector))
    payload += inventoryVector
    payload += encodeVarint(len(errorText))
    payload += errorText
    
    return CreatePacket(b'error', payload)


# Packet decoding


def decodeObjectParameters(data):
    """Decode the parameters of a raw object needed to put it in inventory"""
    if data is None or len(data) < 30:
        return None, None, None
    
    try:
        expiresTime = unpack('>Q', data[8:16])[0]
        objectType = unpack('>I', data[16:20])[0]
        parserPos = 20 + decodeVarint(data[20:30])[1]
        if parserPos >= len(data):
            return None, None, None
        toStreamNumber = decodeVarint(data[parserPos:parserPos + 10])[0]
        return objectType, toStreamNumber, expiresTime
    except Exception:
        return None, None, None


def decryptAndCheckPubkeyPayload(data, address):
    """
    Version 4 pubkeys are encrypted. This function is run when we
    already have the address to which we want to try to send a message.
    The 'data' may come either off of the wire or we might have had it
    already in our inventory when we tried to send a msg to this
    particular address.
    """
    if data is None or address is None:
        return 'failed'
    
    # Adresse validieren
    if not validate_input(address, 'general'):
        return 'failed'
    
    # Datenlänge validieren
    if len(data) < 100:  # Minimale plausible Größe für encrypted pubkey
        return 'failed'
    
    try:
        addressVersion, streamNumber, ripe = decodeAddress(address)[1:]

        readPosition = 20  # bypass the nonce, time, and object type
        if readPosition + 10 > len(data):
            return 'failed'
        
        embeddedAddressVersion, varintLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += varintLength
        
        if readPosition + 10 > len(data):
            return 'failed'
        
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
            return 'failed'
        if streamNumber != embeddedStreamNumber:
            logger.info(
                'Pubkey decryption was UNsuccessful'
                ' due to stream number mismatch.')
            return 'failed'

        if readPosition + 32 > len(data):
            return 'failed'
        
        tag = data[readPosition:readPosition + 32]
        readPosition += 32
        # the time through the tag. More data is appended onto
        # signedData below after the decryption.
        signedData = bytes(data[8:readPosition])
        
        if readPosition > len(data):
            return 'failed'
        
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
            return 'failed'
        try:
            decryptedData = cryptorObject.decrypt(encryptedData)
        except:  # noqa:E722
            logger.info('Pubkey decryption was unsuccessful.')
            return 'failed'

        if len(decryptedData) < 140:  # Minimale Größe für decrypted pubkey
            return 'failed'
        
        readPosition = 0
        # bitfieldBehaviors = decryptedData[readPosition:readPosition + 4]
        readPosition += 4
        
        if readPosition + 64 > len(decryptedData):
            return 'failed'
        pubSigningKey = b'\x04' + decryptedData[readPosition:readPosition + 64]
        readPosition += 64
        
        if readPosition + 64 > len(decryptedData):
            return 'failed'
        pubEncryptionKey = b'\x04' + decryptedData[readPosition:readPosition + 64]
        readPosition += 64
        
        if readPosition + 10 > len(decryptedData):
            return 'failed'
        specifiedNonceTrialsPerByteLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])[1]
        readPosition += specifiedNonceTrialsPerByteLength
        
        if readPosition + 10 > len(decryptedData):
            return 'failed'
        specifiedPayloadLengthExtraBytesLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])[1]
        readPosition += specifiedPayloadLengthExtraBytesLength
        
        storedData += decryptedData[:readPosition]
        signedData += decryptedData[:readPosition]
        
        if readPosition + 10 > len(decryptedData):
            return 'failed'
        signatureLength, signatureLengthLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        readPosition += signatureLengthLength
        
        if readPosition + signatureLength > len(decryptedData):
            return 'failed'
        signature = decryptedData[readPosition:readPosition + signatureLength]

        if not highlevelcrypto.verify(
                signedData, signature, hexlify(pubSigningKey)):
            logger.info(
                'ECDSA verify failed (within decryptAndCheckPubkeyPayload)')
            return 'failed'

        logger.info(
            'ECDSA verify passed (within decryptAndCheckPubkeyPayload)')

        embeddedRipe = highlevelcrypto.to_ripe(pubSigningKey, pubEncryptionKey)

        if embeddedRipe != ripe:
            logger.info(
                'Pubkey decryption was UNsuccessful due to RIPE mismatch.')
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
        return 'successful'
    except varintDecodeError:
        logger.info(
            'Pubkey decryption was UNsuccessful due to a malformed varint.')
        return 'failed'
    except Exception:
        logger.critical(
            'Pubkey decryption was UNsuccessful because of'
            ' an unhandled exception! This is definitely a bug!',
            exc_info=True
        )
        return 'failed'
