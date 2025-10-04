"""
Class BMProto defines bitmessage's network protocol workflow.
"""

import base64
import hashlib
import logging
import re
import socket
import struct
import time
import six

# magic imports!
import addresses
from network import knownnodes
import protocol
import state
import network.connectionpool  # use long name to address recursive import
from bmconfigparser import config
from queues import objectProcessorQueue
from randomtrackingdict import RandomTrackingDict
from network.advanceddispatcher import AdvancedDispatcher
from network.bmobject import (
    BMObject, BMObjectAlreadyHaveError, BMObjectExpiredError,
    BMObjectInsufficientPOWError, BMObjectInvalidError,
    BMObjectUnwantedStreamError
)
from network.proxy import ProxyError

from network import dandelion_ins, invQueue, portCheckerQueue
from .node import Node, Peer
from .objectracker import ObjectTracker, missingObjects


logger = logging.getLogger('default')
def safe_bytearray_slice(data, start, end=None):
    """
    Safely slice bytearray/bytes with bounds checking
    If end is None, returns data from start to the end
    """
    # Input validation
    if not data or start < 0:
        return b''
    
    data_len = len(data)
    
    # If start is beyond data length, return empty
    if start >= data_len:
        return b''
    
    # If end is not provided, slice to the end
    if end is None:
        end = data_len
    
    # Adjust end if it exceeds data length or is invalid
    if end < start:
        return b''
    
    end = min(end, data_len)
    
    # Return safe slice
    return data[start:end]

# magic imports!
import addresses
from network import knownnodes

def _hoststr(v):
    if six.PY3:
        return v
    else:  # assume six.PY2
        return str(v)

def _restr(v):
    if six.PY3:
        return v.decode("utf-8", "replace")
    else:  # assume six.PY2
        return v

class BMProtoError(ProxyError):
    """A Bitmessage Protocol Base Error"""
    errorCodes = ("Protocol error")


class BMProtoInsufficientDataError(BMProtoError):
    """A Bitmessage Protocol Insufficient Data Error"""
    errorCodes = ("Insufficient data")


class BMProtoExcessiveDataError(BMProtoError):
    """A Bitmessage Protocol Excessive Data Error"""
    errorCodes = ("Too much data")


class BMProto(AdvancedDispatcher, ObjectTracker):
    """A parser for the Bitmessage Protocol"""
    # pylint: disable=too-many-instance-attributes, too-many-public-methods
    timeOffsetWrongCount = 0

    def __init__(self, address=None, sock=None):
        # pylint: disable=unused-argument, super-init-not-called
        logger.debug("DEBUG: BMProto.__init__ called with address=%s, sock=%s", address, sock)
        AdvancedDispatcher.__init__(self, sock)
        self.isOutbound = False
        # packet/connection from a local IP
        self.local = False
        self.pendingUpload = RandomTrackingDict()
        # canonical identifier of network group
        self.network_group = None
        # userAgent initialization
        self.userAgent = ''
        logger.debug("DEBUG: BMProto initialized")

    def bm_proto_reset(self):
        """Reset the bitmessage object parser"""
        logger.debug("DEBUG: Resetting BMProto parser state")
        self.magic = None
        self.command = None
        self.payloadLength = 0
        self.checksum = None
        self.payload = None
        self.invalid = False
        self.payloadOffset = 0
        self.expectBytes = protocol.Header.size
        self.object = None
        logger.debug("DEBUG: BMProto parser state reset complete")

    def state_bm_header(self):
        """Process incoming header"""
        logger.debug("DEBUG: Processing incoming header")
        try:
            self.magic, self.command, self.payloadLength, self.checksum = \
                protocol.Header.unpack(self.read_buf[:protocol.Header.size])
            self.command = self.command.rstrip(b'\x00')
            logger.debug("DEBUG: Unpacked header - magic: %s, command: %s, payloadLength: %d, checksum: %s",
                        self.magic, self.command, self.payloadLength, self.checksum)
            
            if self.magic != protocol.magic:
                logger.debug("DEBUG: Bad magic value received: %s (expected: %s)", self.magic, protocol.magic)
                # skip 1 byte in order to sync
                self.set_state("bm_header", length=1)
                self.bm_proto_reset()
                if self.socket.type == socket.SOCK_STREAM:
                    self.close_reason = "Bad magic"
                    self.set_state("close")
                return False
                
            if self.payloadLength > protocol.MAX_MESSAGE_SIZE:
                logger.debug("DEBUG: Payload length %d exceeds maximum allowed size %d",
                            self.payloadLength, protocol.MAX_MESSAGE_SIZE)
                self.invalid = True
                
            self.set_state(
                "bm_command",
                length=protocol.Header.size, expectBytes=self.payloadLength)
            logger.debug("DEBUG: Header processed successfully, moving to command state")
            return True
        except Exception as e:
            logger.debug("DEBUG: Exception in state_bm_header: %s", str(e))
            raise

    def state_bm_command(self):   # pylint: disable=too-many-branches
        """Process incoming command"""
        logger.debug("DEBUG: Processing incoming command: %s", self.command)
        try:
            self.payload = self.read_buf[:self.payloadLength]
            logger.debug("DEBUG: Payload length: %d", len(self.payload))
            
            calculated_checksum = hashlib.sha512(self.payload).digest()[0:4]
            if self.checksum != calculated_checksum:
                logger.debug("DEBUG: Bad checksum - received: %s, calculated: %s", 
                           self.checksum, calculated_checksum)
                self.invalid = True
                
            retval = True
            if not self.fullyEstablished and self.command not in (
                    b"error", b"version", b"verack"):
                logger.debug("DEBUG: Received command %s before connection was fully established", self.command)
                self.invalid = True
                
            if not self.invalid:
                try:
                    command_method = "bm_command_" + self.command.decode("utf-8", "replace").lower()
                    logger.debug("DEBUG: Attempting to call %s", command_method)
                    retval = getattr(self, command_method)()
                except AttributeError:
                    logger.debug("DEBUG: Unimplemented command %s", self.command)
                except BMProtoInsufficientDataError:
                    logger.debug("DEBUG: Packet length too short")
                except BMProtoExcessiveDataError:
                    logger.debug("DEBUG: Too much data in packet")
                except BMObjectInsufficientPOWError:
                    logger.debug("DEBUG: Insufficient PoW")
                except BMObjectExpiredError:
                    logger.debug("DEBUG: Object expired")
                except BMObjectUnwantedStreamError:
                    logger.debug("DEBUG: Object not in wanted stream")
                except BMObjectInvalidError:
                    logger.debug("DEBUG: Object invalid")
                except BMObjectAlreadyHaveError:
                    logger.debug("DEBUG: Already have object from %(host)s:%(port)i", self.destination._asdict())
                except struct.error:
                    logger.debug("DEBUG: Decoding error")
            elif self.socket.type == socket.SOCK_DGRAM:
                logger.debug("DEBUG: Broken read on UDP socket, ignoring")
            else:
                logger.debug("DEBUG: Closing due to invalid command %s", self.command)
                self.close_reason = "Invalid command %s" % self.command
                self.set_state("close")
                return False
                
            if retval:
                logger.debug("DEBUG: Command processed successfully, resetting state")
                self.set_state("bm_header", length=self.payloadLength)
                self.bm_proto_reset()
            else:
                logger.debug("DEBUG: Command requires different state to follow")
                
            return True
        except Exception as e:
            logger.debug("DEBUG: Exception in state_bm_command: %s", str(e))
            raise

    def decode_payload_string(self, length):
        """Read and return `length` bytes from payload"""
        logger.debug("DEBUG: Decoding string of length %d from payload", length)
        value = self.payload[self.payloadOffset:self.payloadOffset + length]
        self.payloadOffset += length
        logger.debug("DEBUG: Decoded string: %s", value)
        return value

    def decode_payload_varint(self):
        """Decode a varint from the payload"""
        logger.debug("DEBUG: Decoding varint from payload")
        value, offset = addresses.decodeVarint(
            self.payload[self.payloadOffset:])
        self.payloadOffset += offset
        logger.debug("DEBUG: Decoded varint: %d (offset: %d)", value, offset)
        return value

    def decode_payload_node(self):
        """Decode node details from the payload"""
        logger.debug("DEBUG: Decoding node details from payload")
        services, host, port = self.decode_payload_content("Q16sH")
        logger.debug("DEBUG: Raw node details - services: %d, host: %s, port: %d", services, host, port)
        
        if safe_bytearray_slice(host, 0, 12) == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF':
            host = socket.inet_ntop(socket.AF_INET, _hoststr(safe_bytearray_slice(host, 12, 16)))
            logger.debug("DEBUG: IPv4-mapped IPv6 address detected, converted to: %s", host)
        elif safe_bytearray_slice(host, 0, 6) == b'\xfd\x87\xd8\x7e\xeb\x43':
            # Onion, based on BMD/bitcoind
            host = base64.b32encode(safe_bytearray_slice(host, 6)).lower() + b".onion"
            logger.debug("DEBUG: Onion address detected, converted to: %s", host)
        else:
            host = socket.inet_ntop(socket.AF_INET6, _hoststr(host))
            logger.debug("DEBUG: IPv6 address detected, converted to: %s", host)
            
        if host == b"":
            # This can happen on Windows systems which are not 64-bit
            # compatible so let us drop the IPv6 address.
            host = socket.inet_ntop(socket.AF_INET, _hoststr(safe_bytearray_slice(host, 12, 16)))
            logger.debug("DEBUG: Empty host detected, converted to IPv4: %s", host)

        node = Node(services, host, port)
        logger.debug("DEBUG: Created node: %s", node)
        return node

    # pylint: disable=too-many-branches,too-many-statements
    def decode_payload_content(self, pattern="v"):
        """
        Decode the payload depending on pattern:
        L = varint indicating the length of the next array
        l = varint indicating the length of the next item
        v = varint (or array)
        H = uint16
        I = uint32
        Q = uint64
        i = net_addr (without time and stream number)
        s = string
        0-9 = length of the next item
        , = end of array
        """
        logger.debug("DEBUG: decode_payload_content called with pattern: %s", pattern)

        def decode_simple(self, char="v"):
            """Decode the payload using one char pattern"""
            logger.debug("DEBUG: decode_simple called with char: %s", char)
            if char == "v":
                result = self.decode_payload_varint()
                logger.debug("DEBUG: Decoded varint: %d", result)
                return result
            if char == "i":
                result = self.decode_payload_node()
                logger.debug("DEBUG: Decoded node: %s", result)
                return result
            if char == "H":
                self.payloadOffset += 2
                result = struct.unpack(">H", self.payload[
                    self.payloadOffset - 2:self.payloadOffset])[0]
                logger.debug("DEBUG: Decoded uint16: %d", result)
                return result
            if char == "I":
                self.payloadOffset += 4
                result = struct.unpack(">I", self.payload[
                    self.payloadOffset - 4:self.payloadOffset])[0]
                logger.debug("DEBUG: Decoded uint32: %d", result)
                return result
            if char == "Q":
                self.payloadOffset += 8
                result = struct.unpack(">Q", self.payload[
                    self.payloadOffset - 8:self.payloadOffset])[0]
                logger.debug("DEBUG: Decoded uint64: %d", result)
                return result
            logger.debug("DEBUG: Unknown pattern character: %s", char)
            return None

        size = None
        isArray = False
        parserStack = [[1, 1, False, pattern, 0, []]]
        logger.debug("DEBUG: Initial parser stack: %s", parserStack)

        while True:
            i = parserStack[-1][3][parserStack[-1][4]]
            logger.debug("DEBUG: Current character: %s", i)
            
            if i in "0123456789" and (
                    size is None or parserStack[-1][3][parserStack[-1][4] - 1]
                    not in "lL"):
                try:
                    size = size * 10 + int(i)
                except TypeError:
                    size = int(i)
                isArray = False
                logger.debug("DEBUG: Parsed size: %d", size)
            elif i in "Ll" and size is None:
                size = self.decode_payload_varint()
                isArray = i == "L"
                logger.debug("DEBUG: Parsed varint size: %d (isArray: %s)", size, isArray)
            elif size is not None:
                if isArray:
                    parserStack.append([
                        size, size, isArray,
                        parserStack[-1][3][parserStack[-1][4]:], 0, []
                    ])
                    parserStack[-2][4] = len(parserStack[-2][3])
                    logger.debug("DEBUG: Pushed array context to stack")
                else:
                    j = 0
                    for j in range(
                            parserStack[-1][4], len(parserStack[-1][3])):
                        if parserStack[-1][3][j] not in "lL0123456789":
                            break
                    parserStack.append([
                        size, size, isArray,
                        parserStack[-1][3][parserStack[-1][4]:j + 1], 0, []
                    ])
                    parserStack[-2][4] += len(parserStack[-1][3]) - 1
                    logger.debug("DEBUG: Pushed item context to stack")
                size = None
                continue
            elif i == "s":
                parserStack[-1][5] = self.payload[
                    self.payloadOffset:self.payloadOffset + parserStack[-1][0]]
                self.payloadOffset += parserStack[-1][0]
                parserStack[-1][1] = 0
                parserStack[-1][2] = True
                logger.debug("DEBUG: Decoded string: %s", parserStack[-1][5])
                size = None
            elif i in "viHIQ":
                decoded_value = decode_simple(self, parserStack[-1][3][parserStack[-1][4]])
                parserStack[-1][5].append(decoded_value)
                logger.debug("DEBUG: Added decoded value to result: %s", decoded_value)
                size = None
            else:
                size = None
                
            for depth in range(len(parserStack) - 1, -1, -1):
                parserStack[depth][4] += 1
                if parserStack[depth][4] >= len(parserStack[depth][3]):
                    parserStack[depth][1] -= 1
                    parserStack[depth][4] = 0
                    if depth > 0:
                        if parserStack[depth][2]:
                            parserStack[depth - 1][5].append(
                                parserStack[depth][5])
                        else:
                            parserStack[depth - 1][5].extend(
                                parserStack[depth][5])
                        parserStack[depth][5] = []
                    if parserStack[depth][1] <= 0:
                        if depth == 0:
                            logger.debug("DEBUG: Finished parsing, result: %s", parserStack[depth][5])
                            return parserStack[depth][5]
                        del parserStack[-1]
                        continue
                    break
                break
                
        if self.payloadOffset > self.payloadLength:
            logger.debug("DEBUG: Insufficient data %i/%i", self.payloadOffset, self.payloadLength)
            raise BMProtoInsufficientDataError()

    def bm_command_error(self):
        """Decode an error message and log it"""
        logger.debug("DEBUG: Processing error command")
        err_values = self.decode_payload_content("vvlsls")
        fatalStatus = err_values[0]
        # banTime = err_values[1]
        # inventoryVector = err_values[2]
        errorText = err_values[3]
        logger.error(
            '%s:%i error: %i, %s', self.destination.host,
            self.destination.port, fatalStatus, errorText)
        logger.debug("DEBUG: Error command processed")
        return True

    def bm_command_getdata(self):
        """
        Incoming request for object(s).
        If we have them and some other conditions are fulfilled,
        append them to the write queue.
        """
        logger.debug("DEBUG: Processing getdata command")
        items = self.decode_payload_content("l32s")
        logger.debug("DEBUG: Received %d getdata items", len(items))
        
        now = time.time()
        if now < self.skipUntil:
            logger.debug("DEBUG: Skipping getdata due to skipUntil time")
            return True
            
        for i in items:
            self.pendingUpload[i] = now
            logger.debug("DEBUG: Added item %s to pending upload", i)
            
        logger.debug("DEBUG: getdata command processed")
        return True

    def _command_inv(self, extend_dandelion_stem=False):
        """
        Common inv announce implementation:
        both inv and dinv depending on *extend_dandelion_stem* kwarg
        """
        cmd_type = 'dinv' if extend_dandelion_stem else 'inv'
        logger.debug("DEBUG: Processing %s command", cmd_type)
        
        items = self.decode_payload_content("l32s")
        logger.debug("DEBUG: Received %d %s items", len(items), cmd_type)

        if len(items) > protocol.MAX_OBJECT_COUNT:
            logger.error(
                'Too many items in %sinv message!', 'd' if extend_dandelion_stem else '')
            logger.debug("DEBUG: %s message contains too many items (%d > %d)", 
                        cmd_type, len(items), protocol.MAX_OBJECT_COUNT)
            raise BMProtoExcessiveDataError()

        # ignore dinv if dandelion turned off
        if extend_dandelion_stem and not dandelion_ins.enabled:
            logger.debug("DEBUG: Dandelion is disabled, ignoring dinv")
            return True

        for i in items:
            if i in state.Inventory and not dandelion_ins.hasHash(i):
                logger.debug("DEBUG: Already have item %s and not in dandelion, skipping", i)
                continue
            if extend_dandelion_stem and not dandelion_ins.hasHash(i):
                logger.debug("DEBUG: Adding hash %s to dandelion", i)
                dandelion_ins.addHash(i, self)
            logger.debug("DEBUG: Handling received inventory %s", i)
            self.handleReceivedInventory(i)

        logger.debug("DEBUG: %s command processed", cmd_type)
        return True

    def bm_command_inv(self):
        """Non-dandelion announce"""
        logger.debug("DEBUG: Processing inv command")
        return self._command_inv(False)

    def bm_command_dinv(self):
        """Dandelion stem announce"""
        logger.debug("DEBUG: Processing dinv command")
        return self._command_inv(True)

    def bm_command_object(self):
        """Incoming object, process it"""
        logger.debug("DEBUG: Processing object command")
        objectOffset = self.payloadOffset
        nonce, expiresTime, objectType, version, streamNumber = \
            self.decode_payload_content("QQIvv")
        logger.debug("DEBUG: Object metadata - nonce: %d, expiresTime: %d, type: %d, version: %d, stream: %d",
                   nonce, expiresTime, objectType, version, streamNumber)
        
        self.object = BMObject(
            nonce, expiresTime, objectType, version, streamNumber,
            self.payload, self.payloadOffset)
        logger.debug("DEBUG: Created BMObject instance")

        payload_len = len(self.payload) - self.payloadOffset
        if payload_len > protocol.MAX_OBJECT_PAYLOAD_SIZE:
            logger.info(
                'The payload length of this object is too large'
                ' (%d bytes). Ignoring it.', payload_len)
            logger.debug("DEBUG: Payload size %d exceeds maximum %d", 
                       payload_len, protocol.MAX_OBJECT_PAYLOAD_SIZE)
            raise BMProtoExcessiveDataError()

        try:
            logger.debug("DEBUG: Checking object POW")
            self.object.checkProofOfWorkSufficient()
            logger.debug("DEBUG: Checking object EOL sanity")
            self.object.checkEOLSanity()
            logger.debug("DEBUG: Checking if we already have object")
            self.object.checkAlreadyHave()
        except (BMObjectExpiredError, BMObjectAlreadyHaveError,
                BMObjectInsufficientPOWError) as e:
            logger.debug("DEBUG: Object validation failed: %s", str(e))
            BMProto.stopDownloadingObject(self.object.inventoryHash)
            raise
            
        try:
            logger.debug("DEBUG: Checking object stream")
            self.object.checkStream()
        except BMObjectUnwantedStreamError as e:
            logger.debug("DEBUG: Object stream check failed: %s", str(e))
            acceptmismatch = config.getboolean(
                "inventory", "acceptmismatch")
            BMProto.stopDownloadingObject(
                self.object.inventoryHash, acceptmismatch)
            if not acceptmismatch:
                raise
        except BMObjectInvalidError as e:
            logger.debug("DEBUG: Object is invalid: %s", str(e))
            BMProto.stopDownloadingObject(self.object.inventoryHash)
            raise

        try:
            logger.debug("DEBUG: Checking object by type")
            self.object.checkObjectByType()
            if six.PY2:
                data_buffer = buffer(self.object.data)
            else:  # assume six.PY3
                data_buffer = memoryview(self.object.data)
            logger.debug("DEBUG: Putting object in processor queue")
            objectProcessorQueue.put((
                self.object.objectType, data_buffer))  # noqa: F821
        except BMObjectInvalidError as e:
            logger.debug("DEBUG: Object type check failed: %s", str(e))
            BMProto.stopDownloadingObject(self.object.inventoryHash, True)
        else:
            try:
                logger.debug("DEBUG: Removing object from missingObjects")
                del missingObjects[bytes(self.object.inventoryHash)]
            except KeyError:
                logger.debug("DEBUG: Object not in missingObjects")
                pass

        if self.object.inventoryHash in state.Inventory and dandelion_ins.hasHash(
                self.object.inventoryHash):
            logger.debug("DEBUG: Removing object from dandelion (cycle detection)")
            dandelion_ins.removeHash(
                self.object.inventoryHash, "cycle detection")

        if six.PY2:
            object_buffer = buffer(self.payload[objectOffset:])
            tag_buffer = buffer(self.object.tag)
        else:  # assume six.PY3
            object_buffer = memoryview(self.payload[objectOffset:])
            tag_buffer = memoryview(self.object.tag)
            
        logger.debug("DEBUG: Adding object to inventory")
        state.Inventory[self.object.inventoryHash] = (
            self.object.objectType, self.object.streamNumber,
            object_buffer, self.object.expiresTime,  # noqa: F821
            tag_buffer  # noqa: F821
        )
        
        logger.debug("DEBUG: Handling received object")
        self.handleReceivedObject(
            self.object.streamNumber, self.object.inventoryHash)
            
        logger.debug("DEBUG: Adding object to invQueue")
        invQueue.put((
            self.object.streamNumber, self.object.inventoryHash,
            self.destination))
            
        logger.debug("DEBUG: Object command processed")
        return True

    def _decode_addr(self):
        logger.debug("DEBUG: Decoding addr message")
        return self.decode_payload_content("LQIQ16sH")

    def bm_command_addr(self):
        """Incoming addresses, process them"""
        logger.debug("DEBUG: Processing addr command")
        # not using services
        for seenTime, stream, _, ip, port in self._decode_addr():
            logger.debug("DEBUG: Processing address - seenTime: %d, stream: %d, ip: %s, port: %d",
                        seenTime, stream, ip, port)
            
            if (
                stream not in network.connectionpool.pool.streams
                # FIXME: should check against complete list
                or ip.decode("utf-8", "replace").startswith('bootstrap')
            ):
                logger.debug("DEBUG: Skipping address - stream not in pool or bootstrap IP")
                continue
                
            decodedIP = protocol.checkIPAddress(ip)
            if (
                decodedIP and time.time() - seenTime > 0
                and seenTime > time.time() - protocol.ADDRESS_ALIVE
                and port > 0
            ):
                peer = Peer(decodedIP, port)
                logger.debug("DEBUG: Valid address - peer: %s", peer)

                with knownnodes.knownNodesLock:
                    # isnew =
                    knownnodes.addKnownNode(stream, peer, seenTime)
                    logger.debug("DEBUG: Added known node to stream %d", stream)

                # since we don't track peers outside of knownnodes,
                # only spread if in knownnodes to prevent flood
                # DISABLED TO WORKAROUND FLOOD/LEAK
                # if isnew:
                #     addrQueue.put((
                #         stream, peer, seenTime, self.destination))
        logger.debug("DEBUG: addr command processed")
        return True

    def bm_command_portcheck(self):
        """Incoming port check request, queue it."""
        logger.debug("DEBUG: Processing portcheck command")
        portCheckerQueue.put(Peer(self.destination, self.peerNode.port))
        logger.debug("DEBUG: Added port check to queue")
        return True

    def bm_command_ping(self):
        """Incoming ping, respond to it."""
        logger.debug("DEBUG: Processing ping command")
        self.append_write_buf(protocol.CreatePacket(b'pong'))
        logger.debug("DEBUG: Sent pong response")
        return True

    @staticmethod
    def bm_command_pong():
        """
        Incoming pong.
        Ignore it. PyBitmessage pings connections after about 5 minutes
        of inactivity, and leaves it to the TCP stack to handle actual
        timeouts. So there is no need to do anything when a pong arrives.
        """
        logger.debug("DEBUG: Processing pong command (no action taken)")
        # nothing really
        return True

    def bm_command_verack(self):
        """
        Incoming verack.
        If already sent my own verack, handshake is complete (except
        potentially waiting for buffers to flush), so we can continue
        to the main connection phase. If not sent verack yet,
        continue processing.
        """
        logger.debug("DEBUG: Processing verack command")
        self.verackReceived = True
        if not self.verackSent:
            logger.debug("DEBUG: Verack not yet sent, continuing processing")
            return True
            
        logger.debug("DEBUG: Verack handshake complete")
        self.set_state(
            "tls_init" if self.isSSL else "connection_fully_established",
            length=self.payloadLength, expectBytes=0)
        return False

    def bm_command_version(self):
        """
        Incoming version.
        Parse and log, remember important things, like streams, bitfields, etc.
        """
        logger.debug("DEBUG: Processing version command")
        decoded = self.decode_payload_content("IQQiiQlslv")
        (self.remoteProtocolVersion, self.services, self.timestamp,
         self.sockNode, self.peerNode, self.nonce, self.userAgent
         ) = decoded[:7]
        self.streams = safe_bytearray_slice(decoded, 7)
        self.nonce = struct.pack('>Q', self.nonce)
        self.timeOffset = self.timestamp - int(time.time())
        
        logger.debug('DEBUG: remoteProtocolVersion: %i', self.remoteProtocolVersion)
        logger.debug('DEBUG: services: 0x%08X', self.services)
        logger.debug('DEBUG: time offset: %i', self.timeOffset)
        logger.debug('DEBUG: my external IP: %s', self.sockNode.host)
        logger.debug(
            'DEBUG: remote node incoming address: %s:%i',
            self.destination.host, self.peerNode.port)
        logger.debug('DEBUG: user agent: %s', self.userAgent.decode("utf-8", "replace"))
        logger.debug('DEBUG: streams: [%s]', ','.join(map(str, self.streams)))
        
        if not self.peerValidityChecks():
            logger.debug("DEBUG: Peer validity checks failed")
            # ABORT afterwards
            return True
            
        logger.debug("DEBUG: Sending verack")
        self.append_write_buf(protocol.CreatePacket(b'verack'))
        self.verackSent = True
        
        ua_valid = re.match(
            r'^/[a-zA-Z]+:[0-9]+\.?[\w\s\(\)\./:;-]*/$', _restr(self.userAgent))
        if not ua_valid:
            logger.debug("DEBUG: Invalid user agent format: %s", self.userAgent)
            self.userAgent = b'/INVALID:0/'
            
        if not self.isOutbound:
            logger.debug("DEBUG: Sending version message (inbound connection)")
            self.append_write_buf(protocol.assembleVersionMessage(
                self.destination.host, self.destination.port,
                network.connectionpool.pool.streams, dandelion_ins.enabled, True,
                nodeid=self.nodeid))
            logger.debug(
                'DEBUG: %(host)s:%(port)i sending version',
                self.destination._asdict())
                
        if ((self.services & protocol.NODE_SSL == protocol.NODE_SSL)
           and protocol.haveSSL(not self.isOutbound)):
            logger.debug("DEBUG: SSL service detected and available")
            self.isSSL = True
            
        if not self.verackReceived:
            logger.debug("DEBUG: Waiting for verack")
            return True
            
        logger.debug("DEBUG: Version handshake complete")
        self.set_state(
            "tls_init" if self.isSSL else "connection_fully_established",
            length=self.payloadLength, expectBytes=0)
        return False

    # pylint: disable=too-many-return-statements
    def peerValidityChecks(self):
        """Check the validity of the peer"""
        logger.debug("DEBUG: Performing peer validity checks")
        
        if self.remoteProtocolVersion < 3:
            self.append_write_buf(protocol.assembleErrorMessage(
                errorText="Your is using an old protocol. Closing connection.",
                fatal=2))
            logger.debug(
                'DEBUG: Closing connection to old protocol version %s, node: %s',
                self.remoteProtocolVersion, self.destination)
            return False
                
        if self.timeOffset > protocol.MAX_TIME_OFFSET:
            self.append_write_buf(protocol.assembleErrorMessage(
                errorText="Your time is too far in the future"
                " compared to mine. Closing connection.", fatal=2))
            logger.info(
                "DEBUG: %s's time is too far in the future (%s seconds)."
                " Closing connection to it.",
                self.destination, self.timeOffset)
            BMProto.timeOffsetWrongCount += 1
            return False
        elif self.timeOffset < -protocol.MAX_TIME_OFFSET:
            self.append_write_buf(protocol.assembleErrorMessage(
                errorText="Your time is too far in the past compared to mine."
                " Closing connection.", fatal=2))
            logger.info(
                "DEBUG: %s's time is too far in the past"
                " (timeOffset %s seconds). Closing connection to it.",
                self.destination, self.timeOffset)
            BMProto.timeOffsetWrongCount += 1
            return False
        else:
            BMProto.timeOffsetWrongCount = 0
            
        if not self.streams:
            self.append_write_buf(protocol.assembleErrorMessage(
                errorText="We don't have shared stream interests."
                " Closing connection.", fatal=2))
            logger.debug(
                'DEBUG: Closed connection to %s because there is no overlapping'
                ' interest in streams.', self.destination)
            return False
                
        if network.connectionpool.pool.inboundConnections.get(
                self.destination):
            try:
                if not protocol.checkSocksIP(self.destination.host):
                    self.append_write_buf(protocol.assembleErrorMessage(
                        errorText="Too many connections from your IP."
                        " Closing connection.", fatal=2))
                    logger.debug(
                        'DEBUG: Closed connection to %s because we are already'
                        ' connected to that IP.', self.destination)
                    return False
            except Exception:  # nosec B110 # pylint:disable=broad-exception-caught
                logger.debug("DEBUG: Exception in socks IP check", exc_info=True)
                pass
                
        if not self.isOutbound:
            # incoming from a peer we're connected to as outbound,
            # or server full report the same error to counter deanonymisation
            if (
                Peer(self.destination.host, self.peerNode.port)
                in network.connectionpool.pool.inboundConnections
                or len(network.connectionpool.pool)
                > config.safeGetInt(
                    'bitmessagesettings', 'maxtotalconnections')
                + config.safeGetInt(
                    'bitmessagesettings', 'maxbootstrapconnections')
            ):
                self.append_write_buf(protocol.assembleErrorMessage(
                    errorText="Server full, please try again later.", fatal=2))
                logger.debug(
                    'DEBUG: Closed connection to %s due to server full'
                    ' or duplicate inbound/outbound.', self.destination)
                return False
                    
        if network.connectionpool.pool.isAlreadyConnected(self.nonce):
            self.append_write_buf(protocol.assembleErrorMessage(
                errorText="I'm connected to myself. Closing connection.",
                fatal=2))
            logger.debug(
                "DEBUG: Closed connection to %s because I'm connected to myself.",
                self.destination)
            return False

        logger.debug("DEBUG: Peer validity checks passed")
        return True

    @staticmethod
    def stopDownloadingObject(hashId, forwardAnyway=False):
        """Stop downloading object *hashId*"""
        logger.debug("DEBUG: Stopping download of object %s (forwardAnyway: %s)", 
                    hashId, forwardAnyway)
        for connection in network.connectionpool.pool.connections():
            try:
                del connection.objectsNewToMe[hashId]
                logger.debug("DEBUG: Removed object from objectsNewToMe for connection %s", connection)
            except KeyError:
                pass
            if not forwardAnyway:
                try:
                    with connection.objectsNewToThemLock:
                        del connection.objectsNewToThem[hashId]
                        logger.debug("DEBUG: Removed object from objectsNewToThem for connection %s", connection)
                except KeyError:
                    pass
        try:
            del missingObjects[bytes(hashId)]
            logger.debug("DEBUG: Removed object from missingObjects")
        except KeyError:
            logger.debug("DEBUG: Object not in missingObjects")
            pass

    def handle_close(self):
        """Handle close"""
        logger.debug("DEBUG: Handling connection close")
        self.set_state("close")
        if not (self.accepting or self.connecting or self.connected):
            logger.debug("DEBUG: Already disconnected")
            # already disconnected
            return
        try:
            logger.debug(
                'DEBUG: %s:%i: closing, %s', self.destination.host,
                self.destination.port, self.close_reason)
        except AttributeError:
            try:
                logger.debug(
                    'DEBUG: %s:%i: closing',
                    self.destination.host, self.destination.port)
            except AttributeError:
                logger.debug('DEBUG: Disconnected socket closing')
        AdvancedDispatcher.handle_close(self)
        logger.debug("DEBUG: Connection closed")
