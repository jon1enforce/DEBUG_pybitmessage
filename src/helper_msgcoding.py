"""
Message encoding end decoding functions
"""

import zlib

import messagetypes
from bmconfigparser import config
from debug import logger
from tr import _translate

try:
    import msgpack
    logger.debug("DEBUG: Using msgpack library")
except ImportError:
    try:
        import umsgpack as msgpack
        logger.debug("DEBUG: Using umsgpack library")
    except ImportError:
        import fallback.umsgpack.umsgpack as msgpack
        logger.debug("DEBUG: Using fallback umsgpack library")

BITMESSAGE_ENCODING_IGNORE = 0
BITMESSAGE_ENCODING_TRIVIAL = 1
BITMESSAGE_ENCODING_SIMPLE = 2
BITMESSAGE_ENCODING_EXTENDED = 3


class MsgEncodeException(Exception):
    """Exception during message encoding"""
    pass


class MsgDecodeException(Exception):
    """Exception during message decoding"""
    pass


class DecompressionSizeException(MsgDecodeException):
    # pylint: disable=super-init-not-called
    """Decompression resulted in too much data (attack protection)"""
    def __init__(self, size):
        logger.debug("DEBUG: DecompressionSizeException created with size: %d", size)
        self.size = size


class MsgEncode(object):
    """Message encoder class"""
    def __init__(self, message, encoding=BITMESSAGE_ENCODING_SIMPLE):
        logger.debug("DEBUG: MsgEncode init with encoding: %d", encoding)
        self.data = None
        self.encoding = encoding
        self.length = 0
        if self.encoding == BITMESSAGE_ENCODING_EXTENDED:
            logger.debug("DEBUG: Using extended encoding")
            self.encodeExtended(message)
        elif self.encoding == BITMESSAGE_ENCODING_SIMPLE:
            logger.debug("DEBUG: Using simple encoding")
            self.encodeSimple(message)
        elif self.encoding == BITMESSAGE_ENCODING_TRIVIAL:
            logger.debug("DEBUG: Using trivial encoding")
            self.encodeTrivial(message)
        else:
            error_msg = "Unknown encoding %i" % encoding
            logger.error("DEBUG: Encoding error: %s", error_msg)
            raise MsgEncodeException(error_msg)

    def encodeExtended(self, message):
        """Handle extended encoding"""
        logger.debug("DEBUG: Starting extended encoding")
        try:
            msgObj = messagetypes.message.Message()
            logger.debug("DEBUG: Created Message object")
            
            packed = msgpack.dumps(msgObj.encode(message))
            logger.debug("DEBUG: Message packed, length: %d", len(packed))
            
            self.data = zlib.compress(packed, 9)
            logger.debug("DEBUG: Message compressed, length: %d", len(self.data))
            
        except zlib.error as e:
            logger.error("DEBUG: Compression error: %s", str(e))
            raise MsgEncodeException("Error compressing message")
        except msgpack.exceptions.PackException as e:
            logger.error("DEBUG: Msgpack error: %s", str(e))
            raise MsgEncodeException("Error msgpacking message")
        self.length = len(self.data)
        logger.debug("DEBUG: Extended encoding complete, final length: %d", self.length)

    def encodeSimple(self, message):
        """Handle simple encoding"""
        logger.debug("DEBUG: Starting simple encoding")
        data = 'Subject:%(subject)s\nBody:%(body)s' % message
        logger.debug("DEBUG: Formatted message: %s", data[:100] + "..." if len(data) > 100 else data)
        
        self.data = data.encode("utf-8", "replace")
        self.length = len(self.data)
        logger.debug("DEBUG: Simple encoding complete, length: %d", self.length)

    def encodeTrivial(self, message):
        """Handle trivial encoding"""
        logger.debug("DEBUG: Starting trivial encoding")
        self.data = message['body']
        self.length = len(self.data)
        logger.debug("DEBUG: Trivial encoding complete, length: %d", self.length)


class MsgDecode(object):
    """Message decoder class"""
    def __init__(self, encoding, data):
        logger.debug("DEBUG: MsgDecode init with encoding: %d, data length: %d", 
                    encoding, len(data) if data else 0)
        self.encoding = encoding
        if self.encoding == BITMESSAGE_ENCODING_EXTENDED:
            logger.debug("DEBUG: Using extended decoding")
            self.decodeExtended(data)
        elif self.encoding in (
                BITMESSAGE_ENCODING_SIMPLE, BITMESSAGE_ENCODING_TRIVIAL):
            logger.debug("DEBUG: Using simple/trivial decoding")
            self.decodeSimple(data)
        else:
            logger.debug("DEBUG: Unknown encoding encountered")
            self.body = _translate(
                "MsgDecode",
                "The message has an unknown encoding.\n"
                "Perhaps you should upgrade Bitmessage.")
            self.subject = _translate("MsgDecode", "Unknown encoding")

    def decodeExtended(self, data):
        """Handle extended encoding"""
        logger.debug("DEBUG: Starting extended decoding")
        dc = zlib.decompressobj()
        tmp = b""
        maxsize = config.safeGetInt("zlib", "maxsize")
        logger.debug("DEBUG: Max decompression size: %d", maxsize)
        
        while len(tmp) <= maxsize:
            try:
                got = dc.decompress(data, maxsize + 1 - len(tmp))
                logger.debug("DEBUG: Decompressed chunk, size: %d", len(got))
                
                # EOF
                if got == b"":
                    logger.debug("DEBUG: Reached end of compressed data")
                    break
                    
                tmp += got
                data = dc.unconsumed_tail
                logger.debug("DEBUG: Total decompressed so far: %d", len(tmp))
                
            except zlib.error as e:
                logger.error("DEBUG: Decompression error: %s", str(e))
                raise MsgDecodeException("Error decompressing message")
        else:
            logger.error("DEBUG: Decompression size exceeded: %d", len(tmp))
            raise DecompressionSizeException(len(tmp))

        try:
            logger.debug("DEBUG: Unpacking msgpack data")
            tmp = msgpack.loads(tmp)
            logger.debug("DEBUG: Successfully unpacked msgpack data")
        except (msgpack.exceptions.UnpackException,
                msgpack.exceptions.ExtraData) as e:
            logger.error("DEBUG: Msgunpack error: %s", str(e))
            raise MsgDecodeException("Error msgunpacking message")

        try:
            msgType = tmp[""]
            logger.debug("DEBUG: Message type: %s", msgType)
        except KeyError:
            logger.error("DEBUG: Message type missing")
            raise MsgDecodeException("Message type missing")

        msgObj = messagetypes.constructObject(tmp)
        if msgObj is None:
            logger.error("DEBUG: Failed to construct message object")
            raise MsgDecodeException("Malformed message")
            
        logger.debug("DEBUG: Constructed message object of type: %s", type(msgObj))
        
        try:
            msgObj.process()
            logger.debug("DEBUG: Successfully processed message")
        except Exception as e:
            logger.error("DEBUG: Message processing error: %s", str(e))
            raise MsgDecodeException("Malformed message")
            
        if msgType == "message":
            logger.debug("DEBUG: Setting subject and body from message object")
            self.subject = msgObj.subject
            self.body = msgObj.body
            logger.debug("DEBUG: Subject: %s", self.subject[:50] + "..." if len(self.subject) > 50 else self.subject)

    def decodeSimple(self, data):
        """Handle simple encoding"""
        logger.debug("DEBUG: Starting simple decoding")
        bodyPositionIndex = data.find(b'\nBody:')
        logger.debug("DEBUG: Body position index: %d", bodyPositionIndex)
        
        if bodyPositionIndex > 1:
            subject = data[8:bodyPositionIndex]
            logger.debug("DEBUG: Raw subject (len %d): %s", 
                        len(subject), subject[:50] + b"..." if len(subject) > 50 else subject)
            
            # Only save and show the first 500 characters of the subject.
            # Any more is probably an attack.
            subject = subject[:500]
            body = data[bodyPositionIndex + 6:]
            logger.debug("DEBUG: Raw body (len %d): %s", 
                        len(body), body[:100] + b"..." if len(body) > 100 else body)
        else:
            logger.debug("DEBUG: No body marker found")
            subject = b''
            body = data
            
        # Throw away any extra lines (headers) after the subject.
        if subject:
            subject = subject.splitlines()[0]
            logger.debug("DEBUG: Cleaned subject (len %d): %s", 
                        len(subject), subject[:50] + b"..." if len(subject) > 50 else subject)
            
        # Field types should be the same for all message types
        self.subject = subject.decode("utf-8", "replace")
        self.body = body.decode("utf-8", "replace")
        logger.debug("DEBUG: Decoding complete")
        logger.debug("DEBUG: Final subject (len %d): %s", 
                    len(self.subject), self.subject[:50] + "..." if len(self.subject) > 50 else self.subject)
        logger.debug("DEBUG: Final body length: %d", len(self.body))
