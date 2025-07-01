"""
BMObject and it's exceptions.
"""
import logging
import time

import protocol
import state
import network.connectionpool  # use long name to address recursive import
from network import dandelion_ins
from highlevelcrypto import calculateInventoryHash

logger = logging.getLogger('default')


class BMObjectInsufficientPOWError(Exception):
    """Exception indicating the object
    doesn't have sufficient proof of work."""
    errorCodes = ("Insufficient proof of work")


class BMObjectExpiredError(Exception):
    """Exception indicating the object's lifetime has expired."""
    errorCodes = ("Object expired")


class BMObjectUnwantedStreamError(Exception):
    """Exception indicating the object is in a stream
    we didn't advertise as being interested in."""
    errorCodes = ("Object in unwanted stream")


class BMObjectInvalidError(Exception):
    """The object's data does not match object specification."""
    errorCodes = ("Invalid object")


class BMObjectAlreadyHaveError(Exception):
    """We received a duplicate object (one we already have)"""
    errorCodes = ("Already have this object")


class BMObject(object):  # pylint: disable=too-many-instance-attributes
    """Bitmessage Object as a class."""

    # max TTL, 28 days and 3 hours
    maxTTL = 28 * 24 * 60 * 60 + 10800
    # min TTL, 3 hour (in the past
    minTTL = -3600

    def __init__(
            self,
            nonce,
            expiresTime,
            objectType,
            version,
            streamNumber,
            data,
            payloadOffset
    ):  # pylint: disable=too-many-arguments
        logger.debug("DEBUG: BMObject.__init__ called with nonce=%s, expiresTime=%d, "
                   "objectType=%d, version=%d, streamNumber=%d, data_len=%d, payloadOffset=%d",
                   nonce, expiresTime, objectType, version, streamNumber, len(data), payloadOffset)
        
        self.nonce = nonce
        self.expiresTime = expiresTime
        self.objectType = objectType
        self.version = version
        self.streamNumber = streamNumber
        self.inventoryHash = calculateInventoryHash(data)
        logger.debug("DEBUG: Calculated inventory hash: %s", self.inventoryHash)
        
        # copy to avoid memory issues
        self.data = bytearray(data)
        self.tag = self.data[payloadOffset:payloadOffset + 32]
        logger.debug("DEBUG: Created BMObject instance")

    def checkProofOfWorkSufficient(self):
        """Perform a proof of work check for sufficiency."""
        logger.debug("DEBUG: Checking proof of work for object %s", self.inventoryHash)
        # Let us check to make sure that the proof of work is sufficient.
        if not protocol.isProofOfWorkSufficient(self.data):
            logger.info('Proof of work is insufficient.')
            logger.debug("DEBUG: Proof of work check failed for object %s", self.inventoryHash)
            raise BMObjectInsufficientPOWError()
        logger.debug("DEBUG: Proof of work sufficient for object %s", self.inventoryHash)

    def checkEOLSanity(self):
        """Check if object's lifetime
        isn't ridiculously far in the past or future."""
        logger.debug("DEBUG: Checking EOL sanity for object %s", self.inventoryHash)
        current_time = int(time.time())
        time_diff = self.expiresTime - current_time
        logger.debug("DEBUG: Current time: %d, expiresTime: %d, difference: %d", 
                    current_time, self.expiresTime, time_diff)
        
        # EOL sanity check
        if time_diff > BMObject.maxTTL:
            logger.info(
                'This object\'s End of Life time is too far in the future.'
                ' Ignoring it. Time is %i', self.expiresTime)
            logger.debug("DEBUG: Object %s expires too far in future (diff: %d > maxTTL: %d)", 
                       self.inventoryHash, time_diff, BMObject.maxTTL)
            raise BMObjectExpiredError()

        if time_diff < BMObject.minTTL:
            logger.info(
                'This object\'s End of Life time was too long ago.'
                ' Ignoring the object. Time is %i', self.expiresTime)
            logger.debug("DEBUG: Object %s expired too long ago (diff: %d < minTTL: %d)", 
                       self.inventoryHash, time_diff, BMObject.minTTL)
            raise BMObjectExpiredError()
            
        logger.debug("DEBUG: EOL sanity check passed for object %s", self.inventoryHash)

    def checkStream(self):
        """Check if object's stream matches streams we are interested in"""
        logger.debug("DEBUG: Checking stream for object %s (stream %d)", 
                   self.inventoryHash, self.streamNumber)
        
        if self.streamNumber < protocol.MIN_VALID_STREAM \
           or self.streamNumber > protocol.MAX_VALID_STREAM:
            logger.warning(
                'The object has invalid stream: %s', self.streamNumber)
            logger.debug("DEBUG: Object %s has invalid stream number %d (valid range: %d-%d)", 
                       self.inventoryHash, self.streamNumber, 
                       protocol.MIN_VALID_STREAM, protocol.MAX_VALID_STREAM)
            raise BMObjectInvalidError()
            
        if self.streamNumber not in network.connectionpool.pool.streams:
            logger.debug(
                'The streamNumber %i isn\'t one we are interested in.',
                self.streamNumber)
            logger.debug("DEBUG: Object %s in unwanted stream %d (our streams: %s)", 
                       self.inventoryHash, self.streamNumber, 
                       network.connectionpool.pool.streams)
            raise BMObjectUnwantedStreamError()
            
        logger.debug("DEBUG: Stream check passed for object %s", self.inventoryHash)

    def checkAlreadyHave(self):
        """
        Check if we already have the object
        (so that we don't duplicate it in inventory
        or advertise it unnecessarily)
        """
        logger.debug("DEBUG: Checking if we already have object %s", self.inventoryHash)
        
        # if it's a stem duplicate, pretend we don't have it
        if dandelion_ins.hasHash(self.inventoryHash):
            logger.debug("DEBUG: Object %s is in dandelion stem, skipping duplicate check", 
                       self.inventoryHash)
            return
           
        if self.inventoryHash in state.Inventory:
            logger.debug("DEBUG: Already have object %s in inventory", self.inventoryHash)
            raise BMObjectAlreadyHaveError()
            
        logger.debug("DEBUG: Object %s not already in inventory", self.inventoryHash)

    def checkObjectByType(self):
        """Call a object type specific check
        (objects can have additional checks based on their types)"""
        logger.debug("DEBUG: Performing type-specific check for object %s (type: %d)", 
                   self.inventoryHash, self.objectType)
        
        if self.objectType == protocol.OBJECT_GETPUBKEY:
            logger.debug("DEBUG: Checking GETPUBKEY object")
            self.checkGetpubkey()
        elif self.objectType == protocol.OBJECT_PUBKEY:
            logger.debug("DEBUG: Checking PUBKEY object")
            self.checkPubkey()
        elif self.objectType == protocol.OBJECT_MSG:
            logger.debug("DEBUG: Checking MSG object")
            self.checkMessage()
        elif self.objectType == protocol.OBJECT_BROADCAST:
            logger.debug("DEBUG: Checking BROADCAST object")
            self.checkBroadcast()
        else:
            logger.debug("DEBUG: No specific checks for object type %d", self.objectType)
        # other objects don't require other types of tests

    def checkMessage(self):  # pylint: disable=no-self-use
        """"Message" object type checks."""
        logger.debug("DEBUG: No specific checks for MSG object type")
        return

    def checkGetpubkey(self):
        """"Getpubkey" object type checks."""
        logger.debug("DEBUG: Checking GETPUBKEY object validity")
        if len(self.data) < 42:
            logger.info(
                'getpubkey message doesn\'t contain enough data. Ignoring.')
            logger.debug("DEBUG: GETPUBKEY object too short (%d bytes)", len(self.data))
            raise BMObjectInvalidError()
        logger.debug("DEBUG: GETPUBKEY object check passed")

    def checkPubkey(self):
        """"Pubkey" object type checks."""
        logger.debug("DEBUG: Checking PUBKEY object validity")
        # sanity check
        if len(self.data) < 146 or len(self.data) > 440:
            logger.info('pubkey object too short or too long. Ignoring.')
            logger.debug("DEBUG: PUBKEY object invalid length (%d bytes)", len(self.data))
            raise BMObjectInvalidError()
        logger.debug("DEBUG: PUBKEY object check passed")

    def checkBroadcast(self):
        """"Broadcast" object type checks."""
        logger.debug("DEBUG: Checking BROADCAST object validity")
        if len(self.data) < 180:
            logger.debug(
                'The payload length of this broadcast'
                ' packet is unreasonably low. Someone is probably'
                ' trying funny business. Ignoring message.')
            logger.debug("DEBUG: BROADCAST object too short (%d bytes)", len(self.data))
            raise BMObjectInvalidError()

        # this isn't supported anymore
        if self.version < 2:
            logger.debug("DEBUG: BROADCAST object version too old (%d)", self.version)
            raise BMObjectInvalidError()
        logger.debug("DEBUG: BROADCAST object check passed")
