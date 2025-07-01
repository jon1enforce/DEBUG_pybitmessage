"""
Module for tracking objects
"""
import time
from threading import RLock
import six
import logging

import network.connectionpool  # use long name to address recursive import
from network import dandelion_ins
from randomtrackingdict import RandomTrackingDict

logger = logging.getLogger('default')

haveBloom = False

try:
    # pybloomfiltermmap
    from pybloomfilter import BloomFilter
    haveBloom = True
    logger.debug("DEBUG: Successfully imported pybloomfiltermmap")
except ImportError:
    try:
        # pybloom
        from pybloom import BloomFilter
        haveBloom = True
        logger.debug("DEBUG: Successfully imported pybloom")
    except ImportError:
        logger.debug("DEBUG: No BloomFilter implementation found")

# it isn't actually implemented yet so no point in turning it on
haveBloom = False
logger.debug("DEBUG: BloomFilter functionality manually disabled")

# tracking pending downloads globally, for stats
missingObjects = {}
logger.debug("DEBUG: Initialized missingObjects dictionary")


class ObjectTracker(object):
    """Object tracker mixin"""
    invCleanPeriod = 300
    invInitialCapacity = 50000
    invErrorRate = 0.03
    trackingExpires = 3600
    initialTimeOffset = 60

    def __init__(self):
        logger.debug("DEBUG: Initializing ObjectTracker")
        self.objectsNewToMe = RandomTrackingDict()
        self.objectsNewToThem = {}
        self.objectsNewToThemLock = RLock()
        self.initInvBloom()
        self.initAddrBloom()
        self.lastCleaned = time.time()
        logger.debug("DEBUG: ObjectTracker initialized with lastCleaned=%f", 
                    self.lastCleaned)

    def initInvBloom(self):
        """Init bloom filter for tracking. WIP."""
        logger.debug("DEBUG: Initializing inventory BloomFilter")
        if haveBloom:
            self.invBloom = BloomFilter(
                capacity=ObjectTracker.invInitialCapacity,
                error_rate=ObjectTracker.invErrorRate)
            logger.debug("DEBUG: Created inventory BloomFilter with capacity=%d, error_rate=%f",
                        ObjectTracker.invInitialCapacity, ObjectTracker.invErrorRate)
        else:
            logger.debug("DEBUG: BloomFilter not available, using standard dictionary")

    def initAddrBloom(self):
        """Init bloom filter for tracking addrs, WIP."""
        logger.debug("DEBUG: Initializing address BloomFilter")
        if haveBloom:
            self.addrBloom = BloomFilter(
                capacity=ObjectTracker.invInitialCapacity,
                error_rate=ObjectTracker.invErrorRate)
            logger.debug("DEBUG: Created address BloomFilter with capacity=%d, error_rate=%f",
                        ObjectTracker.invInitialCapacity, ObjectTracker.invErrorRate)

    def clean(self):
        """Clean up tracking to prevent memory bloat"""
        current_time = time.time()
        time_since_last_clean = current_time - self.lastCleaned
        
        logger.debug("DEBUG: Checking if cleanup needed. Last cleaned: %.2f seconds ago", 
                    time_since_last_clean)
        
        if time_since_last_clean > ObjectTracker.invCleanPeriod:
            logger.debug("DEBUG: Performing cleanup")
            
            if haveBloom:
                if len(missingObjects) == 0:
                    logger.debug("DEBUG: Reinitializing inventory BloomFilter")
                    self.initInvBloom()
                logger.debug("DEBUG: Reinitializing address BloomFilter")
                self.initAddrBloom()
            else:
                deadline = current_time - ObjectTracker.trackingExpires
                logger.debug("DEBUG: Cleaning objectsNewToThem with deadline=%f", deadline)
                
                with self.objectsNewToThemLock:
                    before = len(self.objectsNewToThem)
                    self.objectsNewToThem = {
                        k: v
                        for k, v in six.iteritems(self.objectsNewToThem)
                        if v >= deadline}
                    after = len(self.objectsNewToThem)
                    logger.debug("DEBUG: Cleaned %d expired items from objectsNewToThem", 
                                before - after)
            
            self.lastCleaned = current_time
            logger.debug("DEBUG: Cleanup completed, new lastCleaned=%f", self.lastCleaned)

    def hasObj(self, hashid):
        """Do we already have object?"""
        hashid_bytes = bytes(hashid)
        logger.debug("DEBUG: Checking if object exists: %s", hashid_bytes)
        
        if haveBloom:
            result = hashid_bytes in self.invBloom
            logger.debug("DEBUG: BloomFilter check result: %s", result)
            return result
        
        result = hashid_bytes in self.objectsNewToMe
        logger.debug("DEBUG: Dictionary check result: %s", result)
        return result

    def handleReceivedInventory(self, hashId):
        """Handling received inventory"""
        hashId_bytes = bytes(hashId)
        logger.debug("DEBUG: Handling received inventory: %s", hashId_bytes)
        
        if haveBloom:
            logger.debug("DEBUG: Adding to inventory BloomFilter")
            self.invBloom.add(hashId_bytes)
        
        try:
            with self.objectsNewToThemLock:
                logger.debug("DEBUG: Attempting to remove from objectsNewToThem")
                del self.objectsNewToThem[hashId_bytes]
                logger.debug("DEBUG: Successfully removed from objectsNewToThem")
        except KeyError:
            logger.debug("DEBUG: Object not found in objectsNewToThem")
        
        if hashId_bytes not in missingObjects:
            logger.debug("DEBUG: Adding to missingObjects")
            missingObjects[hashId_bytes] = time.time()
        
        self.objectsNewToMe[hashId] = True
        logger.debug("DEBUG: Added to objectsNewToMe")

    def handleReceivedObject(self, streamNumber, hashid):
        """Handling received object"""
        hashid_bytes = bytes(hashid)
        logger.debug("DEBUG: Handling received object %s in stream %d", 
                    hashid_bytes, streamNumber)
        
        for i in network.connectionpool.pool.connections():
            if not i.fullyEstablished:
                logger.debug("DEBUG: Skipping non-fully established connection")
                continue
                
            try:
                logger.debug("DEBUG: Attempting to remove from connection %s objectsNewToMe", i)
                del i.objectsNewToMe[hashid]
                logger.debug("DEBUG: Successfully removed from objectsNewToMe")
            except KeyError:
                if streamNumber in i.streams and (
                        not dandelion_ins.hasHash(hashid)
                        or dandelion_ins.objectChildStem(hashid) == i):
                    logger.debug("DEBUG: Adding to connection %s objectsNewToThem", i)
                    with i.objectsNewToThemLock:
                        i.objectsNewToThem[hashid_bytes] = time.time()
                    
                    logger.debug("DEBUG: Updating Dandelion stream for hash")
                    dandelion_ins.setHashStream(hashid, streamNumber)

            if i == self:
                try:
                    logger.debug("DEBUG: Removing from self.objectsNewToThem")
                    with i.objectsNewToThemLock:
                        del i.objectsNewToThem[hashid_bytes]
                except KeyError:
                    logger.debug("DEBUG: Object not found in self.objectsNewToThem")
        
        self.objectsNewToMe.setLastObject()
        logger.debug("DEBUG: Updated last object timestamp")

    def hasAddr(self, addr):
        """WIP, should be moved to addrthread.py or removed"""
        logger.debug("DEBUG: Checking address existence: %s", addr)
        if haveBloom:
            result = addr in self.invBloom
            logger.debug("DEBUG: BloomFilter address check result: %s", result)
            return result
        logger.debug("DEBUG: No BloomFilter, returning None")
        return None

    def addAddr(self, hashid):
        """WIP, should be moved to addrthread.py or removed"""
        logger.debug("DEBUG: Adding address to tracker: %s", hashid)
        if haveBloom:
            logger.debug("DEBUG: Adding to address BloomFilter")
            self.addrBloom.add(bytes(hashid))
