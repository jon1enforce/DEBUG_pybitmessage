"""
Track randomize ordered dict with enhanced debugging
"""
import sys
import logging
from threading import RLock
from time import time

# Setup debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='DEBUG: %(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

try:
    import helper_random
    logger.debug("Imported helper_random module")
except ImportError:
    from . import helper_random
    logger.debug("Imported helper_random module from local package")

class RandomTrackingDict(object):
    """
    Dict with randomised order and tracking with detailed debugging.
    """
    # pylint: disable=too-many-instance-attributes
    maxPending = 10
    pendingTimeout = 60

    def __init__(self):
        logger.debug("Initializing RandomTrackingDict")
        self.dictionary = {}
        self.indexDict = []
        self.len = 0
        self.pendingLen = 0
        self.lastPoll = 0
        self.lastObject = 0
        self.lock = RLock()
        logger.debug("RandomTrackingDict initialized: maxPending=%d, pendingTimeout=%d", 
                    self.maxPending, self.pendingTimeout)

    def __len__(self):
        logger.debug("Getting length: %d", self.len)
        return self.len

    def __contains__(self, key):
        key_bytes = bytes(key)
        result = key_bytes in self.dictionary
        logger.debug("Checking if key exists: %s -> %s", key_bytes, result)
        return result

    def __getitem__(self, key):
        key_bytes = bytes(key)
        logger.debug("Getting item for key: %s", key_bytes)
        return self.dictionary[key_bytes][1]

    def _swap(self, i1, i2):
        with self.lock:
            logger.debug("Swapping indices %d and %d", i1, i2)
            key1 = self.indexDict[i1]
            key2 = self.indexDict[i2]
            self.indexDict[i1] = key2
            self.indexDict[i2] = key1
            self.dictionary[bytes(key1)][0] = i2
            self.dictionary[bytes(key2)][0] = i1
        logger.debug("Swap completed, returning new index: %d", i2)
        return i2

    def __setitem__(self, key, value):
        key_bytes = bytes(key)
        logger.debug("Setting item for key: %s", key_bytes)
        with self.lock:
            if key_bytes in self.dictionary:
                logger.debug("Key exists, updating value")
                self.dictionary[key_bytes][1] = value
            else:
                logger.debug("New key, adding to dictionary")
                self.indexDict.append(key)
                self.dictionary[key_bytes] = [self.len, value]
                self._swap(self.len, self.len - self.pendingLen)
                self.len += 1
                logger.debug("New item added, new length: %d", self.len)

    def __delitem__(self, key):
        key_bytes = bytes(key)
        logger.debug("Deleting item with key: %s", key_bytes)
        if key_bytes not in self.dictionary:
            logger.error("Key not found for deletion: %s", key_bytes)
            raise KeyError
        with self.lock:
            index = self.dictionary[key_bytes][0]
            logger.debug("Item index: %d, pendingLen: %d", index, self.pendingLen)
            
            if index < self.len - self.pendingLen:
                logger.debug("Item not pending, swapping with pending boundary")
                index = self._swap(index, self.len - self.pendingLen - 1)
            else:
                logger.debug("Item is pending, decrementing pendingLen")
                self.pendingLen -= 1
            
            logger.debug("Final swap before deletion")
            self._swap(index, self.len - 1)
            
            logger.debug("Removing items from indexDict and dictionary")
            del self.indexDict[-1]
            del self.dictionary[key_bytes]
            self.len -= 1
            logger.debug("Deletion complete, new length: %d", self.len)

    def setMaxPending(self, maxPending):
        """Set maximum pending objects with debug logging"""
        logger.debug("Setting maxPending from %d to %d", self.maxPending, maxPending)
        self.maxPending = maxPending

    def setPendingTimeout(self, pendingTimeout):
        """Set pending timeout with debug logging"""
        logger.debug("Setting pendingTimeout from %d to %d", self.pendingTimeout, pendingTimeout)
        self.pendingTimeout = pendingTimeout

    def setLastObject(self):
        """Update last object timestamp with debug logging"""
        current_time = time()
        logger.debug("Updating lastObject from %f to %f", self.lastObject, current_time)
        self.lastObject = current_time

    def randomKeys(self, count=1):
        """Retrieve random keys with detailed debug logging"""
        logger.debug("Requesting %d random keys", count)
        
        current_time = time()
        if self.len == 0 or (
                (self.pendingLen >= self.maxPending or self.pendingLen == self.len)
                and self.lastPoll + self.pendingTimeout > current_time):
            logger.debug("No keys available or pending limit reached")
            raise KeyError

        with self.lock:
            if self.pendingLen == self.len and self.lastObject + \
                    self.pendingTimeout < current_time:
                logger.debug("Resetting pendingLen (all items pending and timeout reached)")
                self.pendingLen = 0
                self.setLastObject()

            available = self.len - self.pendingLen
            if count > available:
                logger.debug("Reducing requested count from %d to %d (available)", count, available)
                count = available

            logger.debug("Generating random indices from %d available items", available)
            randomIndex = helper_random.randomsample(
                range(self.len - self.pendingLen), count)
            retval = [self.indexDict[i] for i in randomIndex]
            logger.debug("Selected %d random keys", len(retval))

            for i in sorted(randomIndex, reverse=True):
                logger.debug("Processing index %d", i)
                self._swap(i, self.len - self.pendingLen - 1)
                self.pendingLen += 1
                logger.debug("Pending length increased to %d", self.pendingLen)

            self.lastPoll = current_time
            logger.debug("Updated lastPoll to current time, returning %d keys", len(retval))
            return retval

logger.debug("randomtrackingdict module initialization complete")
