"""Queues used by bitmessage threads with enhanced debugging"""

import sys
import logging
import threading
import time
from six.moves import queue

# Setup debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='DEBUG: %(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

logger.debug("Initializing queues module")

class ObjectProcessorQueue(queue.Queue):
    """Special queue class with size tracking and debug logging"""
    
    maxSize = 32000000  # 32 MB
    logger.debug("ObjectProcessorQueue maxSize set to %d bytes", maxSize)

    def __init__(self):
        logger.debug("Initializing ObjectProcessorQueue")
        queue.Queue.__init__(self)
        self.sizeLock = threading.Lock()
        self.curSize = 0  # Current size in bytes
        logger.debug("ObjectProcessorQueue initialized with sizeLock and curSize=0")

    def put(self, item, block=True, timeout=None):
        """Put item in queue with size tracking and debug logging"""
        item_size = len(item[1])
        logger.debug("Attempting to put item of size %d bytes into queue (curSize=%d)", 
                     item_size, self.curSize)
        
        while self.curSize >= self.maxSize:
            logger.debug("Queue size %d >= maxSize %d, sleeping...", 
                        self.curSize, self.maxSize)
            time.sleep(1)
        
        with self.sizeLock:
            self.curSize += item_size
            logger.debug("Increased queue size to %d bytes", self.curSize)
        
        logger.debug("Calling parent Queue.put()")
        queue.Queue.put(self, item, block, timeout)
        logger.debug("Successfully put item in queue")

    def get(self, block=True, timeout=None):
        """Get item from queue with size tracking and debug logging"""
        logger.debug("Attempting to get item from queue (curSize=%d)", self.curSize)
        
        logger.debug("Calling parent Queue.get()")
        item = queue.Queue.get(self, block, timeout)
        item_size = len(item[1])
        
        with self.sizeLock:
            self.curSize -= item_size
            logger.debug("Decreased queue size to %d bytes", self.curSize)
        
        logger.debug("Successfully got item of size %d bytes", item_size)
        return item

# Initialize global queues with debug logging
logger.debug("Initializing global queues")

workerQueue = queue.Queue()
logger.debug("Initialized workerQueue")

UISignalQueue = queue.Queue()
logger.debug("Initialized UISignalQueue")

addressGeneratorQueue = queue.Queue()
logger.debug("Initialized addressGeneratorQueue")

objectProcessorQueue = ObjectProcessorQueue()
logger.debug("Initialized objectProcessorQueue")

apiAddressGeneratorReturnQueue = queue.Queue()
logger.debug("Initialized apiAddressGeneratorReturnQueue")

excQueue = queue.Queue()
logger.debug("Initialized excQueue")

logger.debug("All queues initialized successfully")
