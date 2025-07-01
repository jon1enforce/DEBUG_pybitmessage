"""
A queue with multiple internal subqueues.
Elements are added into a random subqueue, and retrieval rotates
"""
import random
import logging
from collections import deque
from six.moves import queue

logger = logging.getLogger('default')


class MultiQueue(queue.Queue):
    """A base queue class with multiple internal subqueues"""
    # pylint: disable=redefined-builtin,attribute-defined-outside-init
    defaultQueueCount = 10

    def __init__(self, maxsize=0, count=0):
        logger.debug("DEBUG: Initializing MultiQueue with maxsize=%d, count=%d", 
                   maxsize, count)
        if not count:
            self.queueCount = MultiQueue.defaultQueueCount
            logger.debug("DEBUG: Using default queue count: %d", self.queueCount)
        else:
            self.queueCount = count
            logger.debug("DEBUG: Using custom queue count: %d", self.queueCount)
        queue.Queue.__init__(self, maxsize)
        logger.debug("DEBUG: MultiQueue initialization complete")

    def _init(self, maxsize):
        """Initialize the queue representation"""
        logger.debug("DEBUG: Initializing %d internal queues", self.queueCount)
        self.iter = 0
        self.queues = []
        for i in range(self.queueCount):
            self.queues.append(deque())
            logger.debug("DEBUG: Initialized queue %d/%d", i+1, self.queueCount)
        logger.debug("DEBUG: Current iterator position: %d", self.iter)

    def _qsize(self, len=len):
        """Return the size of the current queue"""
        size = len(self.queues[self.iter])
        logger.debug("DEBUG: Current queue size: %d (iterator at %d)", 
                   size, self.iter)
        return size

    def _put(self, item):
        """Put a new item in a random queue"""
        queue_idx = random.randrange(self.queueCount)  # nosec B311
        logger.debug("DEBUG: Adding item to queue %d/%d", 
                    queue_idx + 1, self.queueCount)
        self.queues[queue_idx].append(item)
        logger.debug("DEBUG: Item added. Queue %d now has %d items",
                    queue_idx, len(self.queues[queue_idx]))

    def _get(self):
        """Get an item from the current queue"""
        logger.debug("DEBUG: Getting item from queue %d", self.iter)
        try:
            item = self.queues[self.iter].popleft()
            logger.debug("DEBUG: Retrieved item from queue %d. Remaining: %d", 
                       self.iter, len(self.queues[self.iter]))
            return item
        except IndexError:
            logger.debug("DEBUG: Queue %d is empty", self.iter)
            raise queue.Empty("No items in current queue")

    def iterate(self):
        """Increment the iteration counter"""
        old_iter = self.iter
        self.iter = (self.iter + 1) % self.queueCount
        logger.debug("DEBUG: Iterating from %d to %d", old_iter, self.iter)

    def totalSize(self):
        """Return the total number of items in all queues"""
        sizes = [len(x) for x in self.queues]
        total = sum(sizes)
        logger.debug("DEBUG: Total queue sizes: %s (total=%d)", sizes, total)
        return total
