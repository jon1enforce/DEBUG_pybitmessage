"""Threading primitives for the network package"""

import logging
import helper_random as random
import threading
from contextlib import contextmanager


class StoppableThread(threading.Thread):
    """Base class for application threads with stopThread method"""
    name = None
    logger = logging.getLogger('default')

    def __init__(self, name=None):
        self.logger.debug(f"DEBUG: Initializing StoppableThread (name: {name})")
        if name:
            self.name = name
            self.logger.debug(f"DEBUG: Thread name set to {self.name}")
            
        super(StoppableThread, self).__init__(name=self.name)
        self.stop = threading.Event()
        self._stopped = False
        random.seed()
        
        self.logger.info('Init thread %s', self.name)
        self.logger.debug(f"DEBUG: Thread initialized - stop event: {self.stop}, _stopped: {self._stopped}")

    def stopThread(self):
        """Stop the thread"""
        self.logger.debug(f"DEBUG: Stopping thread {self.name}")
        self._stopped = True
        self.stop.set()
        self.logger.debug(f"DEBUG: Thread {self.name} stop signal set - _stopped: {self._stopped}, stop event: {self.stop.is_set()}")


class BusyError(threading.ThreadError):
    """
    Thread error raised when another connection holds the lock
    we are trying to acquire.
    """
    def __init__(self, msg=None):
        super(BusyError, self).__init__(msg or "Resource is busy")
        logging.getLogger('default').debug("DEBUG: BusyError created")


@contextmanager
def nonBlocking(lock):
    """
    A context manager which acquires given lock non-blocking
    and raises BusyError if failed to acquire.
    """
    logger = logging.getLogger('default')
    logger.debug(f"DEBUG: Attempting non-blocking lock acquire on {lock}")
    
    locked = lock.acquire(False)
    if not locked:
        logger.debug(f"DEBUG: Failed to acquire lock {lock} - raising BusyError")
        raise BusyError(f"Could not acquire lock {lock}")
        
    logger.debug(f"DEBUG: Successfully acquired lock {lock}")
    try:
        logger.debug("DEBUG: Entering locked context")
        yield
        logger.debug("DEBUG: Exiting locked context normally")
    except Exception as e:
        logger.debug(f"DEBUG: Exception in locked context: {str(e)}")
        raise
    finally:
        lock.release()
        logger.debug(f"DEBUG: Released lock {lock}")
