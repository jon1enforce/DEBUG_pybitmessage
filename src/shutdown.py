"""shutdown function with enhanced debugging"""
import sys
import os
import threading
import time
import logging
from six.moves import queue

# Setup debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='DEBUG: %(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

logger.debug("Initializing shutdown module")

import state
from debug import logger as debug_logger
from helper_sql import sqlQuery, sqlStoredProcedure
from network import StoppableThread
from network.knownnodes import saveKnownNodes
from queues import (
    addressGeneratorQueue, objectProcessorQueue, UISignalQueue, workerQueue)

logger.debug("Imported all required modules")

def doCleanShutdown():
    """
    Perform clean shutdown with detailed debugging
    """
    logger.debug("doCleanShutdown() called - initiating shutdown sequence")
    
    # Set shutdown flag
    state.shutdown = 1
    logger.debug("Set state.shutdown = 1")

    # Signal object processor to check shutdown
    objectProcessorQueue.put(('checkShutdownVariable', 'no data'))
    logger.debug("Sent checkShutdownVariable to objectProcessorQueue")

    # Stop all StoppableThread instances
    logger.debug("Stopping all StoppableThread instances")
    for thread in threading.enumerate():
        try:
            alive = thread.isAlive()
        except AttributeError:
            alive = thread.is_alive()
        if alive and isinstance(thread, StoppableThread):
            logger.debug("Stopping thread: %s", thread.name)
            thread.stopThread()

    # Save known nodes
    UISignalQueue.put((
        'updateStatusBar',
        'Saving the knownNodes list of peers to disk...'))
    logger.info('Saving knownNodes list of peers to disk')
    debug_logger.debug("DEBUG: Starting saveKnownNodes()")
    saveKnownNodes()
    debug_logger.debug("DEBUG: Completed saveKnownNodes()")
    logger.info('Done saving knownNodes list of peers to disk')
    UISignalQueue.put((
        'updateStatusBar',
        'Done saving the knownNodes list of peers to disk.'))
    logger.debug("Completed knownNodes save operation")

    # Flush inventory
    logger.info('Flushing inventory in memory out to disk...')
    UISignalQueue.put((
        'updateStatusBar',
        'Flushing inventory in memory out to disk.'
        ' This should normally only take a second...'))
    logger.debug("Starting inventory flush")
    state.Inventory.flush()
    logger.debug("Inventory flush completed")

    # Wait for objectProcessor to complete shutdown
    logger.debug("Waiting for objectProcessor to complete shutdown")
    while state.shutdown == 1:
        logger.debug("state.shutdown still 1, waiting...")
        time.sleep(.1)
    logger.debug("state.shutdown changed to %d", state.shutdown)

    # Wait for PoW threads
    logger.debug("Waiting for PoW threads to complete")
    time.sleep(.25)

    # Join remaining threads
    logger.debug("Joining remaining threads")
    for thread in threading.enumerate():
        if (
            thread is not threading.currentThread()
            and isinstance(thread, StoppableThread)
            and thread.name != 'SQL'
        ):
            logger.debug("Waiting for thread %s to complete", thread.name)
            thread.join()
            logger.debug("Thread %s joined", thread.name)

    # Final SQL operations
    logger.debug("Performing final SQL operations")
    sqlQuery('SELECT address FROM subscriptions')
    logger.info('Finished flushing inventory.')
    sqlStoredProcedure('exit')
    logger.debug("SQL exit procedure completed")

    # Flush all queues
    logger.debug("Flushing all queues")
    for q in (
            workerQueue, UISignalQueue, addressGeneratorQueue,
            objectProcessorQueue):
        logger.debug("Flushing queue: %s", q)
        while True:
            try:
                q.get(False)
                q.task_done()
            except queue.Empty:
                logger.debug("Queue %s is empty", q)
                break

    # Final shutdown
    if state.thisapp.daemon or not state.enableGUI:
        logger.info('Clean shutdown complete.')
        logger.debug("Running daemon cleanup")
        state.thisapp.cleanup()
        logger.debug("Exiting with os._exit(0)")
        os._exit(0)  # pylint: disable=protected-access
    else:
        logger.info('Core shutdown complete.')
        logger.debug("GUI remains running")

    # Log any remaining threads
    logger.debug("Checking for remaining threads")
    for thread in threading.enumerate():
        logger.debug('Thread %s still running', thread.name)

logger.debug("shutdown module initialization complete")
