"""
Process data incoming from network
"""
import errno
from six.moves import queue as Queue
import socket
import logging

from network import connectionpool
from network.advanceddispatcher import UnknownStateError
from network import receiveDataQueue
from .threads import StoppableThread


logger = logging.getLogger('default')


class ReceiveQueueThread(StoppableThread):
    """This thread processes data received from the network
    (which is done by the asyncore thread)"""
    def __init__(self, num=0):
        logger.debug("DEBUG: Initializing ReceiveQueueThread #%d", num)
        super(ReceiveQueueThread, self).__init__(name="ReceiveQueue_%i" % num)
        self.logger = logger
        logger.debug("DEBUG: ReceiveQueueThread #%d initialized", num)

    def run(self):
        logger.debug("DEBUG: ReceiveQueueThread #%d starting main loop", self.name.split('_')[-1])
        
        while not self._stopped:
            try:
                logger.debug("DEBUG: Waiting for data from receiveDataQueue...")
                dest = receiveDataQueue.get(block=True, timeout=1)
                logger.debug("DEBUG: Received data for destination: %s", dest)
            except Queue.Empty:
                logger.debug("DEBUG: Queue empty, continuing...")
                continue

            if self._stopped:
                logger.debug("DEBUG: Thread stop signal received, breaking loop")
                break

            logger.debug("DEBUG: Processing data for destination: %s", dest)
            
            try:
                connection = connectionpool.pool.getConnectionByAddr(dest)
                logger.debug("DEBUG: Found connection object: %s", connection)
            except KeyError:
                logger.debug("DEBUG: Connection object not found for destination: %s", dest)
                receiveDataQueue.task_done()
                continue
                
            try:
                logger.debug("DEBUG: Processing connection data...")
                connection.process()
                logger.debug("DEBUG: Successfully processed connection data")
            except UnknownStateError:
                logger.warning("DEBUG: Unknown state encountered for connection: %s", connection)
                pass
            except socket.error as err:
                if err.errno == errno.EBADF:
                    logger.debug("DEBUG: Bad file descriptor error, closing connection")
                    connection.set_state("close", 0)
                else:
                    logger.error('DEBUG: Socket error processing connection: %s', err)
            except Exception as e:
                logger.error('DEBUG: Unexpected error processing connection:', exc_info=True)
                logger.debug("DEBUG: Error details: %s", str(e))
            finally:
                receiveDataQueue.task_done()
                logger.debug("DEBUG: Marked task as done in queue")
                
        logger.debug("DEBUG: ReceiveQueueThread #%d exiting main loop", self.name.split('_')[-1])
