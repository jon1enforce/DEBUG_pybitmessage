"""
A thread to handle network concerns
"""
import logging
import network.asyncore_pollchoose as asyncore
from network import connectionpool
from queues import excQueue
from .threads import StoppableThread

logger = logging.getLogger('default')


class BMNetworkThread(StoppableThread):
    """Main network thread"""
    name = "Asyncore"

    def run(self):
        logger.debug("DEBUG: BMNetworkThread starting main loop")
        try:
            while not self._stopped:
                logger.debug("DEBUG: Starting network loop iteration")
                connectionpool.pool.loop()
                logger.debug("DEBUG: Completed network loop iteration")
        except Exception as e:
            logger.error("DEBUG: Exception in network thread: %s", str(e), exc_info=True)
            excQueue.put((self.name, e))
            logger.debug("DEBUG: Exception added to excQueue")
            raise
        logger.debug("DEBUG: BMNetworkThread exiting main loop")

    def stopThread(self):
        logger.debug("DEBUG: BMNetworkThread stopThread called")
        super(BMNetworkThread, self).stopThread()
        
        # Close listening sockets
        logger.debug("DEBUG: Closing listening sockets")
        for addr, sock in connectionpool.pool.listeningSockets.items():
            try:
                logger.debug("DEBUG: Closing listening socket %s", addr)
                sock.close()
            except Exception as e:
                logger.debug("DEBUG: Error closing listening socket %s: %s", addr, str(e))
        
        # Close outbound connections
        logger.debug("DEBUG: Closing outbound connections")
        for addr, conn in connectionpool.pool.outboundConnections.items():
            try:
                logger.debug("DEBUG: Closing outbound connection to %s", addr)
                conn.close()
            except Exception as e:
                logger.debug("DEBUG: Error closing outbound connection to %s: %s", addr, str(e))
        
        # Close inbound connections
        logger.debug("DEBUG: Closing inbound connections")
        for addr, conn in connectionpool.pool.inboundConnections.items():
            try:
                logger.debug("DEBUG: Closing inbound connection from %s", addr)
                conn.close()
            except Exception as e:
                logger.debug("DEBUG: Error closing inbound connection from %s: %s", addr, str(e))

        # Final cleanup
        logger.debug("DEBUG: Performing final asyncore cleanup")
        asyncore.close_all()
        logger.debug("DEBUG: Network thread shutdown complete")
