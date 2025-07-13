"""
A thread to handle network concerns
"""
import logging
import network.asyncore_pollchoose as asyncore
from network import connectionpool
from queues import excQueue
from .threads import StoppableThread
import time

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
        
        # Safe shutdown procedure
        def safe_close_connections(connection_dict, connection_type):
            """Thread-safe connection closing"""
            max_attempts = 3
            for attempt in range(max_attempts):
                try:
                    # Create a snapshot of current connections
                    connections = list(connection_dict.items())
                    if not connections:
                        break
                        
                    logger.debug("DEBUG: Closing %s connections (attempt %d)", connection_type, attempt+1)
                    for addr, conn in connections:
                        try:
                            logger.debug("DEBUG: Closing %s connection %s", connection_type, addr)
                            conn.close()
                            # Remove from original dict if still exists
                            connection_dict.pop(addr, None)
                        except Exception as e:
                            logger.debug("DEBUG: Error closing %s connection %s: %s", 
                                        connection_type, addr, str(e))
                    break
                except RuntimeError as e:
                    if "dictionary changed size" in str(e) and attempt < max_attempts - 1:
                        time.sleep(0.1 * (attempt + 1))
                        continue
                    raise
        
        # Close connections in stages
        safe_close_connections(connectionpool.pool.listeningSockets, "listening socket")
        safe_close_connections(connectionpool.pool.outboundConnections, "outbound")
        safe_close_connections(connectionpool.pool.inboundConnections, "inbound")

        # Final cleanup with retry logic
        for attempt in range(3):
            try:
                logger.debug("DEBUG: Performing asyncore cleanup (attempt %d)", attempt+1)
                asyncore.close_all()
                break
            except Exception as e:
                if attempt == 2:
                    logger.error("DEBUG: Final asyncore cleanup failed: %s", str(e))
                time.sleep(0.2 * (attempt + 1))

        logger.debug("DEBUG: Network thread shutdown complete")
