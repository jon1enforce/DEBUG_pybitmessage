"""
A thread to handle network concerns
"""
import time
import threading
import network.asyncore_pollchoose as asyncore
from network import connectionpool
from queues import excQueue
from .threads import StoppableThread


class BMNetworkThread(StoppableThread):
    """Main network thread - thread safe version"""
    name = "Asyncore"

    def __init__(self):
        super(BMNetworkThread, self).__init__()
        self._stop_lock = threading.RLock()
        self._closing = False

    def run(self):
        try:
            while not self._stopped:
                # Thread-safe loop execution
                try:
                    connectionpool.pool.loop()
                except RuntimeError as e:
                    if "dictionary changed size during iteration" in str(e):
                        # Recovery from asyncore map iteration error
                        time.sleep(0.1)
                        continue
                    else:
                        raise
                except Exception as e:
                    # Log non-critical errors but continue
                    import logging
                    logging.debug(f"Network loop non-critical error: {e}")
                    time.sleep(0.1)
        except Exception as e:
            excQueue.put((self.name, e))
            raise

    def stopThread(self):
        """Thread-safe shutdown with proper error handling"""
        with self._stop_lock:
            if self._closing:
                return
            self._closing = True
            
        super(BMNetworkThread, self).stopThread()
        
        # Give the loop a chance to notice the stop flag
        time.sleep(0.2)
        
        # Close listening sockets - thread-safe iteration
        self._safe_close_connections('listeningSockets')
        
        # Close outbound connections - thread-safe iteration
        self._safe_close_connections('outboundConnections')
        
        # Close inbound connections - thread-safe iteration
        self._safe_close_connections('inboundConnections')
        
        # Close all asyncore sockets as fallback
        try:
            asyncore.close_all()
        except Exception as e:
            import logging
            logging.debug(f"Error in asyncore.close_all(): {e}")

    def _safe_close_connections(self, connection_type):
        """Thread-safe connection closing with retry logic"""
        max_attempts = 3
        
        for attempt in range(max_attempts):
            try:
                # Get the connection dictionary
                connections_dict = getattr(connectionpool.pool, connection_type, None)
                if not connections_dict:
                    return
                
                # Create a copy of values to avoid RuntimeError during iteration
                connections = []
                try:
                    # Try to copy values safely
                    if hasattr(connections_dict, 'values'):
                        connections = list(connections_dict.values())
                    elif hasattr(connections_dict, 'copy'):
                        connections = list(connections_dict.copy().values())
                    else:
                        # Manual copy as last resort
                        connections = [v for v in connections_dict.values()]
                except RuntimeError:
                    # Dictionary changed during copy, wait and retry
                    if attempt < max_attempts - 1:
                        time.sleep(0.1 * (attempt + 1))
                        continue
                    else:
                        # Final attempt: try direct iteration with minimal risk
                        connections = []
                        for key in list(connections_dict.keys()):
                            try:
                                conn = connections_dict.get(key)
                                if conn:
                                    connections.append(conn)
                            except:
                                pass
                
                # Close each connection
                for connection in connections:
                    try:
                        if hasattr(connection, 'close'):
                            connection.close()
                    except Exception as e:
                        # Log but continue closing others
                        import logging
                        logging.debug(f"Error closing {connection_type} connection: {e}")
                
                # Success - break out of retry loop
                break
                
            except RuntimeError as e:
                if "dictionary changed size during iteration" in str(e):
                    if attempt < max_attempts - 1:
                        # Wait and retry
                        time.sleep(0.1 * (attempt + 1))
                        continue
                    else:
                        # Last attempt failed, log and give up
                        import logging
                        logging.warning(f"Failed to close {connection_type} after {max_attempts} attempts")
                        break
                else:
                    # Different RuntimeError, re-raise
                    raise
            except Exception as e:
                import logging
                logging.warning(f"Error closing {connection_type}: {e}")
                # Don't retry on other errors
                break

    def safe_iterate_connections(self, connection_dict):
        """Thread-safe iteration over connection dictionary"""
        max_retries = 3
        for retry in range(max_retries):
            try:
                # Try to get a snapshot
                if hasattr(connection_dict, 'copy'):
                    snapshot = connection_dict.copy()
                else:
                    snapshot = dict(connection_dict)
                
                return list(snapshot.values())
                
            except RuntimeError:
                if retry < max_retries - 1:
                    time.sleep(0.01 * (retry + 1))
                    continue
                else:
                    # Last resort: empty list
                    return []
        
        return []
