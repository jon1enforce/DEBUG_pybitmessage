"""
Announce addresses as they are received from other hosts
"""
import random
import logging
from six.moves import queue

# magic imports!
from network import connectionpool
from protocol import assembleAddrMessage
from network import addrQueue  # FIXME: init with queue

from .threads import StoppableThread

logger = logging.getLogger('default')

class AddrThread(StoppableThread):
    """(Node) address broadcasting thread"""
    name = "AddrBroadcaster"

    def run(self):
        logger.debug("DEBUG: AddrThread started")
        while not self._stopped:
            chunk = []
            while True:
                try:
                    data = addrQueue.get(False)
                    chunk.append(data)
                    logger.debug("DEBUG: Got address data from queue")
                except queue.Empty:
                    logger.debug("DEBUG: Address queue empty")
                    break

            if chunk:
                logger.debug("DEBUG: Processing %d address entries", len(chunk))
                # Choose peers randomly
                connections = connectionpool.pool.establishedConnections()
                random.shuffle(connections)
                logger.debug("DEBUG: Shuffled %d connections", len(connections))
                
                for i in connections:
                    random.shuffle(chunk)
                    filtered = []
                    for stream, peer, seen, destination in chunk:
                        # peer's own address or address received from peer
                        if i.destination in (peer, destination):
                            logger.debug("DEBUG: Filtering out peer's own address")
                            continue
                        if stream not in i.streams:
                            logger.debug("DEBUG: Filtering out address from unwanted stream")
                            continue
                        filtered.append((stream, peer, seen))
                    
                    if filtered:
                        logger.debug("DEBUG: Sending %d filtered addresses to connection", len(filtered))
                        i.append_write_buf(assembleAddrMessage(filtered))
                    else:
                        logger.debug("DEBUG: No addresses to send after filtering")

            addrQueue.iterate()
            for i in range(len(chunk)):
                addrQueue.task_done()
                logger.debug("DEBUG: Marked address task %d as done", i)
            
            logger.debug("DEBUG: Waiting 1 second before next iteration")
            self.stop.wait(1)
        logger.debug("DEBUG: AddrThread stopped")
