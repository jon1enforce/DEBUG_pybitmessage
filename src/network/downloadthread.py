"""
`DownloadThread` class definition
"""
import time
import helper_random as random
import logging
import state
import six
import addresses
import protocol
from network import connectionpool
from network import dandelion_ins
from .objectracker import missingObjects
from .threads import StoppableThread

# Initialize logger
logger = logging.getLogger('default')

class DownloadThread(StoppableThread):
    """Thread-based class for downloading from connections"""
    minPending = 200
    maxRequestChunk = 1000
    requestTimeout = 60
    cleanInterval = 60
    requestExpires = 3600

    def __init__(self):
        logger.debug("DEBUG: Initializing DownloadThread")
        super(DownloadThread, self).__init__(name="Downloader")
        self.lastCleaned = time.time()
        logger.debug("DEBUG: DownloadThread initialized, lastCleaned: %s", 
                   time.ctime(self.lastCleaned))

    def cleanPending(self):
        """Expire pending downloads eventually"""
        logger.debug("DEBUG: Starting cleanPending")
        deadline = time.time() - self.requestExpires
        logger.debug("DEBUG: Cleaning objects older than %s", time.ctime(deadline))
        
        try:
            toDelete = [
                k for k, v in six.iteritems(missingObjects)
                if v < deadline]
            logger.debug("DEBUG: Found %d objects to clean", len(toDelete))
        except RuntimeError as e:
            logger.debug("DEBUG: Error during cleanPending: %s", str(e))
            pass
        else:
            for i in toDelete:
                try:
                    del missingObjects[i]
                    logger.debug("DEBUG: Removed expired object: %s", i)
                except KeyError:
                    logger.debug("DEBUG: Object already removed: %s", i)
            self.lastCleaned = time.time()
            logger.debug("DEBUG: cleanPending completed at %s", 
                        time.ctime(self.lastCleaned))

    def run(self):
        logger.debug("DEBUG: DownloadThread main loop started")
        while not self._stopped:
            requested = 0
            logger.debug("DEBUG: Starting new download cycle")
            
            # Choose downloading peers randomly
            connections = connectionpool.pool.establishedConnections()
            logger.debug("DEBUG: Found %d established connections", len(connections))
            random.shuffle(connections)
            
            requestChunk = max(int(
                min(self.maxRequestChunk, len(missingObjects))
                / len(connections)), 1) if connections else 1
            logger.debug("DEBUG: Request chunk size: %d", requestChunk)

            for i in connections:
                now = time.time()
                logger.debug("DEBUG: Processing connection to %s:%d", 
                           i.destination.host, i.destination.port)
                
                # avoid unnecessary delay
                if i.skipUntil >= now:
                    logger.debug("DEBUG: Skipping connection (skipUntil: %s)", 
                               time.ctime(i.skipUntil))
                    continue
                
                try:
                    request = i.objectsNewToMe.randomKeys(requestChunk)
                    logger.debug("DEBUG: Got %d objects from objectsNewToMe", len(request))
                except KeyError as e:
                    logger.debug("DEBUG: No objects available in objectsNewToMe: %s", str(e))
                    continue
                
                payload = bytearray()
                chunkCount = 0
                for chunk in request:
                    if chunk in state.Inventory and not dandelion_ins.hasHash(chunk):
                        logger.debug("DEBUG: Skipping existing object: %s", chunk)
                        try:
                            del i.objectsNewToMe[chunk]
                            logger.debug("DEBUG: Removed existing object from objectsNewToMe")
                        except KeyError:
                            logger.debug("DEBUG: Object already removed from objectsNewToMe")
                        continue
                    
                    payload.extend(chunk)
                    chunkCount += 1
                    missingObjects[bytes(chunk)] = now
                    logger.debug("DEBUG: Added object to download queue: %s", chunk)
                
                if not chunkCount:
                    logger.debug("DEBUG: No new objects to request")
                    continue
                
                payload[0:0] = addresses.encodeVarint(chunkCount)
                i.append_write_buf(protocol.CreatePacket(b'getdata', payload))
                logger.debug("DEBUG: Requesting %d objects from %s:%d", 
                           chunkCount, i.destination.host, i.destination.port)
                requested += chunkCount
            
            if time.time() >= self.lastCleaned + self.cleanInterval:
                logger.debug("DEBUG: Running periodic cleanup")
                self.cleanPending()
            
            if not requested:
                logger.debug("DEBUG: No objects requested, waiting...")
                self.stop.wait(1)
            else:
                logger.debug("DEBUG: Requested %d objects in this cycle", requested)
        
        logger.debug("DEBUG: DownloadThread main loop ended")
