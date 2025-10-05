"""
`UploadThread` class definition
"""
import time
import helper_random as random
import protocol
import state
from network import connectionpool
from randomtrackingdict import RandomTrackingDict
from network import dandelion_ins
from .threads import StoppableThread


class UploadThread(StoppableThread):
    """
    This is a thread that uploads the objects that the peers requested from me
    """
    maxBufSize = 2097152  # 2MB
    name = "Uploader"

    def run(self):
        self.logger.debug("DEBUG: UploadThread started")
        while not self._stopped:
            self.logger.debug("DEBUG: Starting new upload cycle")
            uploaded = 0
            # Choose uploading peers randomly
            connections = connectionpool.pool.establishedConnections()
            self.logger.debug(f"DEBUG: Found {len(connections)} established connections")
            random.shuffle(connections)
            
            for i in connections:
                now = time.time()
                self.logger.debug(f"DEBUG: Processing connection to {i.destination}")
                
                # avoid unnecessary delay
                if i.skipUntil >= now:
                    self.logger.debug(f"DEBUG: Skipping {i.destination} due to skipUntil time")
                    continue
                    
                if len(i.write_buf) > self.maxBufSize:
                    self.logger.debug(f"DEBUG: Skipping {i.destination} due to full write buffer")
                    continue
                    
                try:
                    request = i.pendingUpload.randomKeys(
                        RandomTrackingDict.maxPending)
                    self.logger.debug(f"DEBUG: Got {len(request)} pending upload requests from {i.destination}")
                except KeyError as e:
                    self.logger.debug(f"DEBUG: No pending uploads for {i.destination}: {str(e)}")
                    continue
                    
                payload = bytearray()
                chunk_count = 0
                
                for chunk in request:
                    self.logger.debug(f"DEBUG: Processing chunk {chunk} for {i.destination}")
                    try:
                        del i.pendingUpload[chunk]
                        self.logger.debug(f"DEBUG: Removed chunk {chunk} from pending uploads")
                        
                        if dandelion_ins.hasHash(chunk) and \
                           i != dandelion_ins.objectChildStem(chunk):
                            i.antiIntersectionDelay()
                            self.logger.info(
                                '%s asked for a stem object we didn\'t offer to it.',
                                i.destination)
                            self.logger.debug(f"DEBUG: Anti-intersection delay triggered for {i.destination}")
                            break
                            
                        try:
                            obj_payload = state.Inventory[chunk].payload
                            packet = protocol.CreatePacket(b'object', obj_payload)
                            payload.extend(packet)
                            chunk_count += 1
                            self.logger.debug(f"DEBUG: Added chunk {chunk} to payload (size: {len(packet)} bytes)")
                        except KeyError:
                            i.antiIntersectionDelay()
                            self.logger.info(
                                '%s asked for an object we don\'t have.',
                                i.destination)
                            self.logger.debug(f"DEBUG: Missing object {chunk} in inventory")
                            break
                    except Exception as e:
                        self.logger.debug(f"DEBUG: Error processing chunk {chunk}: {str(e)}")
                        continue
                        
                if not chunk_count:
                    self.logger.debug(f"DEBUG: No chunks processed for {i.destination}")
                    continue
                    
                i.append_write_buf(payload)
                self.logger.debug(
                    '%s:%i Uploading %i objects (total size: %i bytes)',
                    i.destination.host, i.destination.port, chunk_count, len(payload))
                uploaded += chunk_count
                self.logger.debug(f"DEBUG: Total uploaded this cycle: {uploaded}")
                
            if not uploaded:
                self.logger.debug("DEBUG: No uploads this cycle, waiting...")
                self.stop.wait(1)
                
        self.logger.debug("DEBUG: UploadThread stopped")
