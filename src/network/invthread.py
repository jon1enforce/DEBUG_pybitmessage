"""
Thread to send inv announcements
"""
from six.moves import queue as Queue
import random
from time import time

import addresses
import protocol
import state
from network import connectionpool
from network import dandelion_ins, invQueue
from .threads import StoppableThread


def handleExpiredDandelion(expired):
    """For expired dandelion objects, mark all remotes as not having
       the object"""
    logger.debug("DEBUG: Starting handleExpiredDandelion with %d expired items", len(expired) if expired else 0)
    if not expired:
        logger.debug("DEBUG: No expired items to handle")
        return
    for i in connectionpool.pool.connections():
        if not i.fullyEstablished:
            logger.debug("DEBUG: Skipping non-fully established connection")
            continue
        for x in expired:
            streamNumber, hashid, _ = x
            try:
                del i.objectsNewToMe[hashid]
                logger.debug("DEBUG: Removed hash %s from objectsNewToMe for connection", hashid)
            except KeyError:
                if streamNumber in i.streams:
                    with i.objectsNewToThemLock:
                        i.objectsNewToThem[hashid] = time()
                        logger.debug("DEBUG: Added hash %s to objectsNewToThem for connection", hashid)
    logger.debug("DEBUG: Completed handleExpiredDandelion")


class InvThread(StoppableThread):
    """Main thread that sends inv announcements"""

    name = "InvBroadcaster"

    @staticmethod
    def handleLocallyGenerated(stream, hashId):
        """Locally generated inventory items require special handling"""
        logger.debug("DEBUG: Starting handleLocallyGenerated for stream %d, hash %s", stream, hashId)
        dandelion_ins.addHash(hashId, stream=stream)
        logger.debug("DEBUG: Added hash to dandelion with stem node %s", 
                    dandelion_ins.objectChildStem(hashId))
        for connection in connectionpool.pool.connections():
            if dandelion_ins.enabled and connection != dandelion_ins.objectChildStem(hashId):
                logger.debug("DEBUG: Skipping connection (not stem node)")
                continue
            connection.objectsNewToThem[hashId] = time()
            logger.debug("DEBUG: Updated objectsNewToThem for connection")
        logger.debug("DEBUG: Completed handleLocallyGenerated")

    def run(self):  # pylint: disable=too-many-branches
        logger.debug("DEBUG: Starting InvThread main loop")
        while not state.shutdown:  # pylint: disable=too-many-nested-blocks
            chunk = []
            while True:
                # Dandelion fluff trigger by expiration
                expired = dandelion_ins.expire(invQueue)
                logger.debug("DEBUG: Checking for expired dandelion items, found %d", len(expired))
                handleExpiredDandelion(expired)
                try:
                    data = invQueue.get(False)
                    logger.debug("DEBUG: Got data from invQueue: stream=%d, hash=%s", data[0], data[1])
                    chunk.append((data[0], data[1]))
                    # locally generated
                    if len(data) == 2 or data[2] is None:
                        logger.debug("DEBUG: Handling locally generated item")
                        self.handleLocallyGenerated(data[0], data[1])
                except Queue.Empty:
                    logger.debug("DEBUG: invQueue is empty")
                    break

            if chunk:
                logger.debug("DEBUG: Processing chunk of %d inventory items", len(chunk))
                for connection in connectionpool.pool.connections():
                    fluffs = []
                    stems = []
                    logger.debug("DEBUG: Processing connection %s", connection.destination)
                    for inv in chunk:
                        if inv[0] not in connection.streams:
                            logger.debug("DEBUG: Skipping item - wrong stream")
                            continue
                        try:
                            with connection.objectsNewToThemLock:
                                del connection.objectsNewToThem[inv[1]]
                            logger.debug("DEBUG: Removed hash from objectsNewToThem")
                        except KeyError:
                            logger.debug("DEBUG: Hash not in objectsNewToThem")
                            continue
                        try:
                            if connection == dandelion_ins.objectChildStem(inv[1]):
                                logger.debug("DEBUG: Item is on dandelion stem")
                                # Fluff trigger by RNG
                                # auto-ignore if config set to 0, i.e. dandelion is off
                                rand_val = random.randint(1, 100)  # nosec B311
                                if rand_val >= dandelion_ins.enabled:
                                    logger.debug("DEBUG: RNG %d >= %d - adding to fluffs", 
                                               rand_val, dandelion_ins.enabled)
                                    fluffs.append(inv[1])
                                # send a dinv only if the stem node supports dandelion
                                elif connection.services & protocol.NODE_DANDELION > 0:
                                    logger.debug("DEBUG: Adding to stems (DANDELION supported)")
                                    stems.append(inv[1])
                                else:
                                    logger.debug("DEBUG: Adding to fluffs (DANDELION not supported)")
                                    fluffs.append(inv[1])
                        except KeyError:
                            logger.debug("DEBUG: Item not in dandelion - adding to fluffs")
                            fluffs.append(inv[1])

                    if fluffs:
                        logger.debug("DEBUG: Preparing %d fluff items", len(fluffs))
                        random.shuffle(fluffs)
                        connection.append_write_buf(protocol.CreatePacket(
                            b'inv',
                            addresses.encodeVarint(
                                len(fluffs)) + b''.join(fluffs)))
                        logger.debug("DEBUG: Sent inv packet with %d items", len(fluffs))
                    if stems:
                        logger.debug("DEBUG: Preparing %d stem items", len(stems))
                        random.shuffle(stems)
                        connection.append_write_buf(protocol.CreatePacket(
                            b'dinv',
                            addresses.encodeVarint(
                                len(stems)) + b''.join(stems)))
                        logger.debug("DEBUG: Sent dinv packet with %d items", len(stems))

            invQueue.iterate()
            logger.debug("DEBUG: Processed %d tasks from invQueue", len(chunk))
            for _ in range(len(chunk)):
                invQueue.task_done()

            dandelion_ins.reRandomiseStems()
            logger.debug("DEBUG: Re-randomized dandelion stems")

            self.stop.wait(1)
            logger.debug("DEBUG: InvThread waiting for next cycle")
        logger.debug("DEBUG: InvThread shutting down")
