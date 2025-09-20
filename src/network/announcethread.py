"""
Announce myself (node address)
"""
import time
import logging

# magic imports!
from network import connectionpool
from bmconfigparser import config
from protocol import assembleAddrMessage  # Zwei Ebenen nach oben
from .node import Peer
from .threads import StoppableThread

logger = logging.getLogger('default')

class AnnounceThread(StoppableThread):
    """A thread to manage regular announcing of this node"""
    name = "Announcer"
    announceInterval = 60

    def run(self):
        logger.debug("DEBUG: AnnounceThread started")
        lastSelfAnnounced = 0
        while not self._stopped:
            processed = 0
            if lastSelfAnnounced < time.time() - self.announceInterval:
                logger.debug("DEBUG: Time to announce ourselves")
                self.announceSelf()
                lastSelfAnnounced = time.time()
                logger.debug("DEBUG: Last announcement time updated to %s", lastSelfAnnounced)
            if processed == 0:
                logger.debug("DEBUG: No processing done, waiting 10 seconds")
                self.stop.wait(10)
        logger.debug("DEBUG: AnnounceThread stopped")

    @staticmethod
    def announceSelf():
        """Announce our presence"""
        logger.debug("DEBUG: Starting self announcement")
        for connection in connectionpool.pool.udpSockets.values():
            if not connection.announcing:
                logger.debug("DEBUG: Connection %s not announcing, skipping", connection)
                continue
            for stream in connectionpool.pool.streams:
                addr = (
                    stream,
                    Peer(
                        '127.0.0.1',
                        config.safeGetInt('bitmessagesettings', 'port')),
                    int(time.time()))
                logger.debug("DEBUG: Assembling addr message for stream %s", stream)
                connection.append_write_buf(assembleAddrMessage([addr]))
        logger.debug("DEBUG: Self announcement completed")
