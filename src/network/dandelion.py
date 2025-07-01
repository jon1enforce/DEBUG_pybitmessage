"""
Dandelion class definition, tracks stages
"""
import logging
from collections import namedtuple
from random import choice, expovariate, sample
from threading import RLock
from time import time
import six
from binascii import hexlify


# randomise routes after 600 seconds
REASSIGN_INTERVAL = 600

# trigger fluff due to expiration
FLUFF_TRIGGER_FIXED_DELAY = 10
FLUFF_TRIGGER_MEAN_DELAY = 30

MAX_STEMS = 2

Stem = namedtuple('Stem', ['child', 'stream', 'timeout'])

logger = logging.getLogger('default')


class Dandelion:  # pylint: disable=old-style-class
    """Dandelion class for tracking stem/fluff stages."""
    def __init__(self):
        logger.debug("DEBUG: Initializing Dandelion instance")
        # currently assignable child stems
        self.stem = []
        # currently assigned parent <-> child mappings
        self.nodeMap = {}
        # currently existing objects in stem mode
        self.hashMap = {}
        # when to rerandomise routes
        self.refresh = time() + REASSIGN_INTERVAL
        self.lock = RLock()
        self.enabled = None
        self.pool = None
        logger.debug("DEBUG: Dandelion instance initialized with stem=%s, nodeMap=%s, hashMap=%s, refresh=%s", 
                    len(self.stem), len(self.nodeMap), len(self.hashMap), self.refresh)

    @staticmethod
    def poissonTimeout(start=None, average=0):
        """Generate deadline using Poisson distribution"""
        if start is None:
            start = time()
        if average == 0:
            average = FLUFF_TRIGGER_MEAN_DELAY
        result = start + expovariate(1.0 / average) + FLUFF_TRIGGER_FIXED_DELAY
        logger.debug("DEBUG: Generated poisson timeout: %s (start: %s, average: %s)", result, start, average)
        return result

    def init_pool(self, pool):
        """pass pool instance"""
        logger.debug("DEBUG: Initializing pool with %s connections", len(pool.outboundConnections))
        self.pool = pool

    def init_dandelion_enabled(self, config):
        """Check if Dandelion is enabled and set value in enabled attribute"""
        dandelion_enabled = config.safeGetInt('network', 'dandelion')
        logger.debug("DEBUG: Raw dandelion_enabled value from config: %s", dandelion_enabled)
        
        # dandelion requires outbound connections, without them,
        # stem objects will get stuck forever
        if not config.safeGetBoolean(
                'bitmessagesettings', 'sendoutgoingconnections'):
            dandelion_enabled = 0
            logger.debug("DEBUG: Dandelion disabled due to sendoutgoingconnections=False")
            
        self.enabled = dandelion_enabled
        logger.debug("DEBUG: Final dandelion enabled status: %s", self.enabled)

    def addHash(self, hashId, source=None, stream=1):
        """Add inventory vector to dandelion stem return status of dandelion enabled"""
        assert self.enabled is not None
        with self.lock:
            stem_node = self.getNodeStem(source)
            timeout = self.poissonTimeout()
            self.hashMap[bytes(hashId)] = Stem(
                stem_node,
                stream,
                timeout)
            logger.debug("DEBUG: Added hash %s with child=%s, stream=%s, timeout=%s", 
                        hexlify(hashId), stem_node, stream, timeout)

    def setHashStream(self, hashId, stream=1):
        """
        Update stream for inventory vector (as inv/dinv commands don't
        include streams, we only learn this after receiving the object)
        """
        with self.lock:
            hashId_bytes = bytes(hashId)
            if hashId_bytes in self.hashMap:
                old_stem = self.hashMap[hashId_bytes]
                new_timeout = self.poissonTimeout()
                self.hashMap[hashId_bytes] = Stem(
                    old_stem.child,
                    stream,
                    new_timeout)
                logger.debug("DEBUG: Updated stream for hash %s: new_stream=%s, new_timeout=%s", 
                           hexlify(hashId), stream, new_timeout)

    def removeHash(self, hashId, reason="no reason specified"):
        """Switch inventory vector from stem to fluff mode"""
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                'DEBUG: %s entering fluff mode due to %s.',
                hexlify(hashId), reason)
        with self.lock:
            try:
                del self.hashMap[bytes(hashId)]
                logger.debug("DEBUG: Successfully removed hash %s", hexlify(hashId))
            except KeyError:
                logger.debug("DEBUG: Failed to remove hash %s (not found)", hexlify(hashId))
                pass

    def hasHash(self, hashId):
        """Is inventory vector in stem mode?"""
        result = bytes(hashId) in self.hashMap
        logger.debug("DEBUG: Checking if hash %s exists in stem mode: %s", hexlify(hashId), result)
        return result

    def objectChildStem(self, hashId):
        """Child (i.e. next) node for an inventory vector during stem mode"""
        result = self.hashMap[bytes(hashId)].child
        logger.debug("DEBUG: Getting child stem for hash %s: %s", hexlify(hashId), result)
        return result

    def maybeAddStem(self, connection, invQueue):
        """
        If we had too few outbound connections, add the current one to the
        current stem list. Dandelion as designed by the authors should
        always have two active stem child connections.
        """
        # fewer than MAX_STEMS outbound connections at last reshuffle?
        with self.lock:
            if len(self.stem) < MAX_STEMS:
                logger.debug("DEBUG: Adding new stem connection (current stems: %s)", len(self.stem))
                self.stem.append(connection)
                
                # Update nodeMap for nodes with None value
                none_nodes = [k for k, v in six.iteritems(self.nodeMap) if v is None]
                if none_nodes:
                    logger.debug("DEBUG: Updating %s nodes in nodeMap with new stem", len(none_nodes))
                    for k in none_nodes:
                        self.nodeMap[k] = connection
                
                # Update hashMap for hashes with None child
                none_hashes = {
                    k: v for k, v in six.iteritems(self.hashMap) 
                    if v.child is None
                }
                if none_hashes:
                    logger.debug("DEBUG: Updating %s hashes in hashMap with new stem", len(none_hashes))
                    for k, v in six.iteritems(none_hashes):
                        new_stem = Stem(connection, v.stream, self.poissonTimeout())
                        self.hashMap[k] = new_stem
                        invQueue.put((v.stream, k, v.child))
                        logger.debug("DEBUG: Updated hash %s with new stem %s", hexlify(k), connection)

    def maybeRemoveStem(self, connection):
        """
        Remove current connection from the stem list (called e.g. when
        a connection is closed).
        """
        # is the stem active?
        with self.lock:
            if connection in self.stem:
                logger.debug("DEBUG: Removing stem connection %s", connection)
                self.stem.remove(connection)
                
                # Update nodeMap for nodes pointing to removed connection
                affected_nodes = [
                    k for k, v in six.iteritems(self.nodeMap)
                    if v == connection
                ]
                if affected_nodes:
                    logger.debug("DEBUG: Setting %s nodes in nodeMap to None", len(affected_nodes))
                    for k in affected_nodes:
                        self.nodeMap[k] = None
                
                # Update hashMap for hashes with removed connection as child
                affected_hashes = {
                    k: v for k, v in six.iteritems(self.hashMap)
                    if v.child == connection
                }
                if affected_hashes:
                    logger.debug("DEBUG: Setting %s hashes in hashMap to None child", len(affected_hashes))
                    for k, v in six.iteritems(affected_hashes):
                        new_stem = Stem(None, v.stream, self.poissonTimeout())
                        self.hashMap[k] = new_stem

    def pickStem(self, parent=None):
        """
        Pick a random active stem, but not the parent one
        (the one where an object came from)
        """
        try:
            # pick a random from available stems
            stem = choice(range(len(self.stem)))  # nosec B311
            if self.stem[stem] == parent:
                # one stem available and it's the parent
                if len(self.stem) == 1:
                    logger.debug("DEBUG: Only one stem available and it's the parent")
                    return None
                # else, pick the other one
                logger.debug("DEBUG: Picking alternative stem to avoid parent")
                return self.stem[1 - stem]
            # all ok
            logger.debug("DEBUG: Randomly selected stem %s", stem)
            return self.stem[stem]
        except IndexError:
            # no stems available
            logger.debug("DEBUG: No stems available for picking")
            return None

    def getNodeStem(self, node=None):
        """
        Return child stem node for a given parent stem node
        (the mapping is static for about 10 minutes, then it reshuffles)
        """
        with self.lock:
            try:
                result = self.nodeMap[node]
                logger.debug("DEBUG: Found existing stem mapping for node %s: %s", node, result)
                return result
            except KeyError:
                new_stem = self.pickStem(node)
                self.nodeMap[node] = new_stem
                logger.debug("DEBUG: Created new stem mapping for node %s: %s", node, new_stem)
                return new_stem

    def expire(self, invQueue):
        """Switch expired objects from stem to fluff mode"""
        with self.lock:
            deadline = time()
            toDelete = [
                [v.stream, k, v.child] for k, v in six.iteritems(self.hashMap)
                if v.timeout < deadline
            ]
            logger.debug("DEBUG: Found %s expired hashes (deadline: %s)", len(toDelete), deadline)

            for row in toDelete:
                self.removeHash(row[1], 'expiration')
                invQueue.put(row)
                logger.debug("DEBUG: Processed expired hash %s", hexlify(row[1]))
        return toDelete

    def reRandomiseStems(self):
        """Re-shuffle stem mapping (parent <-> child pairs)"""
        assert self.pool is not None
        if self.refresh > time():
            logger.debug("DEBUG: Not time to re-randomise stems yet (refresh at %s)", self.refresh)
            return

        with self.lock:
            try:
                # random two connections
                self.stem = sample(
                    sorted(self.pool.outboundConnections.values()), MAX_STEMS)
                logger.debug("DEBUG: Re-randomised stems: selected %s new stems", len(self.stem))
            # not enough stems available
            except ValueError:
                self.stem = list(self.pool.outboundConnections.values())
                logger.debug("DEBUG: Using all %s available stems (not enough for sample)", len(self.stem))
            
            self.nodeMap = {}
            # hashMap stays to cater for pending stems
            logger.debug("DEBUG: Reset nodeMap, kept %s hashes in hashMap", len(self.hashMap))
        
        self.refresh = time() + REASSIGN_INTERVAL
        logger.debug("DEBUG: Set next refresh time to %s", self.refresh)
