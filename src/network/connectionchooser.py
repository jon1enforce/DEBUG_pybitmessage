"""
Select which node to connect to
"""
# pylint: disable=too-many-branches
import logging
import random

from six.moves import queue

from network import knownnodes
import protocol
import state

from bmconfigparser import config
from network import portCheckerQueue

logger = logging.getLogger('default')


def _ends_with(s, tail):
    try:
        result = s.endswith(tail)
    except:
        result = s.decode("utf-8", "replace").endswith(tail)
    logger.debug("DEBUG: _ends_with check - string: %s, tail: %s, result: %s", s, tail, result)
    return result

def getDiscoveredPeer():
    """Get a peer from the local peer discovery list"""
    logger.debug("DEBUG: Getting discovered peer")
    try:
        peer = random.choice(list(state.discoveredPeers.keys()))  # nosec B311
        logger.debug("DEBUG: Selected discovered peer: %s", peer)
    except (IndexError, KeyError) as e:
        logger.debug("DEBUG: No discovered peers available: %s", str(e))
        raise ValueError
    try:
        del state.discoveredPeers[peer]
        logger.debug("DEBUG: Removed peer from discoveredPeers")
    except KeyError:
        logger.debug("DEBUG: Peer already removed from discoveredPeers")
        pass
    return peer


def chooseConnection(stream):
    """Returns an appropriate connection"""
    logger.debug("DEBUG: Choosing connection for stream %s", stream)
    
    haveOnion = config.safeGet("bitmessagesettings", "socksproxytype")[0:5] == 'SOCKS'
    onionOnly = config.safeGetBoolean("bitmessagesettings", "onionservicesonly")
    logger.debug("DEBUG: Connection settings - haveOnion: %s, onionOnly: %s", haveOnion, onionOnly)

    try:
        retval = portCheckerQueue.get(False)
        portCheckerQueue.task_done()
        logger.debug("DEBUG: Found connection in portCheckerQueue: %s", retval)
        return retval
    except queue.Empty:
        logger.debug("DEBUG: No connections in portCheckerQueue")
        pass

    # with a probability of 0.5, connect to a discovered peer
    if random.choice((False, True)) and not haveOnion:  # nosec B311
        logger.debug("DEBUG: Trying to use discovered peer")
        try:
            peer = getDiscoveredPeer()
            logger.debug("DEBUG: Using discovered peer: %s", peer)
            return peer
        except ValueError:
            logger.debug("DEBUG: No discovered peers available")
            pass

    logger.debug("DEBUG: Selecting from known nodes")
    for attempt in range(50):
        logger.debug("DEBUG: Attempt %s/50 to find suitable peer", attempt + 1)
        try:
            peer = random.choice(list(knownnodes.knownNodes[stream].keys()))  # nosec B311
            logger.debug("DEBUG: Selected peer candidate: %s", peer)
            
            try:
                peer_info = knownnodes.knownNodes[stream][peer]
                if peer_info.get('self'):
                    logger.debug("DEBUG: Skipping self-connection")
                    continue
                rating = peer_info["rating"]
                logger.debug("DEBUG: Peer rating: %s", rating)
            except TypeError:
                logger.warning('Error in %s', peer)
                rating = 0
                logger.debug("DEBUG: Using default rating 0 due to error")

            if haveOnion:
                logger.debug("DEBUG: Onion routing enabled - checking host requirements")
                # do not connect to raw IP addresses
                # --keep all traffic within Tor overlay
                if onionOnly and not _ends_with(peer.host, '.onion'):
                    logger.debug("DEBUG: Skipping non-onion host in onion-only mode")
                    continue
                
                # onion addresses have a higher priority when SOCKS
                if _ends_with(peer.host, '.onion') and rating > 0:
                    rating = 1
                    logger.debug("DEBUG: Upgraded onion host rating to 1")
                # TODO: need better check
                elif not peer.host.startswith('bootstrap'):
                    encodedAddr = protocol.encodeHost(peer.host)
                    logger.debug("DEBUG: Encoded address: %s", encodedAddr)
                    # don't connect to local IPs when using SOCKS
                    if not protocol.checkIPAddress(encodedAddr, False):
                        logger.debug("DEBUG: Skipping local IP address")
                        continue

            if rating > 1:
                rating = 1
                logger.debug("DEBUG: Capped rating at 1")

            try:
                threshold = 0.05 / (1.0 - rating)
                rand_val = random.random()  # nosec B311
                logger.debug("DEBUG: Selection threshold: %s, random value: %s", threshold, rand_val)
                if threshold > rand_val:
                    logger.debug("DEBUG: Selected peer based on rating: %s", peer)
                    return peer
            except ZeroDivisionError:
                logger.debug("DEBUG: Zero division - selecting peer immediately: %s", peer)
                return peer

        except Exception as e:
            logger.debug("DEBUG: Error during peer selection: %s", str(e))
            continue

    logger.debug("DEBUG: Failed to find suitable peer after 50 attempts")
    raise ValueError("No suitable peer found")


# Additional debug information about known nodes
def debug_known_nodes():
    for stream in knownnodes.knownNodes:
        logger.debug("DEBUG: Known nodes for stream %s: %s", stream, len(knownnodes.knownNodes[stream]))
