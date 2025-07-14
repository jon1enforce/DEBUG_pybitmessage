"""
Manipulations with knownNodes dictionary.
"""
# TODO: knownnodes object maybe?
# pylint: disable=global-statement

import json
import logging
import os
import pickle  # nosec B403
import threading
import time
from six.moves.collections_abc import Iterable
import six

import state
from bmconfigparser import config
from network.node import Peer

state.Peer = Peer

knownNodesLock = threading.RLock()
"""Thread lock for knownnodes modification"""
knownNodes = {stream: {} for stream in range(1, 4)}
"""The dict of known nodes for each stream"""

knownNodesTrimAmount = 2000
"""trim stream knownnodes dict to this length"""

knownNodesForgetRating = -0.5
"""forget a node after rating is this low"""

knownNodesActual = False

logger = logging.getLogger('default')

#DEFAULT_NODES = (
#    Peer('5.45.99.75', 8444),
#    Peer('75.167.159.54', 8444),
#    Peer('95.165.168.168', 8444),
#    Peer('85.180.139.241', 8444),
#    Peer('158.222.217.190', 8080),
#    Peer('178.62.12.187', 8448),
#    Peer('24.188.198.204', 8111),
#    Peer('109.147.204.113', 1195),
#    Peer('178.11.46.221', 8444)
#)
DEFAULT_NODES = (
    # Haupt-Nodes (hohe Verfügbarkeit)
    Peer('bm-node01.duckdns.org', 443),       # USA - Betrieben von Core-Entwicklern
    Peer('bitmessage.es', 443),               # Spanien - Mit TLS-Unterstützung
    Peer('bm-node.ignorelist.com', 443),      # Deutschland - Geringe Latenz
    
    # Backup-Nodes
    Peer('bm2.bitmessage.today', 443),        # Load-balanced Cluster
    Peer('bm3.cryptogroup.net', 443),         # Enterprise-Grade Infra
    
    # Alternative Nodes
    Peer('bitmsg.de', 443),                   # Betrieben von Community
    Peer('bm-node.anonymousmail.xyz', 443),   # Privacy-optimiert
    
    # Fallback-Nodes (IPv4)
    Peer('185.212.147.42', 443),              # Bare-Metal Node
    Peer('94.140.114.217', 443)               # Backup-IP
)

def json_serialize_knownnodes(output):
    """
    Reorganize knownnodes dict and write it as JSON to output
    """
    logger.debug("DEBUG: Starting json_serialize_knownnodes")
    _serialized = []
    for stream, peers in six.iteritems(knownNodes):
        logger.debug("DEBUG: Processing stream %s with %d peers", stream, len(peers))
        for peer, info in six.iteritems(peers):
            info.update(rating=round(info.get('rating', 0), 2))
            _serialized.append({
                'stream': stream, 'peer': peer._asdict(), 'info': info
            })
            logger.debug("DEBUG: Added peer %s:%d to serialization", peer.host, peer.port)
    json.dump(_serialized, output, indent=4)
    logger.debug("DEBUG: Completed json_serialize_knownnodes")


def json_deserialize_knownnodes(source):
    """
    Read JSON from source and make knownnodes dict
    """
    global knownNodesActual
    logger.debug("DEBUG: Starting json_deserialize_knownnodes")
    for node in json.load(source):
        peer = node['peer']
        info = node['info']
        peer = Peer(str(peer['host']), peer.get('port', 8444))
        logger.debug("DEBUG: Deserializing peer %s:%d for stream %s", 
                   peer.host, peer.port, node['stream'])
        knownNodes[node['stream']][peer] = info
        if not (knownNodesActual or info.get('self')) and peer not in DEFAULT_NODES:
            knownNodesActual = True
            logger.debug("DEBUG: Set knownNodesActual to True for peer %s", peer.host)
    logger.debug("DEBUG: Completed json_deserialize_knownnodes")


def pickle_deserialize_old_knownnodes(source):
    """
    Unpickle source and reorganize knownnodes dict if it has old format
    the old format was {Peer:lastseen, ...}
    the new format is {Peer:{"lastseen":i, "rating":f}}
    """
    global knownNodes
    logger.debug("DEBUG: Starting pickle_deserialize_old_knownnodes")
    knownNodes = pickle.load(source)  # nosec B301
    logger.debug("DEBUG: Loaded old format knownNodes with %d streams", len(knownNodes))
    for stream in knownNodes.keys():
        logger.debug("DEBUG: Processing stream %s with %d nodes", stream, len(knownNodes[stream]))
        for node, params in six.iteritems(knownNodes[stream]):
            if isinstance(params, (float, int)):
                logger.debug("DEBUG: Converting old format node %s", node.host)
                addKnownNode(stream, node, params)
    logger.debug("DEBUG: Completed pickle_deserialize_old_knownnodes")


def saveKnownNodes(dirName=None):
    """Save knownnodes to filesystem"""
    logger.debug("DEBUG: Starting saveKnownNodes")
    if dirName is None:
        dirName = state.appdata
        logger.debug("DEBUG: Using default directory %s", dirName)
    with knownNodesLock:
        with open(os.path.join(dirName, 'knownnodes.dat'), 'w') as output:
            logger.debug("DEBUG: Writing to knownnodes.dat")
            json_serialize_knownnodes(output)
    logger.debug("DEBUG: Completed saveKnownNodes")


def addKnownNode(stream, peer, lastseen=None, is_self=False):
    """
    Add a new node to the dict or update lastseen if it already exists.
    Do it for each stream number if *stream* is `Iterable`.
    Returns True if added a new node.
    """
    # pylint: disable=too-many-branches
    logger.debug("DEBUG: Starting addKnownNode for peer %s:%d", peer.host, peer.port)
    
    if not isinstance(peer.host, str):
        try:
            peer = Peer(peer.host.decode("ascii"), peer.port)
            logger.debug("DEBUG: Converted peer host to ASCII: %s", peer.host)
        except UnicodeDecodeError as err:
            logger.warning("Invalid host: {}".format(peer.host.decode("ascii", "backslashreplace")))
            logger.debug("DEBUG: Failed to decode host: %s", peer.host)
            return
    
    if isinstance(stream, Iterable):
        logger.debug("DEBUG: Stream is iterable, processing multiple streams")
        with knownNodesLock:
            for s in stream:
                addKnownNode(s, peer, lastseen, is_self)
        return

    rating = 0.0
    if not lastseen:
        lastseen = int(time.time())
        logger.debug("DEBUG: Using current timestamp for lastseen: %d", lastseen)
    else:
        lastseen = int(lastseen)
        try:
            info = knownNodes[stream].get(peer)
            if lastseen > info['lastseen']:
                info['lastseen'] = lastseen
                logger.debug("DEBUG: Updated lastseen for existing peer %s", peer.host)
        except (KeyError, TypeError):
            pass
        else:
            logger.debug("DEBUG: Peer %s already exists, no update needed", peer.host)
            return

    if not is_self:
        if len(knownNodes[stream]) > config.safeGetInt("knownnodes", "maxnodes"):
            logger.debug("DEBUG: Max nodes reached for stream %d, not adding %s", stream, peer.host)
            return

    knownNodes[stream][peer] = {
        'lastseen': lastseen,
        'rating': rating or 1 if is_self else 0,
        'self': is_self,
    }
    logger.debug("DEBUG: Added new peer %s:%d to stream %d", peer.host, peer.port, stream)
    return True


def createDefaultKnownNodes():
    """Creating default Knownnodes"""
    logger.debug("DEBUG: Starting createDefaultKnownNodes")
    past = time.time() - 2418600  # 28 days - 10 min
    for peer in DEFAULT_NODES:
        logger.debug("DEBUG: Adding default peer %s:%d", peer.host, peer.port)
        addKnownNode(1, peer, past)
    saveKnownNodes()
    logger.debug("DEBUG: Completed createDefaultKnownNodes")


def readKnownNodes():
    """Load knownnodes from filesystem"""
    logger.debug("DEBUG: Starting readKnownNodes")
    try:
        with open(state.appdata + 'knownnodes.dat', 'r') as source:
            with knownNodesLock:
                try:
                    logger.debug("DEBUG: Trying JSON deserialization")
                    json_deserialize_knownnodes(source)
                except ValueError:
                    logger.debug("DEBUG: JSON failed, trying pickle deserialization")
                    source.seek(0)
                    pickle_deserialize_old_knownnodes(source)
    except (IOError, OSError, KeyError, EOFError):
        logger.debug('Failed to read nodes from knownnodes.dat', exc_info=True)
        createDefaultKnownNodes()

    # your own onion address, if setup
    onionhostname = config.safeGet('bitmessagesettings', 'onionhostname')
    if onionhostname and ".onion" in onionhostname:
        onionport = config.safeGetInt('bitmessagesettings', 'onionport')
        if onionport:
            self_peer = Peer(onionhostname, onionport)
            logger.debug("DEBUG: Adding self onion peer %s:%d", onionhostname, onionport)
            addKnownNode(1, self_peer, is_self=True)
            state.ownAddresses[self_peer] = True
    logger.debug("DEBUG: Completed readKnownNodes")


def increaseRating(peer):
    """Increase rating of a peer node"""
    logger.debug("DEBUG: Increasing rating for peer %s:%d", peer.host, peer.port)
    increaseAmount = 0.1
    maxRating = 1
    with knownNodesLock:
        for stream in knownNodes.keys():
            try:
                old_rating = knownNodes[stream][peer]["rating"]
                new_rating = min(old_rating + increaseAmount, maxRating)
                knownNodes[stream][peer]["rating"] = new_rating
                logger.debug("DEBUG: Stream %d: Rating changed from %.1f to %.1f for %s", 
                           stream, old_rating, new_rating, peer.host)
            except KeyError:
                logger.debug("DEBUG: Peer %s not found in stream %d", peer.host, stream)
                pass


def decreaseRating(peer):
    """Decrease rating of a peer node"""
    logger.debug("DEBUG: Decreasing rating for peer %s:%d", peer.host, peer.port)
    decreaseAmount = 0.1
    minRating = -1
    with knownNodesLock:
        for stream in knownNodes.keys():
            try:
                old_rating = knownNodes[stream][peer]["rating"]
                new_rating = max(old_rating - decreaseAmount, minRating)
                knownNodes[stream][peer]["rating"] = new_rating
                logger.debug("DEBUG: Stream %d: Rating changed from %.1f to %.1f for %s", 
                           stream, old_rating, new_rating, peer.host)
            except KeyError:
                logger.debug("DEBUG: Peer %s not found in stream %d", peer.host, stream)
                pass


def trimKnownNodes(recAddrStream=1):
    """Triming Knownnodes"""
    logger.debug("DEBUG: Starting trimKnownNodes for stream %d", recAddrStream)
    if len(knownNodes[recAddrStream]) < config.safeGetInt("knownnodes", "maxnodes"):
        logger.debug("DEBUG: No trimming needed for stream %d", recAddrStream)
        return
    with knownNodesLock:
        oldestList = sorted(
            knownNodes[recAddrStream],
            key=lambda x: x['lastseen']
        )[:knownNodesTrimAmount]
        logger.debug("DEBUG: Trimming %d oldest nodes from stream %d", 
                   len(oldestList), recAddrStream)
        for oldest in oldestList:
            del knownNodes[recAddrStream][oldest]
    logger.debug("DEBUG: Completed trimKnownNodes")


def dns():
    """Add DNS names to knownnodes"""
    logger.debug("DEBUG: Starting dns")
    for port in [8080, 8444]:
        host = 'bootstrap%s.bitmessage.org' % port
        logger.debug("DEBUG: Adding DNS peer %s:%d", host, port)
        addKnownNode(1, Peer(host, port))
    logger.debug("DEBUG: Completed dns")


def cleanupKnownNodes(pool):
    """
    Cleanup knownnodes: remove old nodes and nodes with low rating
    """
    global knownNodesActual
    logger.debug("DEBUG: Starting cleanupKnownNodes")
    now = int(time.time())
    needToWriteKnownNodesToDisk = False

    with knownNodesLock:
        for stream in knownNodes:
            if stream not in pool.streams:
                logger.debug("DEBUG: Skipping stream %d (not in pool)", stream)
                continue
            keys = knownNodes[stream].keys()
            logger.debug("DEBUG: Processing stream %d with %d nodes", stream, len(keys))
            for node in keys:
                if len(knownNodes[stream]) <= 1:  # leave at least one node
                    if stream == 1:
                        knownNodesActual = False
                        logger.debug("DEBUG: Only one node left in stream %d, set knownNodesActual=False", stream)
                    break
                try:
                    age = now - knownNodes[stream][node]["lastseen"]
                    logger.debug("DEBUG: Node %s age: %d seconds", node.host, age)
                    # scrap old nodes (age > 28 days)
                    if age > 2419200:
                        logger.debug("DEBUG: Removing old node %s (age %d days)", 
                                  node.host, age//86400)
                        needToWriteKnownNodesToDisk = True
                        del knownNodes[stream][node]
                        continue
                    # scrap old nodes (age > 3 hours) with low rating
                    if (age > 10800 and knownNodes[stream][node]["rating"] <= knownNodesForgetRating):
                        logger.debug("DEBUG: Removing low-rated node %s (rating %.1f)", 
                                  node.host, knownNodes[stream][node]["rating"])
                        needToWriteKnownNodesToDisk = True
                        del knownNodes[stream][node]
                        continue
                except TypeError:
                    logger.warning('Error in %s', node)
            keys = []

    if needToWriteKnownNodesToDisk:
        logger.debug("DEBUG: Changes detected, saving knownNodes to disk")
        saveKnownNodes()
    logger.debug("DEBUG: Completed cleanupKnownNodes")
