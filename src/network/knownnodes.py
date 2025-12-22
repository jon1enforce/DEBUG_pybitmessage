"""
Manipulations with knownNodes dictionary.
"""
# TODO: knownnodes object maybe?
# pylint: disable=global-statement

import json
import logging
import os
import threading
import time
from six.moves.collections_abc import Iterable
import six

import state
from bmconfigparser import config
from network.node import Peer
from helper_sql import safe_decode

state.Peer = Peer

knownNodesLock = threading.RLock()
"""Thread lock for knownnodes modification"""
knownNodes = {stream: {} for stream in range(1, 4)}
"""The dict of known nodes for each stream"""

knownNodesTrimAmount = 2000
"""trim stream knownnodes dict to this length"""

knownNodesForgetRating = -0.5
"""forget a node after rating is low"""

knownNodesActual = False

logger = logging.getLogger('default')

# Optimized DEFAULT_NODES
DEFAULT_NODES = (
    Peer('bm-node01.duckdns.org', 443),
    Peer('bitmessage.es', 443),
    Peer('bm-node.ignorelist.com', 443),
    Peer('bm2.bitmessage.today', 443),
    Peer('bm3.cryptogroup.net', 443),
    Peer('bitmsg.de', 443),
    Peer('bm-node.anonymousmail.xyz', 443),
    Peer('185.212.147.42', 443),
    Peer('94.140.114.217', 443)
)


def json_serialize_knownnodes(output):
    """
    Reorganize knownnodes dict and write it as JSON to output
    Handles bytes hostnames by converting them to strings
    """
    logger.debug("Starting json_serialize_knownnodes")
    _serialized = []
    
    with knownNodesLock:
        for stream, peers in six.iteritems(knownNodes):
            logger.debug("Processing stream %s with %d peers", stream, len(peers))
            # Create snapshot for safe iteration
            peers_snapshot = list(peers.items())
            
            for peer, info in peers_snapshot:
                try:
                    # Convert host to string if it's bytes
                    host = peer.host
                    if isinstance(host, bytes):
                        host = safe_decode(host, 'utf-8', 'ignore')
                    
                    info_copy = info.copy()
                    info_copy.update(rating=round(info_copy.get('rating', 0), 2))
                    _serialized.append({
                        'stream': stream, 
                        'peer': {'host': host, 'port': peer.port}, 
                        'info': info_copy
                    })
                except Exception as e:
                    logger.debug("Error serializing peer %s: %s", peer, e)
    
    json.dump(_serialized, output, indent=4)
    logger.debug("Completed json_serialize_knownnodes")


def json_deserialize_knownnodes(source):
    """
    Read JSON from source and make knownnodes dict
    Handles string hostnames (may have been bytes before)
    """
    global knownNodesActual
    logger.debug("Starting json_deserialize_knownnodes")
    
    try:
        data = json.load(source)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse knownnodes.dat: %s", e)
        return
    
    with knownNodesLock:
        for node in data:
            try:
                peer_data = node['peer']
                info = node['info']
                
                # Get host and ensure it's string
                host = peer_data['host']
                if isinstance(host, bytes):
                    host = safe_decode(host, 'utf-8', 'ignore')
                elif not isinstance(host, str):
                    host = str(host)
                
                peer = Peer(host, peer_data.get('port', 8444))
                stream = node['stream']
                
                if stream not in knownNodes:
                    knownNodes[stream] = {}
                
                knownNodes[stream][peer] = info
                
                if not (knownNodesActual or info.get('self')) and peer not in DEFAULT_NODES:
                    knownNodesActual = True
                    
            except (KeyError, ValueError) as e:
                logger.debug("Error deserializing node: %s", e)
                continue
    
    logger.debug("Completed json_deserialize_knownnodes")


def pickle_deserialize_old_knownnodes(source):
    """
    DEACTIVATED - pickle removed for security reasons
    """
    logger.error("🚨 SECURITY MEASURE: pickle deserialization has been deactivated")
    logger.error("Old knownnodes.dat formats are no longer supported")
    
    with knownNodesLock:
        knownNodes.clear()
        for stream in range(1, 4):
            knownNodes[stream] = {}


def saveKnownNodes(dirName=None):
    """Save knownnodes to filesystem"""
    logger.debug("Starting saveKnownNodes")
    
    if dirName is None:
        dirName = state.appdata
    
    try:
        with knownNodesLock:
            temp_path = os.path.join(dirName, 'knownnodes.dat.tmp')
            final_path = os.path.join(dirName, 'knownnodes.dat')
            
            # Write to temp file first
            with open(temp_path, 'w') as output:
                json_serialize_knownnodes(output)
            
            # Atomic rename
            os.replace(temp_path, final_path)
            
    except Exception as e:
        logger.error("Failed to save knownnodes: %s", e)
        raise
    
    logger.debug("Completed saveKnownNodes")


def addKnownNode(stream, peer, lastseen=None, is_self=False):
    """
    Add a new node to the dict or update lastseen if it already exists.
    Do it for each stream number if *stream* is `Iterable`.
    Returns True if added a new node.
    """
    logger.debug("Starting addKnownNode for peer %s:%d", peer.host, peer.port)
    
    # Validate peer host - ensure it's not bytes
    if isinstance(peer.host, bytes):
        try:
            host_str = safe_decode(peer.host, 'utf-8', 'ignore')
            peer = Peer(host_str, peer.port)
        except (UnicodeDecodeError, AttributeError) as err:
            logger.warning("Invalid host bytes: %s", err)
            return False
    
    # Handle multiple streams
    if isinstance(stream, Iterable):
        added = False
        with knownNodesLock:
            for s in stream:
                if addKnownNode(s, peer, lastseen, is_self):
                    added = True
        return added
    
    # Single stream processing
    with knownNodesLock:
        try:
            stream_dict = knownNodes.get(stream)
            if stream_dict is None:
                knownNodes[stream] = {}
                stream_dict = knownNodes[stream]
            
            # Check if node already exists
            if peer in stream_dict:
                info = stream_dict[peer]
                if lastseen:
                    lastseen_val = int(lastseen)
                    if lastseen_val > info.get('lastseen', 0):
                        info['lastseen'] = lastseen_val
                        return True
                return False
            
            # Check max nodes
            if not is_self and len(stream_dict) > config.safeGetInt("knownnodes", "maxnodes", 1000):
                logger.debug("Max nodes reached for stream %d, not adding %s", stream, peer.host)
                return False
            
            # Add new node
            stream_dict[peer] = {
                'lastseen': int(lastseen or time.time()),
                'rating': 1.0 if is_self else 0.0,
                'self': is_self,
            }
            
            logger.debug("Added new peer %s:%d to stream %d", peer.host, peer.port, stream)
            return True
            
        except Exception as e:
            logger.error("Error adding known node: %s", e)
            return False


def createDefaultKnownNodes():
    """Creating default Knownnodes"""
    logger.debug("Starting createDefaultKnownNodes")
    
    past = time.time() - 2418600  # 28 days - 10 min
    
    with knownNodesLock:
        for peer in DEFAULT_NODES:
            addKnownNode(1, peer, past)
    
    saveKnownNodes()
    logger.debug("Completed createDefaultKnownNodes")


def readKnownNodes():
    """Load knownnodes from filesystem"""
    logger.debug("Starting readKnownNodes")
    
    try:
        filepath = os.path.join(state.appdata, 'knownnodes.dat')
        if not os.path.exists(filepath):
            logger.debug("knownnodes.dat not found, creating default")
            createDefaultKnownNodes()
            return
        
        with open(filepath, 'r') as source:
            with knownNodesLock:
                try:
                    json_deserialize_knownnodes(source)
                except Exception as e:
                    logger.error("Failed to load knownnodes: %s", e)
                    createDefaultKnownNodes()
                    
    except Exception as e:
        logger.error('Failed to read knownnodes: %s', e)
        createDefaultKnownNodes()
    
    # Add onion host if configured
    onionhostname = config.safeGet('bitmessagesettings', 'onionhostname')
    if onionhostname and ".onion" in onionhostname:
        onionport = config.safeGetInt('bitmessagesettings', 'onionport')
        if onionport:
            self_peer = Peer(onionhostname, onionport)
            with knownNodesLock:
                addKnownNode(1, self_peer, is_self=True)
                state.ownAddresses[self_peer] = True
    
    logger.debug("Completed readKnownNodes")


def increaseRating(peer):
    """Increase rating of a peer node"""
    logger.debug("Increasing rating for peer %s:%d", peer.host, peer.port)
    
    increaseAmount = 0.1
    maxRating = 1.0
    
    with knownNodesLock:
        for stream, nodes in knownNodes.items():
            try:
                if peer in nodes:
                    old_rating = nodes[peer].get("rating", 0)
                    new_rating = min(old_rating + increaseAmount, maxRating)
                    nodes[peer]["rating"] = new_rating
                    logger.debug("Stream %d: Rating changed from %.1f to %.1f for %s", 
                               stream, old_rating, new_rating, peer.host)
            except (KeyError, TypeError):
                continue


def decreaseRating(peer):
    """Decrease rating of a peer node"""
    logger.debug("Decreasing rating for peer %s:%d", peer.host, peer.port)
    
    decreaseAmount = 0.1
    minRating = -1.0
    
    with knownNodesLock:
        for stream, nodes in knownNodes.items():
            try:
                if peer in nodes:
                    old_rating = nodes[peer].get("rating", 0)
                    new_rating = max(old_rating - decreaseAmount, minRating)
                    nodes[peer]["rating"] = new_rating
                    logger.debug("Stream %d: Rating changed from %.1f to %.1f for %s", 
                               stream, old_rating, new_rating, peer.host)
            except (KeyError, TypeError):
                continue


def trimKnownNodes(recAddrStream=1):
    """Triming Knownnodes"""
    logger.debug("Starting trimKnownNodes for stream %d", recAddrStream)
    
    max_nodes = config.safeGetInt("knownnodes", "maxnodes", 1000)
    
    with knownNodesLock:
        stream_nodes = knownNodes.get(recAddrStream)
        if not stream_nodes or len(stream_nodes) < max_nodes:
            return
        
        # Create sorted list of (peer, lastseen) tuples
        nodes_with_age = []
        for peer, info in list(stream_nodes.items()):
            try:
                nodes_with_age.append((peer, info.get('lastseen', 0)))
            except (KeyError, TypeError):
                continue
        
        # Sort by lastseen (oldest first)
        nodes_with_age.sort(key=lambda x: x[1])
        
        # Remove oldest nodes
        nodes_to_remove = nodes_with_age[:knownNodesTrimAmount]
        for peer, _ in nodes_to_remove:
            try:
                del stream_nodes[peer]
            except KeyError:
                pass
        
        logger.debug("Trimmed %d nodes from stream %d", len(nodes_to_remove), recAddrStream)


def dns():
    """Add DNS names to knownnodes"""
    logger.debug("Starting dns")
    
    with knownNodesLock:
        for port in [8080, 8444]:
            host = 'bootstrap%s.bitmessage.org' % port
            addKnownNode(1, Peer(host, port))
    
    logger.debug("Completed dns")


def cleanupKnownNodes(pool):
    """
    Thread-safe cleanup knownnodes: remove old nodes and nodes with low rating
    """
    global knownNodesActual
    logger.debug("Starting thread-safe cleanupKnownNodes")
    
    now = int(time.time())
    needToWriteKnownNodesToDisk = False
    
    with knownNodesLock:
        for stream in list(knownNodes.keys()):
            if stream not in pool.streams:
                continue
            
            nodes = knownNodes.get(stream)
            if not nodes:
                continue
            
            # Create snapshot of nodes to process
            nodes_to_process = []
            try:
                nodes_to_process = list(nodes.items())
            except RuntimeError:
                logger.debug("Stream %d nodes changed during snapshot, skipping", stream)
                continue
            
            nodes_removed = 0
            
            for node, info in nodes_to_process:
                try:
                    # Skip if node was already removed
                    if node not in nodes:
                        continue
                    
                    age = now - info.get("lastseen", 0)
                    rating = info.get("rating", 0)
                    
                    # Remove nodes older than 28 days
                    if age > 2419200:  # 28 days
                        del nodes[node]
                        needToWriteKnownNodesToDisk = True
                        nodes_removed += 1
                        continue
                    
                    # Remove nodes older than 3 hours with low rating
                    if age > 10800 and rating <= knownNodesForgetRating:
                        del nodes[node]
                        needToWriteKnownNodesToDisk = True
                        nodes_removed += 1
                        continue
                        
                except (KeyError, TypeError) as e:
                    logger.debug("Error processing node %s: %s", node, e)
                    continue
            
            # Update knownNodesActual if stream 1 has few nodes
            if stream == 1 and len(nodes) <= 1:
                knownNodesActual = False
            
            logger.debug("Stream %d: processed %d nodes, removed %d", 
                        stream, len(nodes_to_process), nodes_removed)
    
    # Save if changes were made
    if needToWriteKnownNodesToDisk:
        try:
            saveKnownNodes()
        except Exception as e:
            logger.error("Failed to save knownnodes after cleanup: %s", e)
    
    logger.debug("Completed cleanupKnownNodes")


def safe_cleanup_knownnodes(pool):
    """
    Wrapper with additional safety for cleanup
    """
    try:
        cleanupKnownNodes(pool)
    except RuntimeError as e:
        if "dictionary changed size during iteration" in str(e):
            logger.warning("Cleanup interrupted by dict modification, will retry next cycle")
        else:
            logger.error("Unexpected error in cleanup: %s", e)
    except Exception as e:
        logger.error("Error in knownnodes cleanup: %s", e)
