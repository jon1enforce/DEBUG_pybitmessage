"""
Network subsystem package
"""
import logging
from six.moves import queue
from .dandelion import Dandelion
from .threads import StoppableThread
from .multiqueue import MultiQueue

# Initialize logger
logger = logging.getLogger('default')

logger.debug("DEBUG: Initializing network subsystem package")

dandelion_ins = Dandelion()
logger.debug("DEBUG: Dandelion instance created")

# network queues
invQueue = MultiQueue()
addrQueue = MultiQueue()
portCheckerQueue = queue.Queue()
receiveDataQueue = queue.Queue()
logger.debug("DEBUG: Network queues initialized - invQueue, addrQueue, portCheckerQueue, receiveDataQueue")

__all__ = ["StoppableThread"]
logger.debug("DEBUG: __all__ set to ['StoppableThread']")


def start(config, state):
    """Start network threads"""
    logger.debug("DEBUG: Starting network subsystem with config: %s", config)
    
    from .announcethread import AnnounceThread
    from network import connectionpool
    from .addrthread import AddrThread
    from .downloadthread import DownloadThread
    from .invthread import InvThread
    from .networkthread import BMNetworkThread
    from .knownnodes import readKnownNodes
    from .receivequeuethread import ReceiveQueueThread
    from .uploadthread import UploadThread

    logger.debug("DEBUG: All required modules imported")

    # check and set dandelion enabled value at network startup
    dandelion_ins.init_dandelion_enabled(config)
    logger.debug("DEBUG: Dandelion initialized with enabled=%s", dandelion_ins.enabled)
    
    # pass pool instance into dandelion class instance
    dandelion_ins.init_pool(connectionpool.pool)
    logger.debug("DEBUG: Connection pool initialized for dandelion")

    logger.debug("DEBUG: Reading known nodes")
    readKnownNodes()
    
    logger.debug("DEBUG: Connecting to stream 1")
    connectionpool.pool.connectToStream(1)
    
    # Core threads
    core_threads = [
        BMNetworkThread(), 
        InvThread(), 
        AddrThread(),
        DownloadThread(), 
        UploadThread()
    ]
    
    logger.debug("DEBUG: Starting core network threads")
    for thread in core_threads:
        thread.daemon = True
        thread.start()
        logger.debug("DEBUG: Started thread %s", thread.name)

    # Optional components
    receive_thread_count = config.getint('threads', 'receive')
    logger.debug("DEBUG: Starting %d ReceiveQueueThread(s)", receive_thread_count)
    for i in range(receive_thread_count):
        thread = ReceiveQueueThread(i)
        thread.daemon = True
        thread.start()
        logger.debug("DEBUG: Started ReceiveQueueThread %d", i)

    if config.safeGetBoolean('bitmessagesettings', 'udp'):
        logger.debug("DEBUG: UDP enabled, starting AnnounceThread")
        state.announceThread = AnnounceThread()
        state.announceThread.daemon = True
        state.announceThread.start()
        logger.debug("DEBUG: AnnounceThread started")
    else:
        logger.debug("DEBUG: UDP disabled, skipping AnnounceThread")

    logger.debug("DEBUG: Network subsystem startup completed")
