"""
Network statistics
"""
import time
import logging

from network import asyncore_pollchoose as asyncore
from network import connectionpool
from .objectracker import missingObjects

logger = logging.getLogger('default')

# Global variables for tracking network statistics
lastReceivedTimestamp = time.time()
lastReceivedBytes = 0
currentReceivedSpeed = 0
lastSentTimestamp = time.time()
lastSentBytes = 0
currentSentSpeed = 0

logger.debug("DEBUG: Initialized network statistics with timestamp: "
             "lastReceived=%f, lastSent=%f", lastReceivedTimestamp, lastSentTimestamp)

def connectedHostsList():
    """List of all the connected hosts"""
    connections = connectionpool.pool.establishedConnections()
    logger.debug("DEBUG: connectedHostsList returning %d connections", len(connections))
    return connections

def sentBytes():
    """Sending Bytes"""
    bytes_sent = asyncore.sentBytes
    logger.debug("DEBUG: sentBytes returning %d bytes", bytes_sent)
    return bytes_sent

def uploadSpeed():
    """Getting upload speed"""
    global lastSentTimestamp, lastSentBytes, currentSentSpeed
    currentTimestamp = time.time()
    
    logger.debug("DEBUG: uploadSpeed called - lastSentTimestamp=%f, currentTimestamp=%f", 
                lastSentTimestamp, currentTimestamp)
    
    if int(lastSentTimestamp) < int(currentTimestamp):
        currentSentBytes = asyncore.sentBytes
        time_diff = currentTimestamp - lastSentTimestamp
        byte_diff = currentSentBytes - lastSentBytes
        
        if time_diff > 0:
            currentSentSpeed = int(byte_diff / time_diff)
        else:
            currentSentSpeed = 0
            logger.debug("DEBUG: Zero time difference in uploadSpeed calculation")
        
        logger.debug("DEBUG: Upload speed calculation - bytes=%d, time=%.3fs, speed=%d B/s",
                    byte_diff, time_diff, currentSentSpeed)
        
        lastSentBytes = currentSentBytes
        lastSentTimestamp = currentTimestamp
    else:
        logger.debug("DEBUG: No time change since last upload speed calculation")
    
    logger.debug("DEBUG: Returning upload speed: %d B/s", currentSentSpeed)
    return currentSentSpeed

def receivedBytes():
    """Receiving Bytes"""
    bytes_received = asyncore.receivedBytes
    logger.debug("DEBUG: receivedBytes returning %d bytes", bytes_received)
    return bytes_received

def downloadSpeed():
    """Getting download speed"""
    global lastReceivedTimestamp, lastReceivedBytes, currentReceivedSpeed
    currentTimestamp = time.time()
    
    logger.debug("DEBUG: downloadSpeed called - lastReceivedTimestamp=%f, currentTimestamp=%f",
                lastReceivedTimestamp, currentTimestamp)
    
    if int(lastReceivedTimestamp) < int(currentTimestamp):
        currentReceivedBytes = asyncore.receivedBytes
        time_diff = currentTimestamp - lastReceivedTimestamp
        byte_diff = currentReceivedBytes - lastReceivedBytes
        
        if time_diff > 0:
            currentReceivedSpeed = int(byte_diff / time_diff)
        else:
            currentReceivedSpeed = 0
            logger.debug("DEBUG: Zero time difference in downloadSpeed calculation")
        
        logger.debug("DEBUG: Download speed calculation - bytes=%d, time=%.3fs, speed=%d B/s",
                    byte_diff, time_diff, currentReceivedSpeed)
        
        lastReceivedBytes = currentReceivedBytes
        lastReceivedTimestamp = currentTimestamp
    else:
        logger.debug("DEBUG: No time change since last download speed calculation")
    
    logger.debug("DEBUG: Returning download speed: %d B/s", currentReceivedSpeed)
    return currentReceivedSpeed

def pendingDownload():
    """Getting pending downloads"""
    pending = len(missingObjects)
    logger.debug("DEBUG: pendingDownload returning %d missing objects", pending)
    return pending

def pendingUpload():
    """Getting pending uploads"""
    # Original commented out code remains unchanged
    logger.debug("DEBUG: pendingUpload returning 0 (functionality disabled)")
    return 0
