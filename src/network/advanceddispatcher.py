"""
Improved version of asyncore dispatcher
"""
import socket
import threading
import time
import logging

import network.asyncore_pollchoose as asyncore
import state
from .threads import BusyError, nonBlocking

logger = logging.getLogger('default')

class ProcessingError(Exception):
    """General class for protocol parser exception,
    use as a base for others."""
    pass


class UnknownStateError(ProcessingError):
    """Parser points to an unknown (unimplemented) state."""
    pass


class AdvancedDispatcher(asyncore.dispatcher):
    """Improved version of asyncore dispatcher,
    with buffers and protocol state."""
    # pylint: disable=too-many-instance-attributes
    _buf_len = 131072  # 128kB

    def __init__(self, sock=None):
        logger.debug("DEBUG: AdvancedDispatcher initialization started")
        if not hasattr(self, '_map'):
            asyncore.dispatcher.__init__(self, sock)
        self.connectedAt = 0
        self.close_reason = None
        self.read_buf = bytearray()
        self.write_buf = bytearray()
        self.state = "init"
        self.lastTx = time.time()
        self.sentBytes = 0
        self.receivedBytes = 0
        self.expectBytes = 0
        self.readLock = threading.RLock()
        self.writeLock = threading.RLock()
        self.processingLock = threading.RLock()
        self.uploadChunk = self.downloadChunk = 0
        logger.debug("DEBUG: AdvancedDispatcher initialized")

    def append_write_buf(self, data):
        """Append binary data to the end of stream write buffer."""
        if data:
            logger.debug("DEBUG: Appending %d bytes to write buffer", len(data))
            if isinstance(data, list):
                with self.writeLock:
                    for chunk in data:
                        self.write_buf.extend(chunk)
                        logger.debug("DEBUG: Appended chunk of %d bytes", len(chunk))
            else:
                with self.writeLock:
                    self.write_buf.extend(data)
                    logger.debug("DEBUG: Appended %d bytes to write buffer", len(data))

    def slice_write_buf(self, length=0):
        """Cut the beginning of the stream write buffer."""
        if length > 0:
            logger.debug("DEBUG: Slicing write buffer by %d bytes", length)
            with self.writeLock:
                if length >= len(self.write_buf):
                    logger.debug("DEBUG: Clearing entire write buffer")
                    del self.write_buf[:]
                else:
                    del self.write_buf[0:length]
                    logger.debug("DEBUG: Write buffer now has %d bytes", len(self.write_buf))

    def slice_read_buf(self, length=0):
        """Cut the beginning of the stream read buffer."""
        if length > 0:
            logger.debug("DEBUG: Slicing read buffer by %d bytes", length)
            with self.readLock:
                if length >= len(self.read_buf):
                    logger.debug("DEBUG: Clearing entire read buffer")
                    del self.read_buf[:]
                else:
                    del self.read_buf[0:length]
                    logger.debug("DEBUG: Read buffer now has %d bytes", len(self.read_buf))

    def process(self):
        """Process (parse) data that's in the buffer,
        as long as there is enough data and the connection is open."""
        logger.debug("DEBUG: Starting processing")
        while self.connected and not state.shutdown:
            try:
                with nonBlocking(self.processingLock):
                    if not self.connected or state.shutdown:
                        logger.debug("DEBUG: Not connected or shutdown, breaking processing loop")
                        break
                    if len(self.read_buf) < self.expectBytes:
                        logger.debug("DEBUG: Not enough data (%d < %d), waiting", 
                                   len(self.read_buf), self.expectBytes)
                        return False
                    try:
                        logger.debug("DEBUG: Getting state handler for state %s", self.state)
                        cmd = getattr(self, "state_" + str(self.state))
                    except AttributeError:
                        logger.error('Unknown state %s', self.state, exc_info=True)
                        raise UnknownStateError(self.state)
                    logger.debug("DEBUG: Executing state handler")
                    if not cmd():
                        logger.debug("DEBUG: State handler returned False, breaking loop")
                        break
            except BusyError:
                logger.debug("DEBUG: Processing lock busy")
                return False
        logger.debug("DEBUG: Processing completed")
        return False

    def set_state(self, state_str, length=0, expectBytes=0):
        """Set the next processing state."""
        logger.debug("DEBUG: Setting new state: %s (length: %d, expectBytes: %d)", 
                    state_str, length, expectBytes)
        self.expectBytes = expectBytes
        self.slice_read_buf(length)
        self.state = state_str

    def writable(self):
        """Is data from the write buffer ready to be sent to the network?"""
        self.uploadChunk = AdvancedDispatcher._buf_len
        if asyncore.maxUploadRate > 0:
            self.uploadChunk = int(asyncore.uploadBucket)
        self.uploadChunk = min(self.uploadChunk, len(self.write_buf))
        result = asyncore.dispatcher.writable(self) and (
            self.connecting or (
                self.connected and self.uploadChunk > 0))
        logger.debug("DEBUG: writable() -> %s (chunk: %d)", result, self.uploadChunk)
        return result

    def readable(self):
        """Is the read buffer ready to accept data from the network?"""
        self.downloadChunk = AdvancedDispatcher._buf_len
        if asyncore.maxDownloadRate > 0:
            self.downloadChunk = int(asyncore.downloadBucket)
        try:
            if self.expectBytes > 0 and not self.fullyEstablished:
                self.downloadChunk = min(
                    self.downloadChunk, self.expectBytes - len(self.read_buf))
                if self.downloadChunk < 0:
                    self.downloadChunk = 0
        except AttributeError:
            pass
        result = asyncore.dispatcher.readable(self) and (
            self.connecting or self.accepting or (
                self.connected and self.downloadChunk > 0))
        logger.debug("DEBUG: readable() -> %s (chunk: %d)", result, self.downloadChunk)
        return result

    def handle_read(self):
        """Append incoming data to the read buffer."""
        logger.debug("DEBUG: Handling read event")
        self.lastTx = time.time()
        newData = self.recv(self.downloadChunk)
        logger.debug("DEBUG: Received %d bytes", len(newData))
        self.receivedBytes += len(newData)
        asyncore.update_received(len(newData))
        with self.readLock:
            self.read_buf.extend(newData)
            logger.debug("DEBUG: Read buffer now has %d bytes", len(self.read_buf))

    def handle_write(self):
        """Send outgoing data from write buffer."""
        logger.debug("DEBUG: Handling write event")
        self.lastTx = time.time()
        written = self.send(self.write_buf[0:self.uploadChunk])
        logger.debug("DEBUG: Sent %d bytes", written)
        asyncore.update_sent(written)
        self.sentBytes += written
        self.slice_write_buf(written)

    def handle_connect_event(self):
        """Callback for connection established event."""
        logger.debug("DEBUG: Handling connect event")
        try:
            asyncore.dispatcher.handle_connect_event(self)
        except socket.error as e:
            if e.args[0] not in asyncore._DISCONNECTED:
                logger.debug("DEBUG: Connection error: %s", e)
                raise
            logger.debug("DEBUG: Disconnected socket error, ignoring")

    def handle_connect(self):
        """Method for handling connection established implementations."""
        logger.debug("DEBUG: Connection established")
        self.lastTx = time.time()

    def state_close(self):  # pylint: disable=no-self-use
        """Signal to the processing loop to end."""
        logger.debug("DEBUG: Closing state")
        return False

    def handle_close(self):
        """Callback for connection being closed,
        but can also be called directly when you want connection to close."""
        logger.debug("DEBUG: Handling close event")
        with self.readLock:
            self.read_buf = bytearray()
        with self.writeLock:
            self.write_buf = bytearray()
        self.set_state("close")
        self.close()
