"""
Basic infrastructure for asynchronous socket service clients and servers.
"""
# -*- Mode: Python -*-
#   Id: asyncore.py,v 2.51 2000/09/07 22:29:26 rushing Exp
#   Author: Sam Rushing <rushing@nightmare.com>
# pylint: disable=too-many-branches,too-many-lines,global-statement
# pylint: disable=redefined-builtin,no-self-use
import os
import select
import socket
import random
import sys
import time
import warnings
from errno import (
    EADDRINUSE, EAGAIN, EALREADY, EBADF, ECONNABORTED, ECONNREFUSED,
    ECONNRESET, EHOSTUNREACH, EINPROGRESS, EINTR, EINVAL, EISCONN, ENETUNREACH,
    ENOTCONN, ENOTSOCK, EPIPE, ESHUTDOWN, ETIMEDOUT, EWOULDBLOCK, errorcode
)
from threading import current_thread
from six.moves.reprlib import repr

# Debug logger setup
import logging
logger = logging.getLogger('default')

try:
    from errno import WSAEWOULDBLOCK
except (ImportError, AttributeError):
    WSAEWOULDBLOCK = EWOULDBLOCK
try:
    from errno import WSAENOTSOCK
except (ImportError, AttributeError):
    WSAENOTSOCK = ENOTSOCK
try:
    from errno import WSAECONNRESET
except (ImportError, AttributeError):
    WSAECONNRESET = ECONNRESET
try:
    # Desirable side-effects on Windows; imports winsock error numbers
    from errno import WSAEADDRINUSE  # pylint: disable=unused-import
except (ImportError, AttributeError):
    WSAEADDRINUSE = EADDRINUSE

_DISCONNECTED = frozenset((
    ECONNRESET, ENOTCONN, ESHUTDOWN, ECONNABORTED, EPIPE, EBADF, ECONNREFUSED,
    EHOSTUNREACH, ENETUNREACH, ETIMEDOUT, WSAECONNRESET))

OP_READ = 1
OP_WRITE = 2

try:
    socket_map
except NameError:
    socket_map = {}

def _strerror(err):
    try:
        return os.strerror(err)
    except (ValueError, OverflowError, NameError):
        if err in errorcode:
            return errorcode[err]
        return "Unknown error %s" % err

class ExitNow(Exception):
    """We don't use directly but may be necessary as we replace
    asyncore due to some library raising or expecting it"""
    pass

_reraised_exceptions = (ExitNow, KeyboardInterrupt, SystemExit)

maxDownloadRate = 0
downloadTimestamp = 0
downloadBucket = 0
receivedBytes = 0
maxUploadRate = 0
uploadTimestamp = 0
uploadBucket = 0
sentBytes = 0

def read(obj):
    """Event to read from the object, i.e. its network socket."""
    logger.debug("DEBUG: read() called for obj: %s", obj)
    if not can_receive():
        logger.debug("DEBUG: Download throttled, skipping read")
        return
    try:
        logger.debug("DEBUG: Calling handle_read_event for obj: %s", obj)
        obj.handle_read_event()
    except _reraised_exceptions:
        logger.debug("DEBUG: Reraising exception from read")
        raise
    except BaseException:
        logger.debug("DEBUG: Handling error in read")
        obj.handle_error()

def write(obj):
    """Event to write to the object, i.e. its network socket."""
    logger.debug("DEBUG: write() called for obj: %s", obj)
    if not can_send():
        logger.debug("DEBUG: Upload throttled, skipping write")
        return
    try:
        logger.debug("DEBUG: Calling handle_write_event for obj: %s", obj)
        obj.handle_write_event()
    except _reraised_exceptions:
        logger.debug("DEBUG: Reraising exception from write")
        raise
    except BaseException:
        logger.debug("DEBUG: Handling error in write")
        obj.handle_error()

def set_rates(download, upload):
    """Set throttling rates"""
    global maxDownloadRate, maxUploadRate, downloadBucket
    global uploadBucket, downloadTimestamp, uploadTimestamp

    logger.debug("DEBUG: Setting rates - download: %s KB/s, upload: %s KB/s", download, upload)
    maxDownloadRate = float(download) * 1024
    maxUploadRate = float(upload) * 1024
    downloadBucket = maxDownloadRate
    uploadBucket = maxUploadRate
    downloadTimestamp = time.time()
    uploadTimestamp = time.time()
    logger.debug("DEBUG: New rates set - download: %s B/s, upload: %s B/s", 
                maxDownloadRate, maxUploadRate)

def can_receive():
    """Predicate indicating whether the download throttle is in effect"""
    result = maxDownloadRate == 0 or downloadBucket > 0
    logger.debug("DEBUG: can_receive() -> %s (bucket: %s)", result, downloadBucket)
    return result

def can_send():
    """Predicate indicating whether the upload throttle is in effect"""
    result = maxUploadRate == 0 or uploadBucket > 0
    logger.debug("DEBUG: can_send() -> %s (bucket: %s)", result, uploadBucket)
    return result

def update_received(download=0):
    """Update the receiving throttle"""
    global receivedBytes, downloadBucket, downloadTimestamp

    logger.debug("DEBUG: update_received(%s)", download)
    currentTimestamp = time.time()
    receivedBytes += download
    if maxDownloadRate > 0:
        bucketIncrease = maxDownloadRate * (currentTimestamp - downloadTimestamp)
        downloadBucket += bucketIncrease
        if downloadBucket > maxDownloadRate:
            downloadBucket = int(maxDownloadRate)
        downloadBucket -= download
    downloadTimestamp = currentTimestamp
    logger.debug("DEBUG: Updated download bucket: %s", downloadBucket)

def update_sent(upload=0):
    """Update the sending throttle"""
    global sentBytes, uploadBucket, uploadTimestamp

    logger.debug("DEBUG: update_sent(%s)", upload)
    currentTimestamp = time.time()
    sentBytes += upload
    if maxUploadRate > 0:
        bucketIncrease = maxUploadRate * (currentTimestamp - uploadTimestamp)
        uploadBucket += bucketIncrease
        if uploadBucket > maxUploadRate:
            uploadBucket = int(maxUploadRate)
        uploadBucket -= upload
    uploadTimestamp = currentTimestamp
    logger.debug("DEBUG: Updated upload bucket: %s", uploadBucket)

def _exception(obj):
    """Handle exceptions as appropriate"""
    logger.debug("DEBUG: Handling exception for obj: %s", obj)
    try:
        obj.handle_expt_event()
    except _reraised_exceptions:
        logger.debug("DEBUG: Reraising exception from _exception")
        raise
    except BaseException:
        logger.debug("DEBUG: Handling error in _exception")
        obj.handle_error()

def readwrite(obj, flags):
    """Read and write any pending data to/from the object"""
    logger.debug("DEBUG: readwrite() called for obj: %s, flags: %s", obj, flags)
    try:
        if flags & select.POLLIN and can_receive():
            logger.debug("DEBUG: Handling POLLIN event")
            obj.handle_read_event()
        if flags & select.POLLOUT and can_send():
            logger.debug("DEBUG: Handling POLLOUT event")
            obj.handle_write_event()
        if flags & select.POLLPRI:
            logger.debug("DEBUG: Handling POLLPRI event")
            obj.handle_expt_event()
        if flags & (select.POLLHUP | select.POLLERR | select.POLLNVAL):
            logger.debug("DEBUG: Handling disconnect event (flags: %s)", flags)
            obj.handle_close()
    except socket.error as e:
        if e.args[0] not in _DISCONNECTED:
            logger.debug("DEBUG: Handling socket error: %s", e)
            obj.handle_error()
        else:
            logger.debug("DEBUG: Handling disconnected socket")
            obj.handle_close()
    except _reraised_exceptions:
        logger.debug("DEBUG: Reraising exception from readwrite")
        raise
    except BaseException:
        logger.debug("DEBUG: Handling error in readwrite")
        obj.handle_error()

def select_poller(timeout=0.0, map=None):
    """A poller which uses select(), available on most platforms."""
    logger.debug("DEBUG: select_poller(timeout=%s)", timeout)
    if map is None:
        map = socket_map
    if map:
        r = []
        w = []
        e = []
        for fd, obj in list(map.items()):
            is_r = obj.readable()
            is_w = obj.writable()
            logger.debug("DEBUG: Checking fd %s - readable: %s, writable: %s", fd, is_r, is_w)
            if is_r:
                r.append(fd)
            if is_w and not obj.accepting:
                w.append(fd)
            if is_r or is_w:
                e.append(fd)
        if [] == r == w == e:
            logger.debug("DEBUG: No sockets ready, sleeping for %s", timeout)
            time.sleep(timeout)
            return

        try:
            logger.debug("DEBUG: Calling select() with r=%s, w=%s, e=%s", len(r), len(w), len(e))
            r, w, e = select.select(r, w, e, timeout)
        except KeyboardInterrupt:
            logger.debug("DEBUG: KeyboardInterrupt in select_poller")
            return
        except socket.error as err:
            if err.args[0] in (EBADF, EINTR):
                logger.debug("DEBUG: select() error: %s", err)
                return
        except Exception as err:
            if err.args[0] in (WSAENOTSOCK, ):
                logger.debug("DEBUG: select() error: %s", err)
                return

        logger.debug("DEBUG: Processing %d read events", len(r))
        for fd in random.sample(r, len(r)):
            obj = map.get(fd)
            if obj is None:
                continue
            logger.debug("DEBUG: Calling read() for fd %s", fd)
            read(obj)

        logger.debug("DEBUG: Processing %d write events", len(w))
        for fd in random.sample(w, len(w)):
            obj = map.get(fd)
            if obj is None:
                continue
            logger.debug("DEBUG: Calling write() for fd %s", fd)
            write(obj)

        logger.debug("DEBUG: Processing %d exception events", len(e))
        for fd in e:
            obj = map.get(fd)
            if obj is None:
                continue
            logger.debug("DEBUG: Calling _exception() for fd %s", fd)
            _exception(obj)
    else:
        logger.debug("DEBUG: No sockets in map, waiting for %s", timeout)
        current_thread().stop.wait(timeout)

def poll_poller(timeout=0.0, map=None):
    """A poller which uses poll(), available on most UNIXen."""
    logger.debug("DEBUG: poll_poller(timeout=%s)", timeout)
    if map is None:
        map = socket_map
    if timeout is not None:
        # timeout is in milliseconds
        timeout = int(timeout * 1000)
    try:
        poll_poller.pollster
    except AttributeError:
        logger.debug("DEBUG: Creating new pollster instance")
        poll_poller.pollster = select.poll()
    if map:
        for fd, obj in list(map.items()):
            flags = newflags = 0
            if obj.readable():
                flags |= select.POLLIN | select.POLLPRI
                newflags |= OP_READ
            else:
                newflags &= ~ OP_READ
            if obj.writable() and not obj.accepting:
                flags |= select.POLLOUT
                newflags |= OP_WRITE
            else:
                newflags &= ~ OP_WRITE
            logger.debug("DEBUG: fd %s flags: %s, newflags: %s", fd, flags, newflags)
            if newflags != obj.poller_flags:
                obj.poller_flags = newflags
                try:
                    if obj.poller_registered:
                        logger.debug("DEBUG: Modifying fd %s in pollster", fd)
                        poll_poller.pollster.modify(fd, flags)
                    else:
                        logger.debug("DEBUG: Registering fd %s in pollster", fd)
                        poll_poller.pollster.register(fd, flags)
                        obj.poller_registered = True
                except IOError:
                    logger.debug("DEBUG: IOError modifying/registering fd %s", fd)
                    pass
        try:
            logger.debug("DEBUG: Calling poll() with timeout %s", timeout)
            r = poll_poller.pollster.poll(timeout)
        except KeyboardInterrupt:
            logger.debug("DEBUG: KeyboardInterrupt in poll_poller")
            r = []
        except socket.error as err:
            if err.args[0] in (EBADF, WSAENOTSOCK, EINTR):
                logger.debug("DEBUG: poll() error: %s", err)
                return
        logger.debug("DEBUG: Processing %d poll events", len(r))
        for fd, flags in random.sample(r, len(r)):
            obj = map.get(fd)
            if obj is None:
                continue
            logger.debug("DEBUG: Calling readwrite() for fd %s, flags %s", fd, flags)
            readwrite(obj, flags)
    else:
        logger.debug("DEBUG: No sockets in map, waiting for %s", timeout)
        current_thread().stop.wait(timeout)

# Aliases for backward compatibility
poll = select_poller
poll2 = poll3 = poll_poller

def epoll_poller(timeout=0.0, map=None):
    """A poller which uses epoll(), supported on Linux 2.5.44 and newer."""
    logger.debug("DEBUG: epoll_poller(timeout=%s)", timeout)
    if map is None:
        map = socket_map
    try:
        epoll_poller.pollster
    except AttributeError:
        logger.debug("DEBUG: Creating new epoll instance")
        epoll_poller.pollster = select.epoll()
    if map:
        for fd, obj in map.items():
            flags = newflags = 0
            if obj.readable():
                flags |= select.POLLIN | select.POLLPRI
                newflags |= OP_READ
            else:
                newflags &= ~ OP_READ
            if obj.writable() and not obj.accepting:
                flags |= select.POLLOUT
                newflags |= OP_WRITE
            else:
                newflags &= ~ OP_WRITE
            logger.debug("DEBUG: fd %s flags: %s, newflags: %s", fd, flags, newflags)
            if newflags != obj.poller_flags:
                obj.poller_flags = newflags
                flags |= select.POLLERR | select.POLLHUP | select.POLLNVAL
                try:
                    if obj.poller_registered:
                        logger.debug("DEBUG: Modifying fd %s in epoll", fd)
                        epoll_poller.pollster.modify(fd, flags)
                    else:
                        logger.debug("DEBUG: Registering fd %s in epoll", fd)
                        epoll_poller.pollster.register(fd, flags)
                        obj.poller_registered = True
                except IOError:
                    logger.debug("DEBUG: IOError modifying/registering fd %s", fd)
                    pass
        try:
            logger.debug("DEBUG: Calling epoll() with timeout %s", timeout)
            r = epoll_poller.pollster.poll(timeout)
        except IOError as e:
            if e.errno != EINTR:
                logger.debug("DEBUG: epoll() error: %s", e)
                raise
            r = []
        except select.error as err:
            if err.args[0] != EINTR:
                logger.debug("DEBUG: epoll() error: %s", err)
                raise
            r = []
        logger.debug("DEBUG: Processing %d epoll events", len(r))
        for fd, flags in random.sample(r, len(r)):
            obj = map.get(fd)
            if obj is None:
                continue
            logger.debug("DEBUG: Calling readwrite() for fd %s, flags %s", fd, flags)
            readwrite(obj, flags)
    else:
        logger.debug("DEBUG: No sockets in map, waiting for %s", timeout)
        current_thread().stop.wait(timeout)

def kqueue_poller(timeout=0.0, map=None):
    """A poller which uses kqueue(), BSD specific."""
    logger.debug("DEBUG: kqueue_poller(timeout=%s)", timeout)
    if map is None:
        map = socket_map
    try:
        kqueue_poller.pollster
    except AttributeError:
        logger.debug("DEBUG: Creating new kqueue instance")
        kqueue_poller.pollster = select.kqueue()
    if map:
        updates = []
        selectables = 0
        for fd, obj in map.items():
            kq_filter = 0
            if obj.readable():
                kq_filter |= 1
                selectables += 1
            if obj.writable() and not obj.accepting:
                kq_filter |= 2
                selectables += 1
            logger.debug("DEBUG: fd %s kq_filter: %s", fd, kq_filter)
            if kq_filter != obj.poller_filter:
                if kq_filter & 1 != obj.poller_filter & 1:
                    poller_flags = select.KQ_EV_ADD
                    if kq_filter & 1:
                        poller_flags |= select.KQ_EV_ENABLE
                    else:
                        poller_flags |= select.KQ_EV_DISABLE
                    logger.debug("DEBUG: Adding read event for fd %s", fd)
                    updates.append(
                        select.kevent(
                            fd, filter=select.KQ_FILTER_READ,
                            flags=poller_flags))
                if kq_filter & 2 != obj.poller_filter & 2:
                    poller_flags = select.KQ_EV_ADD
                    if kq_filter & 2:
                        poller_flags |= select.KQ_EV_ENABLE
                    else:
                        poller_flags |= select.KQ_EV_DISABLE
                    logger.debug("DEBUG: Adding write event for fd %s", fd)
                    updates.append(
                        select.kevent(
                            fd, filter=select.KQ_FILTER_WRITE,
                            flags=poller_flags))
                obj.poller_filter = kq_filter

        if not selectables:
            logger.debug("DEBUG: No selectable sockets, waiting for %s", timeout)
            current_thread().stop.wait(timeout)
            return

        logger.debug("DEBUG: Calling kqueue.control() with %d updates", len(updates))
        events = kqueue_poller.pollster.control(updates, selectables, timeout)
        logger.debug("DEBUG: Processing %d kqueue events", len(events))
        if len(events) > 1:
            events = random.sample(events, len(events))

        for event in events:
            fd = event.ident
            obj = map.get(fd)
            if obj is None:
                continue
            if event.flags & select.KQ_EV_ERROR:
                logger.debug("DEBUG: Handling error event for fd %s", fd)
                _exception(obj)
                continue
            if event.flags & select.KQ_EV_EOF and event.data and event.fflags:
                logger.debug("DEBUG: Handling close event for fd %s", fd)
                obj.handle_close()
                continue
            if event.filter == select.KQ_FILTER_READ:
                logger.debug("DEBUG: Handling read event for fd %s", fd)
                read(obj)
            if event.filter == select.KQ_FILTER_WRITE:
                logger.debug("DEBUG: Handling write event for fd %s", fd)
                write(obj)
    else:
        logger.debug("DEBUG: No sockets in map, waiting for %s", timeout)
        current_thread().stop.wait(timeout)

def loop(timeout=30.0, use_poll=False, map=None, count=None, poller=None):
    """Poll in a loop, until count or timeout is reached"""
    logger.debug("DEBUG: loop(timeout=%s, use_poll=%s, count=%s, poller=%s)", 
                timeout, use_poll, count, poller)
    if map is None:
        map = socket_map
    if count is None:
        count = True

    if poller is None:
        if use_poll:
            poller = poll_poller
            logger.debug("DEBUG: Using poll_poller")
        elif hasattr(select, 'epoll'):
            poller = epoll_poller
            logger.debug("DEBUG: Using epoll_poller")
        elif hasattr(select, 'kqueue'):
            poller = kqueue_poller
            logger.debug("DEBUG: Using kqueue_poller")
        elif hasattr(select, 'poll'):
            poller = poll_poller
            logger.debug("DEBUG: Using poll_poller")
        elif hasattr(select, 'select'):
            poller = select_poller
            logger.debug("DEBUG: Using select_poller")

    if timeout == 0:
        deadline = 0
    else:
        deadline = time.time() + timeout
    while count:
        logger.debug("DEBUG: Loop iteration (count: %s)", count)
        # fill buckets first
        update_sent()
        update_received()
        subtimeout = deadline - time.time()
        if subtimeout <= 0:
            logger.debug("DEBUG: Deadline reached, breaking loop")
            break
        logger.debug("DEBUG: Calling poller with timeout %s", subtimeout)
        poller(subtimeout, map)
        if isinstance(count, int):
            count = count - 1

class dispatcher(object):
    """Dispatcher for socket objects"""
    debug = False
    connected = False
    accepting = False
    connecting = False
    closing = False
    addr = None
    ignore_log_types = frozenset(['warning'])
    poller_registered = False
    poller_flags = 0
    # don't do network IO with a smaller bucket than this
    minTx = 1500

    def __init__(self, sock=None, map=None):
        logger.debug("DEBUG: dispatcher.__init__(sock=%s)", sock)
        if map is None:
            self._map = socket_map
        else:
            self._map = map

        self._fileno = None

        if sock:
            sock.setblocking(0)
            self.set_socket(sock, map)
            self.connected = True
            try:
                self.addr = sock.getpeername()
                logger.debug("DEBUG: Got peername: %s", self.addr)
            except socket.error as err:
                if err.args[0] in (ENOTCONN, EINVAL):
                    self.connected = False
                    logger.debug("DEBUG: Socket not connected")
                else:
                    self.del_channel(map)
                    logger.debug("DEBUG: Socket error: %s", err)
                    raise
        else:
            self.socket = None
            logger.debug("DEBUG: No socket provided")

    def __repr__(self):
        status = [self.__class__.__module__ + "." + self.__class__.__name__]
        if self.accepting and self.addr:
            status.append('listening')
        elif self.connected:
            status.append('connected')
        if self.addr is not None:
            try:
                status.append('%s:%d' % self.addr)
            except TypeError:
                status.append(repr(self.addr))
        return '<%s at %#x>' % (' '.join(status), id(self))

    __str__ = __repr__

    def add_channel(self, map=None):
        """Add a channel"""
        logger.debug("DEBUG: add_channel() for %s", self)
        if map is None:
            map = self._map
        map[self._fileno] = self
        self.poller_flags = 0
        self.poller_filter = 0
        logger.debug("DEBUG: Added channel with fd %s", self._fileno)

    def del_channel(self, map=None):
        """Delete a channel"""
        logger.debug("DEBUG: del_channel() for %s", self)
        fd = self._fileno
        if map is None:
            map = self._map
        if fd in map:
            del map[fd]
            logger.debug("DEBUG: Removed fd %s from map", fd)
        if self._fileno:
            try:
                kqueue_poller.pollster.control([select.kevent(
                    fd, select.KQ_FILTER_READ, select.KQ_EV_DELETE)], 0)
                logger.debug("DEBUG: Removed read filter for fd %s from kqueue", fd)
            except(AttributeError, KeyError, TypeError, IOError, OSError):
                pass
            try:
                kqueue_poller.pollster.control([select.kevent(
                    fd, select.KQ_FILTER_WRITE, select.KQ_EV_DELETE)], 0)
                logger.debug("DEBUG: Removed write filter for fd %s from kqueue", fd)
            except(AttributeError, KeyError, TypeError, IOError, OSError):
                pass
            try:
                epoll_poller.pollster.unregister(fd)
                logger.debug("DEBUG: Unregistered fd %s from epoll", fd)
            except (AttributeError, KeyError, TypeError, IOError):
                pass
            try:
                poll_poller.pollster.unregister(fd)
                logger.debug("DEBUG: Unregistered fd %s from poll", fd)
            except (AttributeError, KeyError, TypeError, IOError):
                pass
        self._fileno = None
        self.poller_flags = 0
        self.poller_filter = 0
        self.poller_registered = False

    def create_socket(self, family=socket.AF_INET, socket_type=socket.SOCK_STREAM):
        """Create a socket"""
        logger.debug("DEBUG: create_socket(family=%s, type=%s)", family, socket_type)
        self.family_and_type = family, socket_type
        sock = socket.socket(family, socket_type)
        sock.setblocking(0)
        self.set_socket(sock)

    def set_socket(self, sock, map=None):
        """Set socket"""
        logger.debug("DEBUG: set_socket() for %s", self)
        self.socket = sock
        self._fileno = sock.fileno()
        self.add_channel(map)

    def set_reuse_addr(self):
        """try to re-use a server port if possible"""
        logger.debug("DEBUG: set_reuse_addr() for %s", self)
        try:
            self.socket.setsockopt(
                socket.SOL_SOCKET, socket.SO_REUSEADDR, self.socket.getsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR) | 1
            )
        except socket.error:
            logger.debug("DEBUG: Failed to set SO_REUSEADDR")
            pass

    def readable(self):
        """Predicate to indicate download throttle status"""
        result = maxDownloadRate == 0 or downloadBucket > dispatcher.minTx
        logger.debug("DEBUG: readable() -> %s (bucket: %s)", result, downloadBucket)
        return result

    def writable(self):
        """Predicate to indicate upload throttle status"""
        result = maxUploadRate == 0 or uploadBucket > dispatcher.minTx
        logger.debug("DEBUG: writable() -> %s (bucket: %s)", result, uploadBucket)
        return result

    def listen(self, num):
        """Listen on a port"""
        logger.debug("DEBUG: listen(%d) for %s", num, self)
        self.accepting = True
        if os.name == 'nt' and num > 5:
            num = 5
        return self.socket.listen(num)

    def bind(self, addr):
        """Bind to an address"""
        logger.debug("DEBUG: bind(%s) for %s", addr, self)
        self.addr = addr
        return self.socket.bind(addr)

    def connect(self, address):
        """Connect to an address"""
        logger.debug("DEBUG: connect(%s) for %s", address, self)
        self.connected = False
        self.connecting = True
        err = self.socket.connect_ex(address)
        logger.debug("DEBUG: connect_ex returned %d", err)
        if err in (EINPROGRESS, EALREADY, EWOULDBLOCK, WSAEWOULDBLOCK) \
                or err == EINVAL and os.name in ('nt', 'ce'):
            self.addr = address
            return
        if err in (0, EISCONN):
            self.addr = address
            self.handle_connect_event()
        else:
            raise socket.error(err, errorcode[err])

    def accept(self):
        """Accept incoming connections."""
        logger.debug("DEBUG: accept() for %s", self)
        try:
            conn, addr = self.socket.accept()
            logger.debug("DEBUG: Accepted connection from %s", addr)
            return conn, addr
        except TypeError:
            logger.debug("DEBUG: accept() returned None")
            return None
        except socket.error as why:
            if why.args[0] in (EWOULDBLOCK, WSAEWOULDBLOCK, ECONNABORTED, EAGAIN, ENOTCONN):
                logger.debug("DEBUG: accept() would block")
                return None
            else:
                logger.debug("DEBUG: accept() error: %s", why)
                raise

    def send(self, data):
        """Send data"""
        logger.debug("DEBUG: send(%d bytes) for %s", len(data), self)
        try:
            result = self.socket.send(data)
            logger.debug("DEBUG: sent %d bytes", result)
            return result
        except socket.error as why:
            if why.args[0] in (EAGAIN, EWOULDBLOCK, WSAEWOULDBLOCK):
                logger.debug("DEBUG: send() would block")
                return 0
            elif why.args[0] in _DISCONNECTED:
                logger.debug("DEBUG: send() on disconnected socket")
                self.handle_close()
                return 0
            else:
                logger.debug("DEBUG: send() error: %s", why)
                raise

    def recv(self, buffer_size):
        """Receive data"""
        logger.debug("DEBUG: recv(%d) for %s", buffer_size, self)
        try:
            data = self.socket.recv(buffer_size)
            if not data:
                logger.debug("DEBUG: recv() returned empty, connection closed")
                self.handle_close()
                return b''
            logger.debug("DEBUG: recv() returned %d bytes", len(data))
            return data
        except socket.error as why:
            if why.args[0] in (EAGAIN, EWOULDBLOCK, WSAEWOULDBLOCK):
                logger.debug("DEBUG: recv() would block")
                return b''
            if why.args[0] in _DISCONNECTED:
                logger.debug("DEBUG: recv() on disconnected socket")
                self.handle_close()
                return b''
            else:
                logger.debug("DEBUG: recv() error: %s", why)
                raise

    def close(self):
        """Close connection"""
        logger.debug("DEBUG: close() for %s", self)
        self.connected = False
        self.accepting = False
        self.connecting = False
        self.del_channel()
        try:
            self.socket.close()
            logger.debug("DEBUG: Socket closed")
        except socket.error as why:
            if why.args[0] not in (ENOTCONN, EBADF):
                logger.debug("DEBUG: close() error: %s", why)
                raise

    def log(self, message):
        """Log a message to stderr"""
        sys.stderr.write('log: %s\n' % str(message))

    def log_info(self, message, log_type='info'):
        """Conditionally print a message"""
        if log_type not in self.ignore_log_types:
            print('%s: %s' % (log_type, message))

    def handle_read_event(self):
        """Handle a read event"""
        logger.debug("DEBUG: handle_read_event() for %s", self)
        if self.accepting:
            logger.debug("DEBUG: Handling accept event")
            self.handle_accept()
        elif not self.connected:
            if self.connecting:
                logger.debug("DEBUG: Handling connect event")
                self.handle_connect_event()
            self.handle_read()
        else:
            self.handle_read()

    def handle_connect_event(self):
        """Handle a connection event"""
        logger.debug("DEBUG: handle_connect_event() for %s", self)
        err = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err != 0:
            logger.debug("DEBUG: Connection error: %d", err)
            raise socket.error(err, _strerror(err))
        self.handle_connect()
        self.connected = True
        self.connecting = False
        logger.debug("DEBUG: Connection established")

    def handle_write_event(self):
        """Handle a write event"""
        logger.debug("DEBUG: handle_write_event() for %s", self)
        if self.accepting:
            logger.debug("DEBUG: Ignoring write event for accepting socket")
            return

        if not self.connected:
            if self.connecting:
                logger.debug("DEBUG: Handling connect event from write")
                self.handle_connect_event()
        self.handle_write()

    def handle_expt_event(self):
        """Handle expected exceptions"""
        logger.debug("DEBUG: handle_expt_event() for %s", self)
        err = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err != 0:
            logger.debug("DEBUG: Socket error: %d", err)
            self.handle_close()
        elif sys.platform.startswith("win"):
            logger.debug("DEBUG: Async connect failed on Windows")
            self.handle_close()
        else:
            self.handle_expt()

    def handle_error(self):
        """Handle unexpected exceptions"""
        logger.debug("DEBUG: handle_error() for %s", self)
        _, t, v, tbinfo = compact_traceback()

        try:
            self_repr = repr(self)
        except BaseException:
            self_repr = '<__repr__(self) failed for object at %0x>' % id(self)

        self.log_info(
            'uncaptured python exception, closing channel %s (%s:%s %s)' % (
                self_repr, t, v, tbinfo),
            'error')
        self.handle_close()

    def handle_accept(self):
        """Handle an accept event"""
        logger.debug("DEBUG: handle_accept() for %s", self)
        pair = self.accept()
        if pair is not None:
            self.handle_accepted(*pair)

    def handle_expt(self):
        """Log that the subclass does not implement handle_expt"""
        self.log_info('unhandled incoming priority event', 'warning')

    def handle_read(self):
        """Log that the subclass does not implement handle_read"""
        self.log_info('unhandled read event', 'warning')

    def handle_write(self):
        """Log that the subclass does not implement handle_write"""
        self.log_info('unhandled write event', 'warning')

    def handle_connect(self):
        """Log that the subclass does not implement handle_connect"""
        self.log_info('unhandled connect event', 'warning')

    def handle_accepted(self, sock, addr):
        """Log that the subclass does not implement handle_accepted"""
        logger.debug("DEBUG: handle_accepted() for %s", addr)
        sock.close()
        self.log_info('unhandled accepted event on %s' % (addr), 'warning')

    def handle_close(self):
        """Log that the subclass does not implement handle_close"""
        logger.debug("DEBUG: handle_close() for %s", self)
        self.log_info('unhandled close event', 'warning')
        self.close()

class dispatcher_with_send(dispatcher):
    """Adds simple buffered output capability"""

    def __init__(self, sock=None, map=None):
        dispatcher.__init__(self, sock, map)
        self.out_buffer = b''
        logger.debug("DEBUG: dispatcher_with_send initialized")

    def initiate_send(self):
        """Initiate a send"""
        logger.debug("DEBUG: initiate_send() with %d bytes in buffer", len(self.out_buffer))
        num_sent = dispatcher.send(self, self.out_buffer[:512])
        self.out_buffer = self.out_buffer[num_sent:]
        logger.debug("DEBUG: Sent %d bytes, %d remaining", num_sent, len(self.out_buffer))

    def handle_write(self):
        """Handle a write event"""
        logger.debug("DEBUG: handle_write() for %s", self)
        self.initiate_send()

    def writable(self):
        """Predicate to indicate if the object is writable"""
        result = not self.connected or len(self.out_buffer)
        logger.debug("DEBUG: writable() -> %s", result)
        return result

    def send(self, data):
        """Send data"""
        if self.debug:
            self.log_info('sending %s' % repr(data))
        logger.debug("DEBUG: send() adding %d bytes to buffer", len(data))
        self.out_buffer = self.out_buffer + data
        self.initiate_send()

def compact_traceback():
    """Return a compact traceback"""
    t, v, tb = sys.exc_info()
    tbinfo = []
    if not tb:
        raise AssertionError("traceback does not exist")
    while tb:
        tbinfo.append((
            tb.tb_frame.f_code.co_filename,
            tb.tb_frame.f_code.co_name,
            str(tb.tb_lineno)
        ))
        tb = tb.tb_next

    del tb

    filename, function, line = tbinfo[-1]
    info = ' '.join(['[%s|%s|%s]' % x for x in tbinfo])
    return (filename, function, line), t, v, info

def close_all(map=None, ignore_all=False):
    """Close all connections"""
    logger.debug("DEBUG: close_all(ignore_all=%s)", ignore_all)
    if map is None:
        map = socket_map
    for x in list(map.values()):
        try:
            logger.debug("DEBUG: Closing %s", x)
            x.close()
        except OSError as e:
            if e.args[0] == EBADF:
                pass
            elif not ignore_all:
                raise
        except _reraised_exceptions:
            raise
        except BaseException:
            if not ignore_all:
                raise
    map.clear()
    logger.debug("DEBUG: All connections closed")

if os.name == 'posix':
    import fcntl

    class file_wrapper:
        """Wrapper to make a file look like a socket"""

        def __init__(self, fd):
            logger.debug("DEBUG: file_wrapper.__init__(fd=%s)", fd)
            self.fd = os.dup(fd)

        def recv(self, *args):
            """Fake recv()"""
            logger.debug("DEBUG: file_wrapper.recv()")
            return os.read(self.fd, *args)

        def send(self, *args):
            """Fake send()"""
            logger.debug("DEBUG: file_wrapper.send()")
            return os.write(self.fd, *args)

        def getsockopt(self, level, optname, buflen=None):
            """Fake getsockopt()"""
            logger.debug("DEBUG: file_wrapper.getsockopt()")
            if (level == socket.SOL_SOCKET and optname == socket.SO_ERROR
                    and not buflen):
                return 0
            raise NotImplementedError(
                "Only asyncore specific behaviour implemented.")

        read = recv
        write = send

        def close(self):
            """Fake close()"""
            logger.debug("DEBUG: file_wrapper.close()")
            os.close(self.fd)

        def fileno(self):
            """Fake fileno()"""
            return self.fd

    class file_dispatcher(dispatcher):
        """A dispatcher for file_wrapper objects"""

        def __init__(self, fd, map=None):
            logger.debug("DEBUG: file_dispatcher.__init__(fd=%s)", fd)
            dispatcher.__init__(self, None, map)
            self.connected = True
            try:
                fd = fd.fileno()
            except AttributeError:
                pass
            self.set_file(fd)
            flags = fcntl.fcntl(fd, fcntl.F_GETFL, 0)
            flags = flags | os.O_NONBLOCK
            fcntl.fcntl(fd, fcntl.F_SETFL, flags)
            logger.debug("DEBUG: Set file to non-blocking mode")

        def set_file(self, fd):
            """Set file"""
            logger.debug("DEBUG: file_dispatcher.set_file(fd=%s)", fd)
            self.socket = file_wrapper(fd)
            self._fileno = self.socket.fileno()
            self.add_channel()
