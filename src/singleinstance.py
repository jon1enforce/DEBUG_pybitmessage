"""
Single instance implementation with enhanced debugging
Based upon the singleton class from `tendo`
"""

import atexit
import os
import sys
import logging
import traceback

# Setup debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='DEBUG: %(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

logger.debug("Initializing singleinstance module")

import state
logger.debug("Imported state module")

try:
    import fcntl  # @UnresolvedImport
    logger.debug("fcntl module available")
except ImportError:
    logger.debug("fcntl module not available (non-Unix system?)")
    pass

class singleinstance(object):
    """
    Single instance application lock with detailed debugging
    """
    def __init__(self, flavor_id="", daemon=False):
        logger.debug("Initializing singleinstance: flavor_id='%s', daemon=%s", 
                   flavor_id, daemon)
        self.initialized = False
        self.counter = 0
        self.daemon = daemon
        self.lockPid = None
        
        self.lockfile = os.path.normpath(
            os.path.join(state.appdata, 'singleton%s.lock' % flavor_id))
        logger.debug("Lock file path: %s", self.lockfile)

        if state.enableGUI and not self.daemon and not state.curses:
            logger.debug("GUI enabled - initializing Qt focus handling")
            try:
                import bitmessageqt
                bitmessageqt.init()
                logger.debug("Qt initialization completed")
            except Exception as e:
                logger.error("Qt initialization failed: %s", traceback.format_exc())
                raise

        logger.debug("Attempting to acquire lock")
        self.lock()
        logger.debug("Lock acquired successfully")

        self.initialized = True
        atexit.register(self.cleanup)
        logger.debug("Registered cleanup handler")

    def lock(self):
        """Obtain single instance lock with detailed logging"""
        logger.debug("lock() called")
        
        if self.lockPid is None:
            self.lockPid = os.getpid()
            logger.debug("Set lockPid to current PID: %s", self.lockPid)
        
        if sys.platform == 'win32':
            logger.debug("Windows platform detected")
            try:
                if os.path.exists(self.lockfile):
                    logger.debug("Lock file exists - attempting removal")
                    os.unlink(self.lockfile)
                
                logger.debug("Creating new lock file")
                self.fd = os.open(
                    self.lockfile,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_TRUNC
                )
                logger.debug("Lock file created successfully")
                
                pidLine = "%i\n" % self.lockPid
                os.write(self.fd, pidLine)
                logger.debug("Wrote PID %s to lock file", self.lockPid)
                
            except OSError as e:
                if e.errno == 13:
                    logger.error("Another instance is already running")
                    sys.exit('Another instance of this application is already running')
                logger.error("Lock acquisition failed: %s", traceback.format_exc())
                raise
        else:  # non Windows
            logger.debug("Unix-like platform detected")
            self.fp = open(self.lockfile, 'a+')
            logger.debug("Opened lock file in append mode")
            
            try:
                if self.daemon and self.lockPid != os.getpid():
                    logger.debug("Daemon mode - waiting for parent lock")
                    fcntl.lockf(self.fp, fcntl.LOCK_EX)
                else:
                    logger.debug("Attempting non-blocking lock")
                    fcntl.lockf(self.fp, fcntl.LOCK_EX | fcntl.LOCK_NB)
                
                self.lockPid = os.getpid()
                logger.debug("Acquired lock for PID: %s", self.lockPid)
                
                pidLine = "%i\n" % self.lockPid
                self.fp.truncate(0)
                self.fp.write(pidLine)
                self.fp.flush()
                logger.debug("Updated lock file with current PID")
                
            except IOError:
                logger.error("Another instance is already running")
                sys.exit('Another instance of this application is already running')

    def cleanup(self):
        """Release single instance lock with detailed logging"""
        logger.debug("cleanup() called - initialized=%s", self.initialized)
        
        if not self.initialized:
            logger.debug("Not initialized - skipping cleanup")
            return
            
        if self.daemon and self.lockPid == os.getpid():
            logger.debug("Daemon cleanup for initial forks")
            try:
                if sys.platform == 'win32':
                    if hasattr(self, 'fd'):
                        logger.debug("Closing Windows file descriptor")
                        os.close(self.fd)
                else:
                    logger.debug("Releasing Unix lock")
                    fcntl.lockf(self.fp, fcntl.LOCK_UN)
            except (IOError, OSError) as e:
                logger.warning("Cleanup error in daemon mode: %s", str(e))
            return

        try:
            logger.debug("Performing full cleanup")
            if sys.platform == 'win32':
                if hasattr(self, 'fd'):
                    logger.debug("Windows cleanup - closing and removing lock file")
                    os.close(self.fd)
                    os.unlink(self.lockfile)
            else:
                logger.debug("Unix cleanup - releasing lock and removing file")
                fcntl.lockf(self.fp, fcntl.LOCK_UN)
                if os.path.isfile(self.lockfile):
                    os.unlink(self.lockfile)
            logger.debug("Cleanup completed successfully")
        except (IOError, OSError) as e:
            logger.warning("Cleanup failed: %s", str(e))

logger.debug("singleinstance module initialization complete")
