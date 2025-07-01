#!/usr/bin/env python
"""
The PyBitmessage startup script
"""
# Copyright (c) 2012-2016 Jonathan Warren
# Copyright (c) 2012-2022 The Bitmessage developers
# Distributed under the MIT/X11 software license. See the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Right now, PyBitmessage only support connecting to stream 1. It doesn't
# yet contain logic to expand into further streams.
import os
import sys

# Debug initialization
DEBUG_MODE = True
def debug_print(message):
    if DEBUG_MODE:
        print(f"DEBUG: {message}")

debug_print("Starting PyBitmessage initialization")

try:
    import pathmagic
    debug_print("Successfully imported pathmagic")
except ImportError:
    from pybitmessage import pathmagic
    debug_print("Imported pathmagic from pybitmessage package")
app_dir = pathmagic.setup()
debug_print(f"Application directory set to: {app_dir}")

import depends
debug_print("Checking dependencies...")
depends.check_dependencies()
debug_print("Dependencies checked")

import getopt
import multiprocessing
# Used to capture a Ctrl-C keypress so that Bitmessage can shutdown gracefully.
import signal
import threading
import time
import traceback

import defaults
# Network subsystem
import network
import shutdown
import state

from testmode_init import populate_api_test_data
from bmconfigparser import config
from debug import logger  # this should go before any threads
from helper_startup import (
    adjustHalfOpenConnectionsLimit, fixSocket, start_proxyconfig)
from inventory import Inventory
from singleinstance import singleinstance
# Synchronous threads
from threads import (
    set_thread_name, printLock,
    addressGenerator, objectProcessor, singleCleaner, singleWorker, sqlThread)


def signal_handler(signum, frame):
    """Single handler for any signal sent to pybitmessage"""
    debug_print(f"Signal handler triggered with signal {signum}")
    process = multiprocessing.current_process()
    thread = threading.current_thread()
    logger.error(
        'Got signal %i in %s/%s',
        signum, process.name, thread.name
    )
    debug_print(f"Signal received in process: {process.name}, thread: {thread.name}")
    
    if process.name == "RegExParser":
        debug_print("RegExParser process exiting due to signal")
        # on Windows this isn't triggered, but it's fine,
        # it has its own process termination thing
        raise SystemExit
    if "PoolWorker" in process.name:
        debug_print("PoolWorker process exiting due to signal")
        raise SystemExit
    if thread.name not in ("PyBitmessage", "MainThread"):
        debug_print("Signal ignored in non-main thread")
        return
        
    logger.error("Got signal %i", signum)
    debug_print(f"Main thread received signal {signum}")
    # there are possible non-UI variants to run bitmessage
    # which should shutdown especially test-mode
    if state.thisapp.daemon or not state.enableGUI:
        debug_print("Initiating clean shutdown (daemon or non-GUI mode)")
        shutdown.doCleanShutdown()
    else:
        print('# Thread: %s(%d)' % (thread.name, thread.ident))
        debug_print("Stack trace for signal in UI mode:")
        for filename, lineno, name, line in traceback.extract_stack(frame):
            print('File: "%s", line %d, in %s' % (filename, lineno, name))
            if line:
                print('  %s' % line.strip())
        debug_print("Cannot use Ctrl+C in UI mode")
        print('Unfortunately you cannot use Ctrl+C when running the UI'
              ' because the UI captures the signal.')


class Main(object):
    """Main PyBitmessage class"""
    def start(self):
        """Start main application"""
        # pylint: disable=too-many-statements,too-many-branches,too-many-locals
        debug_print("Main.start() called")
        
        debug_print("Fixing socket settings")
        fixSocket()
        debug_print("Adjusting half-open connections limit")
        adjustHalfOpenConnectionsLimit()

        daemon = config.safeGetBoolean('bitmessagesettings', 'daemon')
        debug_print(f"Daemon mode from config: {daemon}")

        try:
            debug_print("Parsing command line arguments")
            opts, _ = getopt.getopt(
                sys.argv[1:], "hcdt",
                ["help", "curses", "daemon", "test"])

        except getopt.GetoptError as e:
            debug_print(f"Command line argument error: {str(e)}")
            self.usage()
            sys.exit(2)

        for opt, _ in opts:
            if opt in ("-h", "--help"):
                debug_print("Help option selected")
                self.usage()
                sys.exit()
            elif opt in ("-d", "--daemon"):
                debug_print("Daemon mode enabled via command line")
                daemon = True
            elif opt in ("-c", "--curses"):
                debug_print("Curses mode enabled")
                state.curses = True
            elif opt in ("-t", "--test"):
                debug_print("Test mode enabled")
                state.testmode = True
                if os.path.isfile(os.path.join(
                        state.appdata, 'unittest.lock')):
                    debug_print("Unittest lock file found, forcing daemon mode")
                    daemon = True
                state.enableGUI = False  # run without a UI
                debug_print("GUI disabled for test mode")
                # Fallback: in case when no api command was issued
                state.last_api_response = time.time()
                debug_print("API response timer initialized")
                # Apply special settings
                config.set(
                    'bitmessagesettings', 'apienabled', 'true')
                config.set(
                    'bitmessagesettings', 'apiusername', 'username')
                config.set(
                    'bitmessagesettings', 'apipassword', 'password')
                config.set(
                    'bitmessagesettings', 'apivariant', 'legacy')
                config.set(
                    'bitmessagesettings', 'apinotifypath',
                    os.path.join(app_dir, 'tests', 'apinotify_handler.py')
                )
                debug_print("Test mode API settings configured")

        if daemon:
            state.enableGUI = False  # run without a UI
            debug_print("GUI disabled for daemon mode")

        if state.enableGUI and not state.curses and not depends.check_pyqt():
            debug_print("PyQt check failed for GUI mode")
            sys.exit(
                'PyBitmessage requires PyQt unless you want'
                ' to run it as a daemon and interact with it'
                ' using the API. You can download PyQt from '
                'http://www.riverbankcomputing.com/software/pyqt/download'
                ' or by searching Google for \'PyQt Download\'.'
                ' If you want to run in daemon mode, see '
                'https://bitmessage.org/wiki/Daemon\n'
                'You can also run PyBitmessage with'
                ' the new curses interface by providing'
                ' \'-c\' as a commandline argument.'
            )
            
        debug_print("Checking for existing instance")
        # is the application already running?  If yes then exit.
        state.thisapp = singleinstance("", daemon)
        debug_print("Single instance check completed")

        if daemon:
            with printLock:
                print('Running as a daemon. Send TERM signal to end.')
            debug_print("Starting daemonization process")
            self.daemonize()

        debug_print("Setting up signal handlers")
        self.setSignalHandler()

        set_thread_name("PyBitmessage")
        debug_print("Main thread name set to PyBitmessage")

        if state.testmode or config.safeGetBoolean(
                'bitmessagesettings', 'extralowdifficulty'):
            debug_print("Adjusting proof of work difficulty for test/low mode")
            defaults.networkDefaultProofOfWorkNonceTrialsPerByte = int(
                defaults.networkDefaultProofOfWorkNonceTrialsPerByte / 100)
            defaults.networkDefaultPayloadLengthExtraBytes = int(
                defaults.networkDefaultPayloadLengthExtraBytes / 100)

        # Start the SQL thread
        debug_print("Starting SQL thread")
        sqlLookup = sqlThread()
        # DON'T close the main program even if there are threads left.
        # The closeEvent should command this thread to exit gracefully.
        sqlLookup.daemon = False
        sqlLookup.start()
        state.Inventory = Inventory()  # init
        debug_print("SQL thread started and inventory initialized")

        if state.enableObjProc:  # Not needed if objproc is disabled
            debug_print("Starting object processing related threads")
            # Start the address generation thread
            addressGeneratorThread = addressGenerator()
            # close the main program even if there are threads left
            addressGeneratorThread.daemon = True
            addressGeneratorThread.start()
            debug_print("Address generator thread started")

            # Start the thread that calculates POWs
            singleWorkerThread = singleWorker()
            # close the main program even if there are threads left
            singleWorkerThread.daemon = True
            singleWorkerThread.start()
            debug_print("Single worker thread started")

            # Start the object processing thread
            objectProcessorThread = objectProcessor()
            # DON'T close the main program even if the thread remains.
            # This thread checks the shutdown variable after processing
            # each object.
            objectProcessorThread.daemon = False
            objectProcessorThread.start()
            debug_print("Object processor thread started")

            # SMTP delivery thread
            if daemon and config.safeGet(
                    'bitmessagesettings', 'smtpdeliver', '') != '':
                debug_print("Starting SMTP delivery thread")
                from class_smtpDeliver import smtpDeliver
                smtpDeliveryThread = smtpDeliver()
                smtpDeliveryThread.start()
                debug_print("SMTP delivery thread started")

            # SMTP daemon thread
            if daemon and config.safeGetBoolean(
                    'bitmessagesettings', 'smtpd'):
                debug_print("Starting SMTP server thread")
                from class_smtpServer import smtpServer
                smtpServerThread = smtpServer()
                smtpServerThread.start()
                debug_print("SMTP server thread started")

            # API is also objproc dependent
            if config.safeGetBoolean('bitmessagesettings', 'apienabled'):
                debug_print("Starting API thread")
                import api  # pylint: disable=relative-import
                singleAPIThread = api.singleAPI()
                # close the main program even if there are threads left
                singleAPIThread.daemon = True
                singleAPIThread.start()
                debug_print("API thread started")

        # Start the cleanerThread
        debug_print("Starting cleaner thread")
        singleCleanerThread = singleCleaner()
        # close the main program even if there are threads left
        singleCleanerThread.daemon = True
        singleCleanerThread.start()
        debug_print("Cleaner thread started")

        # start network components if networking is enabled
        if state.enableNetwork:
            debug_print("Starting network components")
            start_proxyconfig()
            network.start(config, state)
            debug_print("Network components started")

            if config.safeGetBoolean('bitmessagesettings', 'upnp'):
                debug_print("Starting UPnP thread")
                import upnp
                upnpThread = upnp.uPnPThread()
                upnpThread.start()
                debug_print("UPnP thread started")
        else:
            debug_print("Networking disabled, connecting to stream 1 directly")
            network.connectionpool.pool.connectToStream(1)

        if not daemon and state.enableGUI:
            if state.curses:
                if not depends.check_curses():
                    debug_print("Curses check failed, exiting")
                    sys.exit()
                debug_print("Starting curses interface")
                print('Running with curses')
                import bitmessagecurses
                bitmessagecurses.runwrapper()
            else:
                debug_print("Starting Qt GUI")
                import bitmessageqt
                bitmessageqt.run()
        else:
            debug_print("Removing dontconnect option from config")
            config.remove_option('bitmessagesettings', 'dontconnect')

        if state.testmode:
            debug_print("Populating API test data")
            populate_api_test_data()

        if daemon:
            debug_print("Entering daemon main loop")
            while state.shutdown == 0:
                time.sleep(1)
                if (
                    state.testmode
                    and time.time() - state.last_api_response >= 30
                ):
                    debug_print("Test mode timeout reached, stopping")
                    self.stop()
        elif not state.enableGUI:
            state.enableGUI = True
            debug_print("Running in test mode without GUI")
            try:
                # pylint: disable=relative-import
                from tests import core as test_core
                debug_print("Imported test_core directly")
            except ImportError:
                try:
                    from pybitmessage.tests import core as test_core
                    debug_print("Imported test_core from pybitmessage package")
                except ImportError:
                    debug_print("Failed to import test_core, stopping")
                    self.stop()
                    return

            debug_print("Running test core")
            test_core_result = test_core.run()
            self.stop()
            test_core.cleanup()
            debug_print(f"Test core completed with result: {test_core_result.wasSuccessful()}")
            sys.exit(not test_core_result.wasSuccessful())

    @staticmethod
    def daemonize():
        """Running as a daemon. Send signal in end."""
        debug_print("Starting daemonization process")
        grandfatherPid = os.getpid()
        parentPid = None
        try:
            debug_print("Attempting first fork")
            if os.fork():
                # unlock
                state.thisapp.cleanup()
                debug_print("First fork parent process cleaning up")
                # wait until grandchild ready
                while True:
                    time.sleep(1)
                os._exit(0)  # pylint: disable=protected-access
        except AttributeError:
            debug_print("Fork not implemented on this platform")
            pass
        else:
            parentPid = os.getpid()
            state.thisapp.lock()  # relock
            debug_print(f"First fork child process (PID: {parentPid})")

        os.umask(0)
        try:
            debug_print("Creating new session")
            os.setsid()
        except AttributeError:
            debug_print("setsid not implemented on this platform")
            pass
        try:
            debug_print("Attempting second fork")
            if os.fork():
                # unlock
                state.thisapp.cleanup()
                debug_print("Second fork parent process cleaning up")
                # wait until child ready
                while True:
                    time.sleep(1)
                os._exit(0)  # pylint: disable=protected-access
        except AttributeError:
            debug_print("Fork not implemented on this platform")
            pass
        else:
            state.thisapp.lock()  # relock
            debug_print("Second fork child process continuing")
        state.thisapp.lockPid = None  # indicate we're the final child
        sys.stdout.flush()
        sys.stderr.flush()
        if not sys.platform.startswith('win'):
            debug_print("Redirecting standard file descriptors on Unix")
            si = open(os.devnull, 'r')
            so = open(os.devnull, 'a+')
            se = open(os.devnull, 'a+', 0)
            os.dup2(si.fileno(), sys.stdin.fileno())
            os.dup2(so.fileno(), sys.stdout.fileno())
            os.dup2(se.fileno(), sys.stderr.fileno())
        if parentPid:
            # signal ready
            debug_print("Signaling parent processes to exit")
            os.kill(parentPid, signal.SIGTERM)
            os.kill(grandfatherPid, signal.SIGTERM)
        debug_print("Daemonization complete")

    @staticmethod
    def setSignalHandler():
        """Setting the Signal Handler"""
        debug_print("Setting up signal handlers for SIGINT and SIGTERM")
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        # signal.signal(signal.SIGINT, signal.SIG_DFL)

    @staticmethod
    def usage():
        """Displaying the usages"""
        debug_print("Displaying usage information")
        print('Usage: ' + sys.argv[0] + ' [OPTIONS]')
        print('''
Options:
  -h, --help            show this help message and exit
  -c, --curses          use curses (text mode) interface
  -d, --daemon          run in daemon (background) mode
  -t, --test            dryrun, make testing

All parameters are optional.
''')

    @staticmethod
    def stop():
        """Stop main application"""
        debug_print("Initiating application stop")
        with printLock:
            print('Stopping Bitmessage Deamon.')
        shutdown.doCleanShutdown()

    # .. todo:: nice function but no one is using this
    @staticmethod
    def getApiAddress():
        """This function returns API address and port"""
        debug_print("getApiAddress called")
        if not config.safeGetBoolean(
                'bitmessagesettings', 'apienabled'):
            debug_print("API not enabled, returning None")
            return None
        address = config.get('bitmessagesettings', 'apiinterface')
        port = config.getint('bitmessagesettings', 'apiport')
        debug_print(f"API address: {address}, port: {port}")
        return {'address': address, 'port': port}


def main():
    """Triggers main module"""
    debug_print("Main function started")
    mainprogram = Main()
    mainprogram.start()
    debug_print("Main function completed")


if __name__ == "__main__":
    debug_print("Script started as main program")
    main()
    debug_print("Script execution completed")


# So far, the creation of and management of the Bitmessage protocol and this
# client is a one-man operation. Bitcoin tips are quite appreciated.
# 1H5XaDA6fYENLbknwZyjiYXYPQaFjjLX2u
