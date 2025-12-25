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
import sys  # <-- IMPORTANT: Keep this at module level

try:
    import pathmagic
except ImportError:
    from pybitmessage import pathmagic
app_dir = pathmagic.setup()

# DEBUG: Early imports
print(f"DEBUG [MAIN]: Starting PyBitmessage, Python {sys.version}")
print(f"DEBUG [MAIN]: sys.path first 3: {sys.path[:3]}")
if len(sys.path) > 3:
    print(f"DEBUG [MAIN]: ... and {len(sys.path)-3} more paths")

import depends
depends.check_dependencies()

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

# Thread-safe signal handling
_signal_lock = threading.RLock()
_active_signals = set()

def signal_handler(signum, frame):
    """Single handler for any signal sent to pybitmessage - REENTRANT SAFE"""
    # Reentrancy protection - don't re-enter signal handler
    with _signal_lock:
        if signum in _active_signals:
            return
        _active_signals.add(signum)
    
    try:
        process = multiprocessing.current_process()
        thread = threading.current_thread()
        
        # Log with minimal risk - use direct stderr for critical cases
        try:
            logger.error(
                'Got signal %i in %s/%s',
                signum, process.name, thread.name
            )
        except Exception:
            # Fallback if logging is already in a bad state
            sys.stderr.write(f"Signal {signum} in {process.name}/{thread.name}\n")
            sys.stderr.flush()
        
        if process.name == "RegExParser":
            # on Windows this isn't triggered, but it's fine,
            # it has its own process termination thing
            raise SystemExit
        if "PoolWorker" in process.name:
            raise SystemExit
        if thread.name not in ("PyBitmessage", "MainThread"):
            return
        
        try:
            logger.error("Got signal %i", signum)
        except Exception:
            sys.stderr.write(f"Got signal {signum}\n")
            sys.stderr.flush()
        
        # there are possible non-UI variants to run bitmessage
        # which should shutdown especially test-mode
        if state.thisapp.daemon or not state.enableGUI:
            # Use safe shutdown that handles threading issues
            _safe_shutdown()
        else:
            print('# Thread: %s(%d)' % (thread.name, thread.ident))
            # Avoid traceback.extract_stack during shutdown if possible
            try:
                for filename, lineno, name, line in traceback.extract_stack(frame):
                    print('File: "%s", line %d, in %s' % (filename, lineno, name))
                    if line:
                        print('  %s' % line.strip())
            except Exception:
                print('Stack trace unavailable')
            print('Unfortunately you cannot use Ctrl+C when running the UI'
                  ' because the UI captures the signal.')
    finally:
        # Clean up signal tracking
        with _signal_lock:
            _active_signals.discard(signum)

def _safe_shutdown():
    """Safe shutdown that minimizes threading issues"""
    try:
        # Set shutdown flag first
        if hasattr(state, 'shutdown'):
            state.shutdown = 1
        
        # Use minimal logging
        try:
            logger.info("Initiating safe shutdown")
        except Exception:
            sys.stderr.write("Initiating shutdown\n")
            sys.stderr.flush()
        
        # Call shutdown with error handling
        shutdown.doCleanShutdown()
    except Exception as e:
        # Last resort
        sys.stderr.write(f"Shutdown error: {e}\n")
        sys.stderr.flush()
        # Force exit after delay to allow cleanup
        threading.Timer(2.0, os._exit, args=[1]).start()

class Main(object):
    """Main PyBitmessage class"""
    def start(self):
        """Start main application"""
        # pylint: disable=too-many-statements,too-many-branches,too-many-locals
        
        print(f"DEBUG [MAIN.start]: Starting main application")
        print(f"DEBUG [MAIN.start]: Thread count: {threading.active_count()}")
        
        fixSocket()
        adjustHalfOpenConnectionsLimit()

        daemon = config.safeGetBoolean('bitmessagesettings', 'daemon')
        
        print(f"DEBUG [MAIN.start]: Daemon mode from config: {daemon}")
        
        # FORCE NO DAEMON FOR DEBUGGING - CRITICAL!
        if daemon:
            print(f"DEBUG [MAIN.start]: WARNING: Daemon mode detected")
            print(f"DEBUG [MAIN.start]: DISABLING daemon mode for debugging")
            print(f"DEBUG [MAIN.start]: Set 'daemon = false' in keys.dat")
            daemon = False

        try:
            opts, _ = getopt.getopt(
                sys.argv[1:], "hcdt",  # <-- FIXED: Use the module-level sys
                ["help", "curses", "daemon", "test"])

        except getopt.GetoptError:
            self.usage()
            sys.exit(2)

        for opt, _ in opts:
            if opt in ("-h", "--help"):
                self.usage()
                sys.exit()
            elif opt in ("-d", "--daemon"):
                print(f"DEBUG [MAIN.start]: Command line --daemon flag, but ignoring for debug")
                # daemon = True  # Don't enable even from command line
            elif opt in ("-c", "--curses"):
                state.curses = True
                print(f"DEBUG [MAIN.start]: Curses mode enabled")
            elif opt in ("-t", "--test"):
                state.testmode = True
                print(f"DEBUG [MAIN.start]: Test mode enabled")
                if os.path.isfile(os.path.join(
                        state.appdata, 'unittest.lock')):
                    # daemon = True  # Don't enable daemon even for tests
                    pass
                state.enableGUI = False  # run without a UI
                # Fallback: in case when no api command was issued
                state.last_api_response = time.time()
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

        if daemon:
            state.enableGUI = False  # run without a UI
            print(f"DEBUG [MAIN.start]: GUI disabled (daemon mode)")
        else:
            print(f"DEBUG [MAIN.start]: GUI enabled (non-daemon mode)")

        if state.enableGUI and not state.curses and not depends.check_pyqt():
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
        
        # is the application already running?  If yes then exit.
        print(f"DEBUG [MAIN.start]: Creating singleinstance...")
        state.thisapp = singleinstance("", daemon)
        print(f"DEBUG [MAIN.start]: singleinstance created")

        if daemon:
            with printLock:
                print('Running as a daemon. Send TERM signal to end.')
                print(f"DEBUG [MAIN.start]: Starting daemonization")
            self.daemonize()

        self.setSignalHandler()

        set_thread_name("PyBitmessage")
        print(f"DEBUG [MAIN.start]: Main thread name set to PyBitmessage")

        if state.testmode or config.safeGetBoolean(
                'bitmessagesettings', 'extralowdifficulty'):
            print(f"DEBUG [MAIN.start]: Adjusting PoW difficulty for test mode")
            defaults.networkDefaultProofOfWorkNonceTrialsPerByte = int(
                defaults.networkDefaultProofOfWorkNonceTrialsPerByte / 100)
            defaults.networkDefaultPayloadLengthExtraBytes = int(
                defaults.networkDefaultPayloadLengthExtraBytes / 100)

        # Start the SQL thread
        print(f"DEBUG [MAIN.start]: Starting SQL thread...")
        sqlLookup = sqlThread()
        # DON'T close the main program even if there are threads left.
        # The closeEvent should command this thread to exit gracefully.
        sqlLookup.daemon = False
        sqlLookup.start()
        print(f"DEBUG [MAIN.start]: SQL thread started")
        
        print(f"DEBUG [MAIN.start]: Initializing Inventory...")
        state.Inventory = Inventory()  # init
        print(f"DEBUG [MAIN.start]: Inventory initialized")

        print(f"DEBUG [MAIN.start]: Checking state.enableObjProc = {state.enableObjProc}")
        if state.enableObjProc:  # Not needed if objproc is disabled
            print(f"DEBUG [MAIN.start]: Object processing ENABLED")
            print(f"DEBUG [MAIN.start]: Thread count before object threads: {threading.active_count()}")
            
            # Start the address generation thread
            print(f"DEBUG [MAIN.start]: Creating addressGenerator...")
            addressGeneratorThread = addressGenerator()
            # close the main program even if there are threads left
            addressGeneratorThread.daemon = True
            print(f"DEBUG [MAIN.start]: Starting addressGenerator thread...")
            addressGeneratorThread.start()
            print(f"DEBUG [MAIN.start]: addressGenerator thread started")
            time.sleep(0.1)  # Kurze Pause
            print(f"DEBUG [MAIN.start]: addressGenerator.is_alive(): {addressGeneratorThread.is_alive()}")

            # ========== SINGLEWORKER DEBUG START ==========
            print(f"\n{'='*80}")
            print(f"DEBUG [MAIN.start]: SINGLEWORKER INITIALIZATION")
            print(f"{'='*80}")
            
            try:
                print(f"DEBUG [MAIN.start]: Importing singleWorker module...")
                from threads import singleWorker
                print(f"DEBUG [MAIN.start]: singleWorker module imported successfully")
                
                print(f"DEBUG [MAIN.start]: Creating singleWorker instance...")
                singleWorkerThread = singleWorker()
                print(f"DEBUG [MAIN.start]: singleWorker instance created: {singleWorkerThread}")
                print(f"DEBUG [MAIN.start]: singleWorker thread name: {singleWorkerThread.name}")
                print(f"DEBUG [MAIN.start]: singleWorker thread type: {type(singleWorkerThread)}")
                
                # close the main program even if there are threads left
                singleWorkerThread.daemon = True
                print(f"DEBUG [MAIN.start]: singleWorker daemon set to True")
                
                print(f"DEBUG [MAIN.start]: Starting singleWorker thread...")
                singleWorkerThread.start()
                print(f"DEBUG [MAIN.start]: singleWorker thread start() called")
                
                # Sofortige Überprüfung
                time.sleep(0.2)
                print(f"DEBUG [MAIN.start]: Immediate check - singleWorkerThread.is_alive(): {singleWorkerThread.is_alive()}")
                
                if not singleWorkerThread.is_alive():
                    print(f"DEBUG [MAIN.start]: ERROR: singleWorker thread died immediately!")
                    print(f"DEBUG [MAIN.start]: Checking for exceptions...")
                    
                    # Versuche, Exception-Info zu bekommen
                    try:
                        # Don't reimport sys here - use the module level one
                        if hasattr(singleWorkerThread, '_exception'):
                            print(f"DEBUG [MAIN.start]: Thread has exception: {singleWorkerThread._exception}")
                    except:
                        pass
                
                # Ausführliche Überwachung des Threads
                import threading as thr
                
                def monitor_singleworker(worker_thread, worker_name):
                    """Überwacht den singleWorker Thread"""
                    print(f"DEBUG [MONITOR {worker_name}]: Monitor thread started")
                    
                    # Sofortige Prüfung
                    time.sleep(1)
                    print(f"DEBUG [MONITOR {worker_name}]: After 1s - is_alive: {worker_thread.is_alive()}")
                    
                    if worker_thread.is_alive():
                        print(f"DEBUG [MONITOR {worker_name}]: Thread is running")
                        
                        # Prüfe alle 5 Sekunden
                        check_count = 0
                        while worker_thread.is_alive() and check_count < 12:  # 60 Sekunden max
                            time.sleep(5)
                            check_count += 1
                            print(f"DEBUG [MONITOR {worker_name}]: Check {check_count} - is_alive: {worker_thread.is_alive()}")
                            
                            # Thread-Stack prüfen
                            try:
                                # Aktive Threads auflisten
                                if check_count % 2 == 0:  # Alle 10 Sekunden
                                    print(f"DEBUG [MONITOR {worker_name}]: Active threads ({thr.active_count()}):")
                                    for i, t in enumerate(thr.enumerate()):
                                        print(f"  {i+1:2d}. {t.name:30} - Alive: {t.is_alive()}")
                            except:
                                pass
                        
                        if worker_thread.is_alive():
                            print(f"DEBUG [MONITOR {worker_name}]: Thread still alive after {check_count*5} seconds")
                        else:
                            print(f"DEBUG [MONITOR {worker_name}]: ERROR: Thread died after {check_count*5} seconds!")
                    else:
                        print(f"DEBUG [MONITOR {worker_name}]: ERROR: Thread never started or died immediately!")
                        
                        # Versuche zu prüfen warum
                        print(f"DEBUG [MONITOR {worker_name}]: Current threads:")
                        for i, t in enumerate(thr.enumerate()):
                            print(f"  {i+1:2d}. {t.name:30} - Alive: {t.is_alive()}")
                
                # Monitor-Thread starten
                monitor_thread = thr.Thread(
                    target=monitor_singleworker,
                    args=(singleWorkerThread, "singleWorker"),
                    name="singleWorkerMonitor",
                    daemon=True
                )
                monitor_thread.start()
                print(f"DEBUG [MAIN.start]: Monitor thread started for singleWorker")
                
            except Exception as e:
                print(f"DEBUG [MAIN.start]: EXCEPTION creating/starting singleWorker: {e}")
                import traceback
                traceback.print_exc()
                print(f"{'='*80}\n")
            
            print(f"{'='*80}\n")
            # ========== SINGLEWORKER DEBUG END ==========

            # Start the object processing thread
            print(f"DEBUG [MAIN.start]: Creating objectProcessor...")
            objectProcessorThread = objectProcessor()
            # DON'T close the main program even if the thread remains.
            # This thread checks the shutdown variable after processing
            # each object.
            objectProcessorThread.daemon = False
            print(f"DEBUG [MAIN.start]: Starting objectProcessor thread...")
            objectProcessorThread.start()
            print(f"DEBUG [MAIN.start]: objectProcessor thread started")
            print(f"DEBUG [MAIN.start]: objectProcessor.is_alive(): {objectProcessorThread.is_alive()}")

            # SMTP delivery thread
            if daemon and config.safeGet(
                    'bitmessagesettings', 'smtpdeliver', '') != '':
                print(f"DEBUG [MAIN.start]: Starting SMTP delivery thread...")
                from class_smtpDeliver import smtpDeliver
                smtpDeliveryThread = smtpDeliver()
                smtpDeliveryThread.start()
                print(f"DEBUG [MAIN.start]: SMTP delivery thread started")

            # SMTP daemon thread
            if daemon and config.safeGetBoolean(
                    'bitmessagesettings', 'smtpd'):
                print(f"DEBUG [MAIN.start]: Starting SMTP daemon thread...")
                from class_smtpServer import smtpServer
                smtpServerThread = smtpServer()
                smtpServerThread.start()
                print(f"DEBUG [MAIN.start]: SMTP daemon thread started")

            # API is also objproc dependent
            if config.safeGetBoolean('bitmessagesettings', 'apienabled'):
                print(f"DEBUG [MAIN.start]: Starting API thread...")
                import api  # pylint: disable=relative-import
                singleAPIThread = api.singleAPI()
                # close the main program even if there are threads left
                singleAPIThread.daemon = True
                singleAPIThread.start()
                print(f"DEBUG [MAIN.start]: API thread started")
                
            print(f"DEBUG [MAIN.start]: Thread count after object threads: {threading.active_count()}")
        else:
            print(f"DEBUG [MAIN.start]: WARNING: Object processing DISABLED (state.enableObjProc = False)")
            print(f"DEBUG [MAIN.start]: singleWorker will NOT be started!")

        # Start the cleanerThread
        print(f"DEBUG [MAIN.start]: Creating singleCleaner...")
        singleCleanerThread = singleCleaner()
        # close the main program even if there are threads left
        singleCleanerThread.daemon = True
        print(f"DEBUG [MAIN.start]: Starting singleCleaner thread...")
        singleCleanerThread.start()
        print(f"DEBUG [MAIN.start]: singleCleaner thread started")
        print(f"DEBUG [MAIN.start]: singleCleaner.is_alive(): {singleCleanerThread.is_alive()}")

        # start network components if networking is enabled
        print(f"DEBUG [MAIN.start]: state.enableNetwork = {state.enableNetwork}")
        if state.enableNetwork:
            print(f"DEBUG [MAIN.start]: Starting network components...")
            start_proxyconfig()
            network.start(config, state)
            print(f"DEBUG [MAIN.start]: Network started")

            if config.safeGetBoolean('bitmessagesettings', 'upnp'):
                print(f"DEBUG [MAIN.start]: Starting uPnP thread...")
                import upnp
                upnpThread = upnp.uPnPThread()
                upnpThread.start()
                print(f"DEBUG [MAIN.start]: uPnP thread started")
        else:
            print(f"DEBUG [MAIN.start]: Network disabled, connecting to stream 1...")
            network.connectionpool.pool.connectToStream(1)

        print(f"DEBUG [MAIN.start]: Thread count before GUI: {threading.active_count()}")
        print(f"DEBUG [MAIN.start]: Current threads:")
        for i, t in enumerate(threading.enumerate()):
            print(f"  {i+1:2d}. {t.name:30} - Alive: {t.is_alive()}")

        if not daemon and state.enableGUI:
            print(f"DEBUG [MAIN.start]: Starting GUI...")
            if state.curses:
                if not depends.check_curses():
                    sys.exit()
                print('Running with curses')
                import bitmessagecurses
                bitmessagecurses.runwrapper()
            else:
                print(f"DEBUG [MAIN.start]: Starting Qt GUI...")
                import bitmessageqt
                bitmessageqt.run()
                print(f"DEBUG [MAIN.start]: Qt GUI started")
        else:
            print(f"DEBUG [MAIN.start]: No GUI (daemon mode)")
            config.remove_option('bitmessagesettings', 'dontconnect')

        if state.testmode:
            print(f"DEBUG [MAIN.start]: Populating API test data...")
            populate_api_test_data()

        print(f"\n{'='*80}")
        print(f"DEBUG [MAIN.start]: STARTUP COMPLETE")
        print(f"DEBUG [MAIN.start]: Total threads: {threading.active_count()}")
        print(f"DEBUG [MAIN.start]: Final thread list:")
        for i, t in enumerate(threading.enumerate()):
            print(f"  {i+1:2d}. {t.name:30} - Alive: {t.is_alive()}")
        print(f"{'='*80}\n")

        if daemon:
            print(f"DEBUG [MAIN.start]: Entering daemon main loop...")
            while state.shutdown == 0:
                time.sleep(1)
                if (
                    state.testmode
                    and time.time() - state.last_api_response >= 30
                ):
                    self.stop()
        elif not state.enableGUI:
            state.enableGUI = True
            try:
                # pylint: disable=relative-import
                from tests import core as test_core
            except ImportError:
                try:
                    from pybitmessage.tests import core as test_core
                except ImportError:
                    self.stop()
                    return

            test_core_result = test_core.run()
            self.stop()
            test_core.cleanup()
            sys.exit(not test_core_result.wasSuccessful())

    @staticmethod
    def daemonize():
        """Running as a daemon. Send signal in end."""
        print(f"DEBUG [MAIN.daemonize]: Starting daemonization process")
        grandfatherPid = os.getpid()
        parentPid = None
        try:
            if os.fork():
                # unlock
                state.thisapp.cleanup()
                # wait until grandchild ready
                while True:
                    time.sleep(1)
                os._exit(0)  # pylint: disable=protected-access
        except AttributeError:
            # fork not implemented
            pass
        else:
            parentPid = os.getpid()
            state.thisapp.lock()  # relock

        os.umask(0)
        try:
            os.setsid()
        except AttributeError:
            # setsid not implemented
            pass
        try:
            if os.fork():
                # unlock
                state.thisapp.cleanup()
                # wait until child ready
                while True:
                    time.sleep(1)
                os._exit(0)  # pylint: disable=protected-access
        except AttributeError:
            # fork not implemented
            pass
        else:
            state.thisapp.lock()  # relock
        
        state.thisapp.lockPid = None  # indicate we're the final child
        sys.stdout.flush()
        sys.stderr.flush()
        
        if not sys.platform.startswith('win'):
            si = open(os.devnull, 'r')
            so = open(os.devnull, 'a+')
            se = open(os.devnull, 'a+', 0)
            os.dup2(si.fileno(), sys.stdin.fileno())
            os.dup2(so.fileno(), sys.stdout.fileno())
            os.dup2(se.fileno(), sys.stderr.fileno())
        
        if parentPid:
            # signal ready
            os.kill(parentPid, signal.SIGTERM)
            os.kill(grandfatherPid, signal.SIGTERM)
        
        print(f"DEBUG [MAIN.daemonize]: Daemonization complete")

    @staticmethod
    def setSignalHandler():
        """Setting the Signal Handler"""
        print(f"DEBUG [MAIN.setSignalHandler]: Setting signal handlers")
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        # signal.signal(signal.SIGINT, signal.SIG_DFL)

    @staticmethod
    def usage():
        """Displaying the usages"""
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
        print(f"DEBUG [MAIN.stop]: Stopping Bitmessage Daemon")
        with printLock:
            print('Stopping Bitmessage Deamon.')
        _safe_shutdown()

    # .. todo:: nice function but no one is using this
    @staticmethod
    def getApiAddress():
        """This function returns API address and port"""
        if not config.safeGetBoolean(
                'bitmessagesettings', 'apienabled'):
            return None
        address = config.get('bitmessagesettings', 'apiinterface')
        port = config.getint('bitmessagesettings', 'apiport')
        return {'address': address, 'port': port}


def main():
    """Triggers main module"""
    print(f"\n{'='*80}")
    print(f"DEBUG [main()]: PyBitmessage starting at {time.ctime()}")
    print(f"DEBUG [main()]: Working directory: {os.getcwd()}")
    print(f"DEBUG [main()]: Script location: {os.path.abspath(__file__)}")
    print(f"{'='*80}")
    
    # Setze Debug-Umgebung
    os.environ['PYBITMESSAGE_DEBUG'] = '1'
    
    mainprogram = Main()
    mainprogram.start()
    
    print(f"\n{'='*80}")
    print(f"DEBUG [main()]: PyBitmessage exiting at {time.ctime()}")
    print(f"{'='*80}")


if __name__ == "__main__":
    main()


# So far, the creation of and management of the Bitmessage protocol and this
# client is a one-man operation. Bitcoin tips are quite appreciated.
# 1H5XaDA6fYENLbknwZyjiYXYPQaFjjLX2u
