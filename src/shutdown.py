"""shutdown function - final robust version"""

import os
import sys
import time
import signal

import state
from debug import logger
from helper_sql import sqlStoredProcedure
from network.knownnodes import saveKnownNodes


def doCleanShutdown():
    """
    ULTIMATE shutdown - saves critical data and EXITS IMMEDIATELY
    NO thread joining, NO waiting for anything
    """
    logger.info("⚡ ULTIMATE SHUTDOWN - FAST EXIT")
    
    # Step 1: Set flag
    state.shutdown = 1
    
    # Step 2: Save ABSOLUTELY CRITICAL data only
    try:
        saveKnownNodes()
        logger.info("✓ Known nodes saved")
    except Exception as e:
        logger.warning("✗ Known nodes save failed: %s", e)
    
    try:
        state.Inventory.flush()
        logger.info("✓ Inventory flushed")
    except Exception as e:
        logger.warning("✗ Inventory flush failed: %s", e)
    
    # Step 3: Signal SQL to exit (but don't wait)
    try:
        sqlStoredProcedure('exit')
    except Exception as e:
        logger.warning("✗ SQL signal failed: %s", e)
    
    # Step 4: IMMEDIATE EXIT
    logger.info("💨 EXITING NOW - NO WAITING")
    
    if state.thisapp.daemon or not state.enableGUI:
        try:
            state.thisapp.cleanup()
        except:
            pass
        os._exit(0)
    else:
        # For GUI mode: Qt should quit, but we'll force exit after delay
        import threading
        
        def force_exit_later():
            """Force exit after 2 seconds in case Qt hangs"""
            time.sleep(2.0)
            logger.warning("⚠️ GUI still running, forcing exit")
            os._exit(0)
        
        threading.Thread(target=force_exit_later, daemon=True).start()


def forceExit():
    """Force immediate exit - last resort"""
    try:
        sys.stderr.write("\n[PYBITMESSAGE] FORCE EXIT\n")
        sys.stderr.flush()
    except:
        pass
    
    # Try clean kill first
    try:
        os.kill(os.getpid(), signal.SIGTERM)
    except:
        pass
    
    # If still here after brief wait, use nuclear option
    time.sleep(0.1)
    os._exit(1)
