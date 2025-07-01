"""
PyBitmessage does various tasks in separate threads. Most of them inherit
from `.network.StoppableThread`. There are `addressGenerator` for
addresses generation, `objectProcessor` for processing the network objects
passed minimal validation, `singleCleaner` to periodically clean various
internal storages (like inventory and knownnodes) and do forced garbage
collection, `singleWorker` for doing PoW, `sqlThread` for querying sqlite
database.

There are also other threads in the `.network` package.

:func:`set_thread_name` is defined here for the threads that don't inherit from
:class:`.network.StoppableThread`
"""

import threading
import six
import sys

print("DEBUG: threads.py module initialization started")

from class_addressGenerator import addressGenerator
from class_objectProcessor import objectProcessor
from class_singleCleaner import singleCleaner
from class_singleWorker import singleWorker
from class_sqlThread import sqlThread

print("DEBUG: Imported thread classes: addressGenerator, objectProcessor, singleCleaner, singleWorker, sqlThread")

try:
    import prctl
    print("DEBUG: prctl module found - will use OS-level thread naming")
except ImportError:
    print("DEBUG: prctl module not found - using Python-level thread naming only")
    def set_thread_name(name):
        """Set a name for the thread for python internal use."""
        print(f"DEBUG: Setting Python thread name to: {name}")
        threading.current_thread().name = name
else:
    print("DEBUG: Using prctl for thread naming")
    def set_thread_name(name):
        """Set the thread name for external use (visible from the OS)."""
        print(f"DEBUG: Setting OS thread name to: {name}")
        prctl.set_name(name)

    if six.PY2:
        print("DEBUG: Python 2 detected - applying thread name hack")
        def _thread_name_hack(self):
            print(f"DEBUG: Applying thread name hack for: {self.name}")
            set_thread_name(self.name)
            threading.Thread.__bootstrap_original__(self)
        
        # pylint: disable=protected-access
        print("DEBUG: Backing up original thread bootstrap")
        threading.Thread.__bootstrap_original__ = threading.Thread._Thread__bootstrap
        threading.Thread._Thread__bootstrap = _thread_name_hack
        print("DEBUG: Thread name hack installed for Python 2")

print("DEBUG: Creating printLock")
printLock = threading.Lock()
print("DEBUG: printLock created - will be used for thread-safe printing")

__all__ = [
    "addressGenerator", "objectProcessor", "singleCleaner", "singleWorker",
    "sqlThread", "printLock"
]

print("DEBUG: Module initialization completed")
print(f"DEBUG: Exported symbols: {__all__}")
