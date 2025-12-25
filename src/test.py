# test.py - Korrigierte Version
import sys
import os

# Den richtigen Pfad zu PyBitmessage src setzen
sys.path.insert(0, '/home/jon/DEBUG_pybitmessage/src')

# Jetzt PyBitmessage Module importieren
import state as bm_state
from class_singleWorker import singleWorker
import time
import threading

print("=" * 60)
print("Manual singleWorker test")
print("=" * 60)

# Set required state variables
bm_state.enableObjProc = True
bm_state.shutdown = 0

print("Creating singleWorker...")
worker = singleWorker()
print(f"Worker created: {worker}")
print(f"Worker name: {worker.name}")

print("Starting worker...")
worker.daemon = True
worker.start()

print(f"Worker started, is_alive: {worker.is_alive()}")

# Check after delay
def check():
    time.sleep(3)
    print(f"\nAfter 3 seconds:")
    print(f"Worker alive: {worker.is_alive()}")
    
    # List all threads
    print("\nAll threads:")
    for t in threading.enumerate():
        print(f"  - {t.name}: {type(t).__name__}, Alive: {t.is_alive()}")

check_thread = threading.Thread(target=check)
check_thread.daemon = True
check_thread.start()

# Keep running
try:
    while worker.is_alive():
        time.sleep(1)
    print("\nWorker stopped!")
except KeyboardInterrupt:
    print("\nStopping...")
    worker.stopThread()
    time.sleep(1)
