
import sys
sys.path.append('/path/to/pybitmessage/src')
import queues

# Direkt Task in Queue stellen
queues.workerQueue.put(('sendOutOrStoreMyV4Pubkey', 
                       'BM-2cViWmZRmQi9wvPe8KP2ccSLpwH6Eh5DWx'))
print("Task in Worker Queue gestellt")
