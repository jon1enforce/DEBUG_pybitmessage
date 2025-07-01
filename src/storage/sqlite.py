"""
Sqlite Inventory
"""
import six
import sqlite3
import time
from threading import RLock
import logging

from helper_sql import SqlBulkExecute, sqlExecute, sqlQuery
from .storage import InventoryItem, InventoryStorage

logger = logging.getLogger('default')

class SqliteInventory(InventoryStorage):
    """Inventory using SQLite"""
    def __init__(self):
        logger.debug("DEBUG: Initializing SqliteInventory")
        super(SqliteInventory, self).__init__()
        self._inventory = {}
        self._objects = {}
        self.lock = RLock()
        logger.debug("DEBUG: SqliteInventory initialized with empty caches and RLock")

    def __contains__(self, hash_):
        with self.lock:
            hash_bytes = bytes(hash_)
            logger.debug(f"DEBUG: Checking if hash exists: {hash_bytes}")
            
            if hash_bytes in self._objects:
                logger.debug("DEBUG: Hash found in memory cache (_objects)")
                return True
                
            logger.debug("DEBUG: Hash not in memory cache, querying database")
            rows = sqlQuery(
                'SELECT streamnumber FROM inventory WHERE hash=?',
                sqlite3.Binary(hash_))
                
            if not rows:
                logger.debug("DEBUG: Hash not found in database")
                return False
                
            logger.debug("DEBUG: Hash found in database, adding to cache")
            self._objects[hash_bytes] = rows[0][0]
            return True

    def __getitem__(self, hash_):
        with self.lock:
            hash_bytes = bytes(hash_)
            logger.debug(f"DEBUG: Retrieving item: {hash_bytes}")
            
            if hash_bytes in self._inventory:
                logger.debug("DEBUG: Item found in memory cache (_inventory)")
                return self._inventory[hash_bytes]
                
            logger.debug("DEBUG: Item not in memory cache, querying database")
            rows = sqlQuery(
                'SELECT objecttype, streamnumber, payload, expirestime, tag'
                ' FROM inventory WHERE hash=?', sqlite3.Binary(hash_))
                
            if not rows:
                logger.debug("DEBUG: Item not found in database")
                raise KeyError(hash_)
                
            logger.debug("DEBUG: Item found in database")
            return InventoryItem(*rows[0])

    def __setitem__(self, hash_, value):
        with self.lock:
            logger.debug(f"DEBUG: Setting item: {hash_}")
            value = InventoryItem(*value)
            hash_bytes = bytes(hash_)
            
            self._inventory[hash_bytes] = value
            self._objects[hash_bytes] = value.stream
            logger.debug(f"DEBUG: Item added to caches - type: {value.type}, stream: {value.stream}")

    def __delitem__(self, hash_):
        logger.debug(f"DEBUG: Delete item attempted (not implemented): {hash_}")
        raise NotImplementedError

    def __iter__(self):
        with self.lock:
            logger.debug("DEBUG: Creating inventory iterator")
            memory_hashes = list(self._inventory.keys())
            db_hashes = [x for x, in sqlQuery('SELECT hash FROM inventory')]
            total = len(memory_hashes) + len(db_hashes)
            logger.debug(f"DEBUG: Iterator created - memory: {len(memory_hashes)}, db: {len(db_hashes)}, total: {total}")
            return (h for h in memory_hashes + db_hashes).__iter__()

    def __len__(self):
        with self.lock:
            memory_len = len(self._inventory)
            db_len = sqlQuery('SELECT count(*) FROM inventory')[0][0]
            total = memory_len + db_len
            logger.debug(f"DEBUG: Inventory length - memory: {memory_len}, db: {db_len}, total: {total}")
            return total

    def by_type_and_tag(self, objectType, tag=None):
        """Get all inventory items of certain objectType with optional tag"""
        with self.lock:
            logger.debug(f"DEBUG: Filtering by type: {objectType}, tag: {tag}")
            
            # Memory cache filtering
            memory_values = [
                value for value in self._inventory.values()
                if value.type == objectType and (tag is None or value.tag == tag)
            ]
            
            # Database query
            query = [
                'SELECT objecttype, streamnumber, payload, expirestime, tag'
                ' FROM inventory WHERE objecttype=?', objectType]
            if tag:
                query[0] += ' AND tag=?'
                query.append(sqlite3.Binary(tag))
                
            db_values = [InventoryItem(*value) for value in sqlQuery(*query)]
            
            total = len(memory_values) + len(db_values)
            logger.debug(f"DEBUG: Found {total} matching items (memory: {len(memory_values)}, db: {len(db_values)})")
            return memory_values + db_values

    def unexpired_hashes_by_stream(self, stream):
        """Return unexpired inventory vectors filtered by stream"""
        with self.lock:
            current_time = int(time.time())
            logger.debug(f"DEBUG: Finding unexpired hashes for stream {stream} at {current_time}")
            
            # Memory cache filtering
            memory_hashes = [
                x for x, value in self._inventory.items()
                if value.stream == stream and value.expires > current_time
            ]
            
            # Database query
            db_hashes = [bytes(payload) for payload, in sqlQuery(
                'SELECT hash FROM inventory WHERE streamnumber=? AND expirestime>?',
                stream, current_time)]
                
            total = len(memory_hashes) + len(db_hashes)
            logger.debug(f"DEBUG: Found {total} unexpired hashes (memory: {len(memory_hashes)}, db: {len(db_hashes)})")
            return memory_hashes + db_hashes

    def flush(self):
        """Flush cache to database"""
        with self.lock:
            count = len(self._inventory)
            logger.debug(f"DEBUG: Flushing {count} items to database")
            
            if not count:
                logger.debug("DEBUG: Nothing to flush")
                return
                
            with SqlBulkExecute() as sql:
                for objectHash, value in self._inventory.items():
                    tag = value[4]
                    if six.PY3 and isinstance(tag, str):
                        tag = tag.encode("utf-8", "replace")
                    value = [
                        value[0], 
                        value[1], 
                        sqlite3.Binary(value[2]), 
                        value[3], 
                        sqlite3.Binary(tag)
                    ]
                    sql.execute(
                        'INSERT INTO inventory VALUES (?, ?, ?, ?, ?, ?)',
                        sqlite3.Binary(objectHash), *value)
                        
                self._inventory.clear()
                logger.debug("DEBUG: Flush completed successfully")

    def clean(self):
        """Free memory / perform garbage collection"""
        with self.lock:
            cutoff_time = int(time.time()) - (60 * 60 * 3)
            logger.debug(f"DEBUG: Cleaning inventory - removing items before {cutoff_time}")
            
            # Clean database
            deleted_count = sqlExecute(
                'DELETE FROM inventory WHERE expirestime<?',
                cutoff_time)
                
            # Clean memory caches
            self._objects.clear()
            for objectHash, value in self._inventory.items():
                self._objects[objectHash] = value.stream
                
            logger.debug(f"DEBUG: Clean completed - {deleted_count} expired items removed from database")
