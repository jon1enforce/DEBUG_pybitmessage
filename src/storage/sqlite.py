"""
Sqlite Inventory
"""
import six
import sqlite3
import time
import logging
from threading import RLock

from helper_sql import SqlBulkExecute, sqlExecute, sqlQuery
from .storage import InventoryItem, InventoryStorage

logger = logging.getLogger('sqlite')


class SqliteInventory(InventoryStorage):
    """Inventory using SQLite"""
    def __init__(self):
        super(SqliteInventory, self).__init__()
        # of objects (like msg payloads and pubkey payloads)
        # Does not include protocol headers (the first 24 bytes of each packet).
        self._inventory = {}
        # cache for existing objects, used for quick lookups if we have an object.
        # This is used for example whenever we receive an inv message from a peer
        # to check to see what items are new to us.
        # We don't delete things out of it; instead,
        # the singleCleaner thread clears and refills it.
        self._objects = {}
        # Guarantees that two receiveDataThreads don't receive
        # and process the same message concurrently
        # (probably sent by a malicious individual)
        self.lock = RLock()

    def __contains__(self, hash_):
        with self.lock:
            # PYTHON 3 KOMPATIBILITÄT: Konvertiere Input zu bytes
            if isinstance(hash_, str):
                hash_bytes = hash_.encode('utf-8')
            elif isinstance(hash_, int):
                hash_bytes = hash_.to_bytes(32, 'big') if hash_.bit_length() > 0 else b'\x00' * 32
            else:
                hash_bytes = bytes(hash_)
            
            if hash_bytes in self._objects:
                return True
                
            rows = sqlQuery(
                'SELECT streamnumber FROM inventory WHERE hash=?',
                sqlite3.Binary(hash_bytes))
            if not rows:
                return False
                
            self._objects[hash_bytes] = rows[0][0]
            return True

    def __getitem__(self, hash_):
        with self.lock:
            # PYTHON 3 KOMPATIBILITÄT: Konvertiere Input zu bytes
            if isinstance(hash_, str):
                hash_bytes = hash_.encode('utf-8')
            elif isinstance(hash_, int):
                hash_bytes = hash_.to_bytes(32, 'big') if hash_.bit_length() > 0 else b'\x00' * 32
            else:
                hash_bytes = bytes(hash_)
            
            if hash_bytes in self._inventory:
                return self._inventory[hash_bytes]
                
            rows = sqlQuery(
                'SELECT objecttype, streamnumber, payload, expirestime, tag'
                ' FROM inventory WHERE hash=?', sqlite3.Binary(hash_bytes))
            if not rows:
                raise KeyError(hash_)
                
            # DEBUG: Prüfe ob wir alle Spalten haben
            if len(rows[0]) < 5:
                logger.error("Row has only %d columns, expected 5 for hash %s", 
                           len(rows[0]), hash_bytes[:8].hex() if len(hash_bytes) >= 8 else str(hash_bytes))
                # Versuche, die Tabelle zu prüfen
                table_info = sqlQuery("PRAGMA table_info(inventory)")
                logger.error("Table columns: %s", [col[1] for col in table_info])
                raise KeyError(hash_)
                
            return InventoryItem(*rows[0])

    def __setitem__(self, hash_, value):
        with self.lock:
            value = InventoryItem(*value)
            # PYTHON 3 KOMPATIBILITÄT: Konvertiere Hash zu bytes
            if isinstance(hash_, str):
                hash_bytes = hash_.encode('utf-8')
            elif isinstance(hash_, int):
                hash_bytes = hash_.to_bytes(32, 'big') if hash_.bit_length() > 0 else b'\x00' * 32
            else:
                hash_bytes = bytes(hash_)
                
            self._inventory[hash_bytes] = value
            self._objects[hash_bytes] = value.stream

    def __delitem__(self, hash_):
        raise NotImplementedError

    def __iter__(self):
        with self.lock:
            # PYTHON 3 KOMPATIBILITÄT: keys() gibt view zurück
            hashes = list(self._inventory.keys())
            
            # KORREKTUR: row[0] kann bytes, string oder integer sein
            for row in sqlQuery('SELECT hash FROM inventory'):
                hash_value = row[0]
                hashes.append(self._convert_to_bytes(hash_value))
                
            return iter(hashes)

    def __len__(self):
        with self.lock:
            return len(self._inventory) + sqlQuery(
                'SELECT count(*) FROM inventory')[0][0]

    def by_type_and_tag(self, objectType, tag=None):
        """
        Get all inventory items of certain *objectType*
        with *tag* if given.
        """
        with self.lock:
            # Zuerst aus dem Cache
            values = [
                value for value in self._inventory.values()
                if value.type == objectType
                and (tag is None or value.tag == tag)
            ]
            
            # Dann aus der Datenbank - KORREKTUR: Alle Spalten selektieren
            query = 'SELECT objecttype, streamnumber, payload, expirestime, tag FROM inventory WHERE objecttype=?'
            params = [objectType]
            
            if tag:
                query += ' AND tag=?'
                # KORREKTUR: Tag in bytes konvertieren falls nötig
                if isinstance(tag, str):
                    params.append(tag.encode('utf-8'))
                else:
                    params.append(sqlite3.Binary(bytes(tag)))
            
            db_rows = sqlQuery(query, *params)
            
            # DEBUG bei Problemen
            if db_rows and len(db_rows) > 0 and len(db_rows[0]) < 5:
                logger.error("by_type_and_tag: Row has only %d columns, expected 5", len(db_rows[0]))
                logger.error("First row: %s", db_rows[0])
                # Zeige alle Spaltennamen
                table_info = sqlQuery("PRAGMA table_info(inventory)")
                logger.error("Table columns: %s", [col[1] for col in table_info])
            
            # Verarbeite die Rows korrekt
            for row in db_rows:
                if len(row) >= 5:
                    # Erstelle InventoryItem aus den 5 Spalten
                    values.append(InventoryItem(row[0], row[1], row[2], row[3], row[4]))
                else:
                    logger.error("Skipping invalid row with only %d columns in by_type_and_tag", len(row))
            
            return values

    def unexpired_hashes_by_stream(self, stream):
        """Return unexpired inventory vectors filtered by stream"""
        with self.lock:
            t = int(time.time())
            # PYTHON 3 KOMPATIBILITÄT: items() gibt view zurück
            hashes = [
                x for x, value in self._inventory.items()
                if value.stream == stream and value.expires > t
            ]
            
            # KORREKTUR: row[0] kann bytes, string oder integer sein!
            query_result = sqlQuery(
                'SELECT hash FROM inventory WHERE streamnumber=? AND expirestime>?', 
                stream, t
            )
            
            for row in query_result:
                hash_value = row[0]
                hashes.append(self._convert_to_bytes(hash_value))
            
            return hashes

    def flush(self):
        """Flush cache"""
        with self.lock:
            # If you use both the inventoryLock and the sqlLock,
            # always use the inventoryLock OUTSIDE of the sqlLock.
            with SqlBulkExecute() as sql:
                for objectHash, value in self._inventory.items():
                    tag = value[4]
                    if six.PY3 and isinstance(tag, str):
                        tag = tag.encode("utf-8", "replace")
                    elif isinstance(tag, memoryview):
                        tag = bytes(tag)
                        
                    value = [value[0], value[1], sqlite3.Binary(value[2]), value[3], sqlite3.Binary(tag)]
                    sql.execute(
                        'INSERT INTO inventory VALUES (?, ?, ?, ?, ?, ?)',
                        sqlite3.Binary(objectHash), *value)
                self._inventory.clear()

    def clean(self):
        """Free memory / perform garbage collection"""
        with self.lock:
            sqlExecute(
                'DELETE FROM inventory WHERE expirestime<?',
                int(time.time()) - (60 * 60 * 3))
            self._objects.clear()
            for objectHash, value in self._inventory.items():
                self._objects[objectHash] = value.stream
    
    # HILFSMETHODE: Konvertiere beliebigen Typ zu bytes
    def _convert_to_bytes(self, value):
        """Convert any value to bytes for hash storage"""
        if isinstance(value, bytes):
            return value
        elif isinstance(value, int):
            # Integer zu bytes konvertieren (wahrscheinlich 32-bit)
            if value.bit_length() > 0:
                # Berechne benötigte Bytes (mindestens 1, maximal 32)
                byte_length = max(1, (value.bit_length() + 7) // 8)
                return value.to_bytes(byte_length, 'big')
            else:
                return b'\x00' * 32
        elif isinstance(value, str):
            # String zu bytes konvertieren
            return value.encode('utf-8')
        elif isinstance(value, memoryview):
            # memoryview zu bytes
            return bytes(value)
        else:
            # Versuche generische Konvertierung
            try:
                return bytes(value)
            except:
                logger.error("Cannot convert to bytes: type=%s, value=%s", type(value), value)
                # Fallback: leeres bytes
                return b''
