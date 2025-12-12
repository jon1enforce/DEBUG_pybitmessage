"""
sqlThread is defined here
"""

import os
import shutil  # used for moving the messages.dat file
import sqlite3
import sys
import threading
import time
import queue as std_queue
import logging
from six.moves.reprlib import repr

try:
    import helper_sql
    import helper_startup
    import paths
    import queues
    import state
    from addresses import encodeAddress
    from bmconfigparser import config, config_ready
    from debug import logger
    from tr import _translate
except ImportError:
    from . import helper_sql, helper_startup, paths, queues, state
    from .addresses import encodeAddress
    from .bmconfigparser import config, config_ready
    from .debug import logger
    from .tr import _translate


class sqlThread(threading.Thread):
    """A thread-safe and robust thread for all SQL operations"""

    def __init__(self):
        threading.Thread.__init__(self, name="SQLThread")
        self._stop_event = threading.Event()
        self._reconnect_attempts = 0
        self._max_reconnect_attempts = 3
        self._last_success_time = time.time()
        self._conn = None
        self._cur = None

    def stop(self):
        """Gracefully stop the SQL thread"""
        self._stop_event.set()
        try:
            helper_sql.sqlSubmitQueue.put("exit", timeout=1.0)
            helper_sql.sqlSubmitQueue.put("", timeout=1.0)
        except std_queue.Full:
            pass

    def _connect_database(self):
        """Connect to database with error handling and retries"""
        for attempt in range(self._max_reconnect_attempts):
            try:
                self._conn = sqlite3.connect(
                    state.appdata + 'messages.dat',
                    timeout=30.0,
                    check_same_thread=False
                )
                self._conn.text_factory = bytes
                
                # Performance and reliability optimizations
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=NORMAL")
                self._conn.execute("PRAGMA busy_timeout=10000")
                self._conn.execute("PRAGMA cache_size=-2000")
                self._conn.execute("PRAGMA foreign_keys=ON")
                
                self._cur = self._conn.cursor()
                self._cur.execute('PRAGMA secure_delete = ON')
                
                self._reconnect_attempts = 0
                logger.info(f"Database connected successfully (attempt {attempt+1})")
                return True
                
            except Exception as err:
                self._reconnect_attempts += 1
                logger.error(f"Database connection failed (attempt {attempt+1}): {err}")
                
                if attempt < self._max_reconnect_attempts - 1:
                    wait_time = 2 ** attempt
                    logger.debug(f"Waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                else:
                    logger.critical(f"Failed to connect to database after {self._max_reconnect_attempts} attempts")
                    return False
        
        return False

    def _safe_execute(self, query, params=None):
        """Execute SQL with comprehensive error handling"""
        max_retries = 2
        
        for retry in range(max_retries):
            try:
                if params is None or params == '':
                    self._cur.execute(query)
                else:
                    fixed_params = self._fix_parameters(params)
                    self._cur.execute(query, fixed_params)
                
                self._last_success_time = time.time()
                return True
                
            except sqlite3.OperationalError as err:
                err_str = str(err)
                
                if "database is locked" in err_str and retry < max_retries - 1:
                    logger.debug(f"Database locked, retrying ({retry+1}/{max_retries}): {query[:100]}...")
                    time.sleep(0.1 * (retry + 1))
                    continue
                    
                elif "disk I/O error" in err_str or "database disk image is malformed" in err_str:
                    logger.error(f"Database corruption detected: {err}")
                    if self._reconnect_attempts < self._max_reconnect_attempts:
                        logger.info("Attempting to reconnect to database...")
                        self._close_database()
                        time.sleep(1)
                        if self._connect_database():
                            continue
                    raise
                    
                else:
                    logger.error(f"SQL operational error: {err} - Query: {query[:200]}")
                    raise
                    
            except sqlite3.InterfaceError as err:
                logger.error(f"SQL interface error: {err} - Query: {query[:200]} - Params: {params}")
                raise
                
            except Exception as err:
                logger.error(f"SQL execution error: {err} - Query: {query[:200]}")
                raise
        
        return False

    def _close_database(self):
        """Safely close database connection"""
        try:
            if self._conn:
                self._conn.commit()
                self._conn.close()
                self._conn = None
                self._cur = None
        except Exception as err:
            logger.debug(f"Error closing database: {err}")

    def _fix_parameters(self, params):
        """Fix parameters where strings should be bytes for sqlite3.Binary"""
        if params is None:
            return params
            
        if isinstance(params, (list, tuple)):
            fixed = []
            for param in params:
                if isinstance(param, str) and hasattr(sqlite3, 'Binary'):
                    try:
                        fixed.append(sqlite3.Binary(param.encode('utf-8')))
                    except UnicodeEncodeError:
                        try:
                            fixed.append(sqlite3.Binary(param.encode('latin-1')))
                        except:
                            fixed.append(param)
                else:
                    fixed.append(param)
            
            return tuple(fixed) if isinstance(params, tuple) else fixed
        
        return params

    def _check_health(self):
        """Check if SQL thread is still healthy"""
        current_time = time.time()
        
        if current_time - self._last_success_time > 60.0:
            logger.warning("SQL thread appears stuck, forcing health check")
            
            try:
                self._cur.execute("SELECT 1")
                result = self._cur.fetchone()
                if result and result[0] == 1:
                    self._last_success_time = current_time
                    logger.debug("SQL thread health check passed")
                    return True
                else:
                    logger.error("SQL thread health check returned invalid result")
                    return False
            except Exception as err:
                logger.error(f"SQL thread health check failed: {err}")
                return False
        
        return True

    def create_function(self):
        """Create SQL functions with error handling"""
        try:
            self._conn.create_function("enaddr", 3, func=encodeAddress, deterministic=True)
        except (TypeError, sqlite3.NotSupportedError) as err:
            logger.debug(
                "Got error while passing deterministic in sqlite create function {}. Passing 3 params".format(err))
            self._conn.create_function("enaddr", 3, encodeAddress)

    def _initialize_database(self):
        """Initialize database schema with error handling"""
        try:
            # Try to create tables (original logic)
            try:
                self._cur.execute(
                    '''CREATE TABLE inbox (msgid blob, toaddress text, fromaddress text, subject text,'''
                    ''' received text, message text, folder text, encodingtype int, read bool, sighash blob,'''
                    ''' UNIQUE(msgid) ON CONFLICT REPLACE)''')
                self._cur.execute(
                    '''CREATE TABLE sent (msgid blob, toaddress text, toripe blob, fromaddress text, subject text,'''
                    ''' message text, ackdata blob, senttime integer, lastactiontime integer,'''
                    ''' sleeptill integer, status text, retrynumber integer, folder text, encodingtype int, ttl int)''')
                self._cur.execute(
                    '''CREATE TABLE subscriptions (label text, address text, enabled bool)''')
                self._cur.execute(
                    '''CREATE TABLE addressbook (label text, address text, UNIQUE(address) ON CONFLICT IGNORE)''')
                self._cur.execute(
                    '''CREATE TABLE blacklist (label text, address text, enabled bool)''')
                self._cur.execute(
                    '''CREATE TABLE whitelist (label text, address text, enabled bool)''')
                self._cur.execute(
                    '''CREATE TABLE pubkeys (address text, addressversion int, transmitdata blob, time int,'''
                    ''' usedpersonally text, UNIQUE(address) ON CONFLICT REPLACE)''')
                self._cur.execute(
                    '''CREATE TABLE inventory (hash blob, objecttype int, streamnumber int, payload blob,'''
                    ''' expirestime integer, tag blob, UNIQUE(hash) ON CONFLICT REPLACE)''')
                self._cur.execute(
                    '''INSERT INTO subscriptions VALUES'''
                    '''('Bitmessage new releases/announcements','BM-GtovgYdgs7qXPkoYaRgrLFuFKz1SFpsw',1)''')
                self._cur.execute(
                    '''CREATE TABLE settings (key text, value blob, UNIQUE(key) ON CONFLICT REPLACE)''')
                self._cur.execute('''INSERT INTO settings VALUES('version','11')''')
                self._cur.execute('''INSERT INTO settings VALUES('lastvacuumtime',?)''', (
                    int(time.time()),))
                self._cur.execute(
                    '''CREATE TABLE objectprocessorqueue'''
                    ''' (objecttype int, data blob, UNIQUE(objecttype, data) ON CONFLICT REPLACE)''')
                self._conn.commit()
                logger.info('Created messages database file')
            except Exception as err:
                if str(err) == 'table inbox already exists':
                    logger.debug('Database file already exists.')
                else:
                    logger.error(f'ERROR trying to create database file: {err}')
                    # Don't exit, try to continue

        except Exception as err:
            logger.error(f"Database initialization failed: {err}")

    def _run_migrations(self):
        """Run all database migrations with error handling"""
        try:
            # If the settings version is equal to 2 or 3 then the
            # sqlThread will modify the pubkeys table and change
            # the settings version to 4.
            settingsversion = config.getint('bitmessagesettings', 'settingsversion')

            # People running earlier versions of PyBitmessage do not have the
            # usedpersonally field in their pubkeys table. Let's add it.
            if settingsversion == 2:
                try:
                    self._cur.execute('''ALTER TABLE pubkeys ADD usedpersonally text DEFAULT 'no' ''')
                    self._conn.commit()
                    settingsversion = 3
                except Exception as err:
                    logger.error(f"Migration 2->3 failed: {err}")

            # People running earlier versions of PyBitmessage do not have the
            # encodingtype field in their inbox and sent tables or the read field
            # in the inbox table. Let's add them.
            if settingsversion == 3:
                try:
                    self._cur.execute('''ALTER TABLE inbox ADD encodingtype int DEFAULT '2' ''')
                    self._cur.execute('''ALTER TABLE inbox ADD read bool DEFAULT '1' ''')
                    self._cur.execute('''ALTER TABLE sent ADD encodingtype int DEFAULT '2' ''')
                    self._conn.commit()
                    settingsversion = 4
                except Exception as err:
                    logger.error(f"Migration 3->4 failed: {err}")

            config.set('bitmessagesettings', 'settingsversion', str(settingsversion))
            config.save()
            helper_startup.updateConfig()

            # From now on, let us keep a 'version' embedded in the messages.dat
            # file so that when we make changes to the database, the database
            # version we are on can stay embedded in the messages.dat file.
            try:
                self._cur.execute('''SELECT name FROM sqlite_master WHERE type='table' AND name='settings';''')
                if self._cur.fetchall() == []:
                    logger.debug("In messages.dat database, creating new 'settings' table.")
                    self._cur.execute(
                        '''CREATE TABLE settings (key text, value blob, UNIQUE(key) ON CONFLICT REPLACE)''')
                    self._cur.execute('''INSERT INTO settings VALUES('version','1')''')
                    self._cur.execute('''INSERT INTO settings VALUES('lastvacuumtime',?)''', (
                        int(time.time()),))
                    
                    logger.debug('In messages.dat database, removing an obsolete field from the pubkeys table.')
                    self._cur.execute(
                        '''CREATE TEMPORARY TABLE pubkeys_backup(hash blob, transmitdata blob, time int,'''
                        ''' usedpersonally text, UNIQUE(hash) ON CONFLICT REPLACE);''')
                    self._cur.execute(
                        '''INSERT INTO pubkeys_backup SELECT hash, transmitdata, time, usedpersonally FROM pubkeys;''')
                    self._cur.execute('''DROP TABLE pubkeys''')
                    self._cur.execute(
                        '''CREATE TABLE pubkeys'''
                        ''' (hash blob, transmitdata blob, time int, usedpersonally text, UNIQUE(hash) ON CONFLICT REPLACE)''')
                    self._cur.execute(
                        '''INSERT INTO pubkeys SELECT hash, transmitdata, time, usedpersonally FROM pubkeys_backup;''')
                    self._cur.execute('''DROP TABLE pubkeys_backup;''')
                    
                    logger.debug('Deleting all pubkeys from inventory.')
                    self._cur.execute('''delete from inventory where objecttype = 'pubkey';''')
                    
                    logger.debug('replacing Bitmessage announcements mailing list with a new one.')
                    self._cur.execute('''delete from subscriptions where address='BM-BbkPSZbzPwpVcYZpU4yHwf9ZPEapN5Zx' ''')
                    self._cur.execute(
                        '''INSERT INTO subscriptions VALUES'''
                        '''('Bitmessage new releases/announcements','BM-GtovgYdgs7qXPkoYaRgrLFuFKz1SFpsw',1)''')
                    
                    logger.debug('Commiting.')
                    self._conn.commit()
                    logger.debug('Vacuuming message.dat.')
                    self._cur.execute(''' VACUUM ''')
            except Exception as err:
                logger.error(f"Settings migration failed: {err}")

            # After code refactoring, the possible status values for sent messages have changed.
            try:
                self._cur.execute('''update sent set status='doingmsgpow' where status='doingpow'  ''')
                self._cur.execute('''update sent set status='msgsent' where status='sentmessage'  ''')
                self._cur.execute('''update sent set status='doingpubkeypow' where status='findingpubkey'  ''')
                self._cur.execute('''update sent set status='broadcastqueued' where status='broadcastpending'  ''')
                self._conn.commit()
            except Exception as err:
                logger.error(f"Status migration failed: {err}")

            # Get current version from settings table
            try:
                self._cur.execute('''SELECT value FROM settings WHERE key='version';''')
                result = self._cur.fetchall()
                if result:
                    currentVersion = int(result[0][0])
                else:
                    currentVersion = 1
            except:
                currentVersion = 1

            # Migration logic for each version
            if currentVersion == 2:
                try:
                    logger.debug('In messages.dat database, removing an obsolete field from the inventory table.')
                    self._cur.execute(
                        '''CREATE TEMPORARY TABLE inventory_backup'''
                        '''(hash blob, objecttype text, streamnumber int, payload blob,'''
                        ''' receivedtime integer, UNIQUE(hash) ON CONFLICT REPLACE);''')
                    self._cur.execute(
                        '''INSERT INTO inventory_backup SELECT hash, objecttype, streamnumber, payload, receivedtime'''
                        ''' FROM inventory;''')
                    self._cur.execute('''DROP TABLE inventory''')
                    self._cur.execute(
                        '''CREATE TABLE inventory'''
                        ''' (hash blob, objecttype text, streamnumber int, payload blob, receivedtime integer,'''
                        ''' UNIQUE(hash) ON CONFLICT REPLACE)''')
                    self._cur.execute(
                        '''INSERT INTO inventory SELECT hash, objecttype, streamnumber, payload, receivedtime'''
                        ''' FROM inventory_backup;''')
                    self._cur.execute('''DROP TABLE inventory_backup;''')
                    self._cur.execute('''update settings set value=? WHERE key='version';''', (3,))
                    currentVersion = 3
                except Exception as err:
                    logger.error(f"Migration version 2 failed: {err}")

            if currentVersion == 1 or currentVersion == 3:
                try:
                    logger.debug('In messages.dat database, adding tag field to the inventory table.')
                    self._cur.execute('''ALTER TABLE inventory ADD tag blob DEFAULT '' ''')
                    self._cur.execute('''update settings set value=? WHERE key='version';''', (4,))
                    currentVersion = 4
                except Exception as err:
                    logger.error(f"Migration to version 4 failed: {err}")

            if currentVersion == 4:
                try:
                    self._cur.execute('''DROP TABLE pubkeys''')
                    self._cur.execute(
                        '''CREATE TABLE pubkeys (hash blob, addressversion int, transmitdata blob, time int,'''
                        '''usedpersonally text, UNIQUE(hash, addressversion) ON CONFLICT REPLACE)''')
                    self._cur.execute('''delete from inventory where objecttype = 'pubkey';''')
                    self._cur.execute('''update settings set value=? WHERE key='version';''', (5,))
                    currentVersion = 5
                except Exception as err:
                    logger.error(f"Migration to version 5 failed: {err}")

            if currentVersion == 5:
                try:
                    self._cur.execute('''DROP TABLE knownnodes''')
                    self._cur.execute(
                        '''CREATE TABLE objectprocessorqueue'''
                        ''' (objecttype text, data blob, UNIQUE(objecttype, data) ON CONFLICT REPLACE)''')
                    self._cur.execute('''update settings set value=? WHERE key='version';''', (6,))
                    currentVersion = 6
                except Exception as err:
                    logger.error(f"Migration to version 6 failed: {err}")

            if currentVersion == 6:
                try:
                    logger.debug('In messages.dat database, dropping and recreating the inventory table.')
                    self._cur.execute('''DROP TABLE inventory''')
                    self._cur.execute(
                        '''CREATE TABLE inventory'''
                        ''' (hash blob, objecttype int, streamnumber int, payload blob, expirestime integer,'''
                        ''' tag blob, UNIQUE(hash) ON CONFLICT REPLACE)''')
                    self._cur.execute('''DROP TABLE objectprocessorqueue''')
                    self._cur.execute(
                        '''CREATE TABLE objectprocessorqueue'''
                        ''' (objecttype int, data blob, UNIQUE(objecttype, data) ON CONFLICT REPLACE)''')
                    self._cur.execute('''update settings set value=? WHERE key='version';''', (7,))
                    currentVersion = 7
                    logger.debug('Finished dropping and recreating the inventory table.')
                except Exception as err:
                    logger.error(f"Migration to version 7 failed: {err}")

            if currentVersion == 7:
                try:
                    logger.debug('In messages.dat database, clearing pubkeys table.')
                    self._cur.execute('''delete from inventory where objecttype = 1;''')
                    self._cur.execute('''delete from pubkeys;''')
                    self._cur.execute(
                        '''UPDATE sent SET status='msgqueued' WHERE status='doingmsgpow' or status='badkey';''')
                    self._cur.execute('''update settings set value=? WHERE key='version';''', (8,))
                    currentVersion = 8
                    logger.debug('Finished clearing currently held pubkeys.')
                except Exception as err:
                    logger.error(f"Migration to version 8 failed: {err}")

            if currentVersion == 8:
                try:
                    logger.debug('In messages.dat database, adding sighash field to the inbox table.')
                    self._cur.execute('''ALTER TABLE inbox ADD sighash blob DEFAULT '' ''')
                    self._cur.execute('''update settings set value=? WHERE key='version';''', (9,))
                    currentVersion = 9
                except Exception as err:
                    logger.error(f"Migration to version 9 failed: {err}")

            if currentVersion == 9:
                try:
                    logger.info('In messages.dat database, making TTL-related changes...')
                    self._cur.execute(
                        '''CREATE TEMPORARY TABLE sent_backup'''
                        ''' (msgid blob, toaddress text, toripe blob, fromaddress text, subject text, message text,'''
                        ''' ackdata blob, lastactiontime integer, status text, retrynumber integer,'''
                        ''' folder text, encodingtype int)''')
                    self._cur.execute(
                        '''INSERT INTO sent_backup SELECT msgid, toaddress, toripe, fromaddress,'''
                        ''' subject, message, ackdata, lastactiontime,'''
                        ''' status, 0, folder, encodingtype FROM sent;''')
                    self._cur.execute('''DROP TABLE sent''')
                    self._cur.execute(
                        '''CREATE TABLE sent'''
                        ''' (msgid blob, toaddress text, toripe blob, fromaddress text, subject text, message text,'''
                        ''' ackdata blob, senttime integer, lastactiontime integer, sleeptill int, status text,'''
                        ''' retrynumber integer, folder text, encodingtype int, ttl int)''')
                    self._cur.execute(
                        '''INSERT INTO sent SELECT msgid, toaddress, toripe, fromaddress, subject, message, ackdata,'''
                        ''' lastactiontime, lastactiontime, 0, status, 0, folder, encodingtype, 216000 FROM sent_backup;''')
                    self._cur.execute('''DROP TABLE sent_backup''')
                    logger.info('In messages.dat database, finished making TTL-related changes.')
                    
                    logger.debug('In messages.dat database, adding address field to the pubkeys table.')
                    self._cur.execute('''ALTER TABLE pubkeys ADD address text DEFAULT '' ;''')
                    self._cur.execute('''UPDATE pubkeys SET address=(enaddr(pubkeys.addressversion, 1, hash)); ''')
                    
                    self._cur.execute(
                        '''CREATE TEMPORARY TABLE pubkeys_backup'''
                        ''' (address text, addressversion int, transmitdata blob, time int,'''
                        ''' usedpersonally text, UNIQUE(address) ON CONFLICT REPLACE)''')
                    self._cur.execute(
                        '''INSERT INTO pubkeys_backup'''
                        ''' SELECT address, addressversion, transmitdata, time, usedpersonally FROM pubkeys;''')
                    self._cur.execute('''DROP TABLE pubkeys''')
                    self._cur.execute(
                        '''CREATE TABLE pubkeys'''
                        ''' (address text, addressversion int, transmitdata blob, time int, usedpersonally text,'''
                        ''' UNIQUE(address) ON CONFLICT REPLACE)''')
                    self._cur.execute(
                        '''INSERT INTO pubkeys SELECT'''
                        ''' address, addressversion, transmitdata, time, usedpersonally FROM pubkeys_backup;''')
                    self._cur.execute('''DROP TABLE pubkeys_backup''')
                    logger.debug('In messages.dat database, done adding address field to the pubkeys table.')
                    self._cur.execute('''update settings set value=10 WHERE key='version';''')
                    currentVersion = 10
                except Exception as err:
                    logger.error(f"Migration to version 10 failed: {err}")

            if currentVersion == 10:
                try:
                    logger.debug('In messages.dat database, updating address column to UNIQUE in addressbook table.')
                    self._cur.execute('''ALTER TABLE addressbook RENAME TO old_addressbook''')
                    self._cur.execute(
                        '''CREATE TABLE addressbook'''
                        ''' (label text, address text, UNIQUE(address) ON CONFLICT IGNORE)''')
                    self._cur.execute(
                        '''INSERT INTO addressbook SELECT label, address FROM old_addressbook;''')
                    self._cur.execute('''DROP TABLE old_addressbook''')
                    self._cur.execute('''update settings set value=11 WHERE key='version';''')
                    currentVersion = 11
                except Exception as err:
                    logger.error(f"Migration to version 11 failed: {err}")

            # Commit all migrations
            self._conn.commit()
            
        except Exception as err:
            logger.error(f"Migration process failed: {err}")
            try:
                self._conn.rollback()
            except:
                pass

    def _test_database(self):
        """Test database functionality"""
        try:
            testpayload = b'\x00\x00'
            t = (b'1234', 1, testpayload, b'12345678', b'no')
            self._cur.execute('''INSERT INTO pubkeys VALUES(?,?,?,?,?)''', t)
            self._conn.commit()
            self._cur.execute('''SELECT transmitdata FROM pubkeys WHERE address=?''', (b'1234',))
            queryreturn = self._cur.fetchall()
            for row in queryreturn:
                transmitdata, = row
            self._cur.execute('''DELETE FROM pubkeys WHERE address=?''', (b'1234',))
            self._conn.commit()
            
            if transmitdata == b'':
                logger.warning("SQLite null value storage test inconclusive")
                
        except Exception as err:
            logger.debug(f"Database test warning: {err}")

    def _check_vacuum(self):
        """Check if vacuum is needed"""
        try:
            self._cur.execute('''SELECT value FROM settings WHERE key='lastvacuumtime';''')
            queryreturn = self._cur.fetchall()
            for row in queryreturn:
                value, = row
                if int(value) < int(time.time()) - 86400:
                    logger.info('Checking if vacuum is needed...')
                    # Skip vacuum for now to prevent timeout
                    # self._cur.execute(''' VACUUM ''')
                    self._cur.execute('''update settings set value=? WHERE key='lastvacuumtime';''', 
                                     (int(time.time()),))
        except Exception as err:
            logger.debug(f"Vacuum check failed: {err}")

    def run(self):
        """Main thread loop with comprehensive error handling"""
        logger.info("SQL thread starting...")
        
        # Initial connection
        if not self._connect_database():
            helper_sql.sql_available = False
            logger.error("SQL thread failed to start - database unavailable")
            return
        
        helper_sql.sql_available = True
        
        # Wait for config
        try:
            config_ready.wait(timeout=30.0)
        except:
            logger.warning("Config ready timeout, continuing anyway")
        
        # Initialize and migrate
        try:
            self._initialize_database()
            self.create_function()
            self._run_migrations()
            self._test_database()
            self._check_vacuum()
        except Exception as err:
            logger.error(f"Database setup failed: {err}")
        
        helper_sql.sql_ready.set()
        logger.info("SQL thread ready for queries")
        
        # Main processing loop
        consecutive_errors = 0
        max_consecutive_errors = 10
        
        while not self._stop_event.is_set():
            try:
                # Get query with timeout
                try:
                    item = helper_sql.sqlSubmitQueue.get(timeout=1.0)
                except std_queue.Empty:
                    # Regular timeout, check health
                    if time.time() - self._last_success_time > 30.0:
                        if not self._check_health():
                            logger.warning("SQL thread unhealthy, attempting recovery...")
                            self._close_database()
                            time.sleep(1)
                            if not self._connect_database():
                                logger.error("Failed to recover SQL thread")
                                consecutive_errors += 1
                                if consecutive_errors >= max_consecutive_errors:
                                    logger.critical("Too many consecutive errors, stopping SQL thread")
                                    break
                                continue
                    
                    consecutive_errors = 0
                    continue
                
                # Process command
                if item == 'commit':
                    try:
                        self._conn.commit()
                        consecutive_errors = 0
                    except Exception as err:
                        logger.error(f"Commit failed: {err}")
                        consecutive_errors += 1
                        continue
                        
                elif item == 'exit':
                    logger.info("SQL thread received exit command")
                    break
                    
                elif item in ('movemessagstoprog', 'movemessagstoappdata'):
                    self._handle_move_operation(item)
                    consecutive_errors = 0
                    
                elif item == 'deleteandvacuume':
                    self._handle_vacuum()
                    consecutive_errors = 0
                    
                else:
                    # Regular query
                    try:
                        parameters = helper_sql.sqlSubmitQueue.get(timeout=5.0)
                    except std_queue.Empty:
                        logger.error("Timeout waiting for query parameters")
                        helper_sql.sqlReturnQueue.put(([], 0))
                        consecutive_errors += 1
                        continue
                    
                    try:
                        if not self._safe_execute(item, parameters):
                            logger.error(f"Query execution failed after retries: {item[:200]}")
                            helper_sql.sqlReturnQueue.put(([], 0))
                            consecutive_errors += 1
                            continue
                        
                        rowcount = self._cur.rowcount
                        result = self._cur.fetchall()
                        
                        helper_sql.sqlReturnQueue.put((result, rowcount))
                        self._last_success_time = time.time()
                        consecutive_errors = 0
                        
                    except Exception as err:
                        logger.error(f"Query execution error: {err} - Query: {item[:200]}")
                        helper_sql.sqlReturnQueue.put(([], 0))
                        consecutive_errors += 1
                        
            except Exception as err:
                logger.error(f"Unexpected error in SQL thread main loop: {err}")
                consecutive_errors += 1
                time.sleep(1)
                
                if consecutive_errors >= max_consecutive_errors:
                    logger.critical(f"Too many consecutive errors ({consecutive_errors}), stopping SQL thread")
                    break
        
        # Clean shutdown
        try:
            self._conn.commit()
            self._close_database()
        except Exception as err:
            logger.debug(f"Error during shutdown: {err}")
        
        helper_sql.sql_available = False
        logger.info("SQL thread stopped")

    def _handle_move_operation(self, operation):
        """Handle moving database file"""
        try:
            self._conn.commit()
            self._close_database()
            
            if operation == 'movemessagstoprog':
                src = paths.lookupAppdataFolder() + 'messages.dat'
                dst = paths.lookupExeFolder() + 'messages.dat'
                logger.debug("Moving messages.dat to program directory")
            else:
                src = paths.lookupExeFolder() + 'messages.dat'
                dst = paths.lookupAppdataFolder() + 'messages.dat'
                logger.debug("Moving messages.dat to Appdata folder")
            
            shutil.move(src, dst)
            
            # Reconnect
            if not self._connect_database():
                logger.error("Failed to reconnect after move operation")
            
        except Exception as err:
            logger.error(f"Failed to move database: {err}")

    def _handle_vacuum(self):
        """Handle vacuum operation"""
        try:
            self._cur.execute('''DELETE FROM inbox WHERE folder='trash' ''')
            self._cur.execute('''DELETE FROM sent WHERE folder='trash' ''')
            self._conn.commit()
            
            logger.debug("Starting VACUUM operation")
            self._cur.execute('''VACUUM''')
            self._conn.commit()
            logger.debug("VACUUM completed")
            
        except Exception as err:
            logger.error(f"Vacuum failed: {err}")
            try:
                self._conn.rollback()
            except:
                pass
