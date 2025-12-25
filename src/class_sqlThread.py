"""
sqlThread is defined here
"""

import os
import shutil  # used for moving the messages.dat file
import sqlite3
import sys
import threading
import time
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
    """A thread for all SQL operations"""

    def __init__(self):
        threading.Thread.__init__(self, name="SQL")

    def run(self):  # pylint: disable=too-many-locals, too-many-branches, too-many-statements
        """Process SQL queries from `.helper_sql.sqlSubmitQueue`"""
        import traceback
        
        helper_sql.sql_available = True
        config_ready.wait()
        
        try:
            self.conn = sqlite3.connect(state.appdata + 'messages.dat', detect_types=sqlite3.PARSE_DECLTYPES)
            self.conn.text_factory = str
            self.cur = self.conn.cursor()

            self.cur.execute('PRAGMA secure_delete = true')

            # call create_function for encode address
            self.create_function()

            try:
                self.cur.execute(
                    '''CREATE TABLE inbox (msgid blob, toaddress text, fromaddress text, subject text,'''
                    ''' received text, message text, folder text, encodingtype int, read bool, sighash blob,'''
                    ''' UNIQUE(msgid) ON CONFLICT REPLACE)''')
                self.cur.execute(
                    '''CREATE TABLE sent (msgid blob, toaddress text, toripe blob, fromaddress text, subject text,'''
                    ''' message text, ackdata blob, senttime integer, lastactiontime integer,'''
                    ''' sleeptill integer, status text, retrynumber integer, folder text, encodingtype int, ttl int)''')
                self.cur.execute(
                    '''CREATE TABLE subscriptions (label text, address text, enabled bool)''')
                self.cur.execute(
                    '''CREATE TABLE addressbook (label text, address text, UNIQUE(address) ON CONFLICT IGNORE)''')
                self.cur.execute(
                    '''CREATE TABLE blacklist (label text, address text, enabled bool)''')
                self.cur.execute(
                    '''CREATE TABLE whitelist (label text, address text, enabled bool)''')
                self.cur.execute(
                    '''CREATE TABLE pubkeys (address text, addressversion int, transmitdata blob, time int,'''
                    ''' usedpersonally text, UNIQUE(address) ON CONFLICT REPLACE)''')
                self.cur.execute(
                    '''CREATE TABLE inventory (hash blob, objecttype int, streamnumber int, payload blob,'''
                    ''' expirestime integer, tag blob, UNIQUE(hash) ON CONFLICT REPLACE)''')
                self.cur.execute(
                    '''INSERT INTO subscriptions VALUES'''
                    '''('Bitmessage new releases/announcements','BM-GtovgYdgs7qXPkoYaRgrLFuFKz1SFpsw',1)''')
                self.cur.execute(
                    '''CREATE TABLE settings (key text, value blob, UNIQUE(key) ON CONFLICT REPLACE)''')
                self.cur.execute('''INSERT INTO settings VALUES('version','11')''')
                self.cur.execute('''INSERT INTO settings VALUES('lastvacuumtime',?)''', (
                    int(time.time()),))
                self.cur.execute(
                    '''CREATE TABLE objectprocessorqueue'''
                    ''' (objecttype int, data blob, UNIQUE(objecttype, data) ON CONFLICT REPLACE)''')
                self.conn.commit()
                logger.info('Created messages database file')
            except Exception as err:
                if str(err) == 'table inbox already exists':
                    logger.debug('Database file already exists.')
                else:
                    logger.error('ERROR trying to create database file (message.dat). Error message: %s', str(err))
                    # Don't exit abruptly, just return and let the thread die gracefully
                    helper_sql.sql_available = False
                    return

            # If the settings version is equal to 2 or 3 then the
            # sqlThread will modify the pubkeys table and change
            # the settings version to 4.
            settingsversion = config.getint(
                'bitmessagesettings', 'settingsversion')

            # People running earlier versions of PyBitmessage do not have the
            # usedpersonally field in their pubkeys table. Let's add it.
            if settingsversion == 2:
                item = '''ALTER TABLE pubkeys ADD usedpersonally text DEFAULT 'no' '''
                parameters = ''
                self.cur.execute(item, parameters)
                self.conn.commit()

                settingsversion = 3

            # People running earlier versions of PyBitmessage do not have the
            # encodingtype field in their inbox and sent tables or the read field
            # in the inbox table. Let's add them.
            if settingsversion == 3:
                item = '''ALTER TABLE inbox ADD encodingtype int DEFAULT '2' '''
                parameters = ''
                self.cur.execute(item, parameters)

                item = '''ALTER TABLE inbox ADD read bool DEFAULT '1' '''
                parameters = ''
                self.cur.execute(item, parameters)

                item = '''ALTER TABLE sent ADD encodingtype int DEFAULT '2' '''
                parameters = ''
                self.cur.execute(item, parameters)
                self.conn.commit()

                settingsversion = 4

            config.set(
                'bitmessagesettings', 'settingsversion', str(settingsversion))
            config.save()

            helper_startup.updateConfig()

            # From now on, let us keep a 'version' embedded in the messages.dat
            # file so that when we make changes to the database, the database
            # version we are on can stay embedded in the messages.dat file. Let us
            # check to see if the settings table exists yet.
            item = '''SELECT name FROM sqlite_master WHERE type='table' AND name='settings';'''
            parameters = ''
            self.cur.execute(item, parameters)
            if self.cur.fetchall() == []:
                # The settings table doesn't exist. We need to make it.
                logger.debug(
                    "In messages.dat database, creating new 'settings' table.")
                self.cur.execute(
                    '''CREATE TABLE settings (key text, value blob, UNIQUE(key) ON CONFLICT REPLACE)''')
                self.cur.execute('''INSERT INTO settings VALUES('version','1')''')
                self.cur.execute('''INSERT INTO settings VALUES('lastvacuumtime',?)''', (
                    int(time.time()),))
                logger.debug('In messages.dat database, removing an obsolete field from the pubkeys table.')
                self.cur.execute(
                    '''CREATE TEMPORARY TABLE pubkeys_backup(hash blob, transmitdata blob, time int,'''
                    ''' usedpersonally text, UNIQUE(hash) ON CONFLICT REPLACE);''')
                self.cur.execute(
                    '''INSERT INTO pubkeys_backup SELECT hash, transmitdata, time, usedpersonally FROM pubkeys;''')
                self.cur.execute('''DROP TABLE pubkeys''')
                self.cur.execute(
                    '''CREATE TABLE pubkeys'''
                    ''' (hash blob, transmitdata blob, time int, usedpersonally text, UNIQUE(hash) ON CONFLICT REPLACE)''')
                self.cur.execute(
                    '''INSERT INTO pubkeys SELECT hash, transmitdata, time, usedpersonally FROM pubkeys_backup;''')
                self.cur.execute('''DROP TABLE pubkeys_backup;''')
                logger.debug(
                    'Deleting all pubkeys from inventory.'
                    ' They will be redownloaded and then saved with the correct times.')
                self.cur.execute(
                    '''delete from inventory where objecttype = 'pubkey';''')
                logger.debug('replacing Bitmessage announcements mailing list with a new one.')
                self.cur.execute(
                    '''delete from subscriptions where address='BM-BbkPSZbzPwpVcYZpU4yHwf9ZPEapN5Zx' ''')
                self.cur.execute(
                    '''INSERT INTO subscriptions VALUES'''
                    '''('Bitmessage new releases/announcements','BM-GtovgYdgs7qXPkoYaRgrLFuFKz1SFpsw',1)''')
                logger.debug('Commiting.')
                self.conn.commit()
                logger.debug('Vacuuming message.dat. You might notice that the file size gets much smaller.')
                self.cur.execute(''' VACUUM ''')

            # After code refactoring, the possible status values for sent messages
            # have changed.
            self.cur.execute(
                '''update sent set status=? where status=?''', ('doingmsgpow', 'doingpow'))
            self.cur.execute(
                '''update sent set status=? where status=?''', ('msgsent', 'sentmessage'))
            self.cur.execute(
                '''update sent set status=? where status=?''', ('doingpubkeypow', 'findingpubkey'))
            self.cur.execute(
                '''update sent set status=? where status=?''', ('broadcastqueued', 'broadcastpending'))
            self.conn.commit()

            # Let's get rid of the first20bytesofencryptedmessage field in
            # the inventory table.
            item = '''SELECT value FROM settings WHERE key='version';'''
            parameters = ''
            self.cur.execute(item, parameters)
            if int(self.cur.fetchall()[0][0]) == 2:
                logger.debug(
                    'In messages.dat database, removing an obsolete field from'
                    ' the inventory table.')
                self.cur.execute(
                    '''CREATE TEMPORARY TABLE inventory_backup'''
                    '''(hash blob, objecttype text, streamnumber int, payload blob,'''
                    ''' receivedtime integer, UNIQUE(hash) ON CONFLICT REPLACE);''')
                self.cur.execute(
                    '''INSERT INTO inventory_backup SELECT hash, objecttype, streamnumber, payload, receivedtime'''
                    ''' FROM inventory;''')
                self.cur.execute('''DROP TABLE inventory''')
                self.cur.execute(
                    '''CREATE TABLE inventory'''
                    ''' (hash blob, objecttype text, streamnumber int, payload blob, receivedtime integer,'''
                    ''' UNIQUE(hash) ON CONFLICT REPLACE)''')
                self.cur.execute(
                    '''INSERT INTO inventory SELECT hash, objecttype, streamnumber, payload, receivedtime'''
                    ''' FROM inventory_backup;''')
                self.cur.execute('''DROP TABLE inventory_backup;''')
                item = '''update settings set value=? WHERE key='version';'''
                parameters = (3,)
                self.cur.execute(item, parameters)

            # Add a new column to the inventory table to store tags.
            item = '''SELECT value FROM settings WHERE key='version';'''
            parameters = ''
            self.cur.execute(item, parameters)
            currentVersion = int(self.cur.fetchall()[0][0])
            if currentVersion == 1 or currentVersion == 3:
                logger.debug(
                    'In messages.dat database, adding tag field to'
                    ' the inventory table.')
                item = '''ALTER TABLE inventory ADD tag blob DEFAULT '' '''
                parameters = ''
                self.cur.execute(item, parameters)
                item = '''update settings set value=? WHERE key='version';'''
                parameters = (4,)
                self.cur.execute(item, parameters)

            # Add a new column to the pubkeys table to store the address version.
            # We're going to trash all of our pubkeys and let them be redownloaded.
            item = '''SELECT value FROM settings WHERE key='version';'''
            parameters = ''
            self.cur.execute(item, parameters)
            currentVersion = int(self.cur.fetchall()[0][0])
            if currentVersion == 4:
                self.cur.execute('''DROP TABLE pubkeys''')
                self.cur.execute(
                    '''CREATE TABLE pubkeys (hash blob, addressversion int, transmitdata blob, time int,'''
                    '''usedpersonally text, UNIQUE(hash, addressversion) ON CONFLICT REPLACE)''')
                self.cur.execute(
                    '''delete from inventory where objecttype = 'pubkey';''')
                item = '''update settings set value=? WHERE key='version';'''
                parameters = (5,)
                self.cur.execute(item, parameters)

            # Add a new table: objectprocessorqueue with which to hold objects
            # that have yet to be processed if the user shuts down Bitmessage.
            item = '''SELECT value FROM settings WHERE key='version';'''
            parameters = ''
            self.cur.execute(item, parameters)
            currentVersion = int(self.cur.fetchall()[0][0])
            if currentVersion == 5:
                self.cur.execute('''DROP TABLE knownnodes''')
                self.cur.execute(
                    '''CREATE TABLE objectprocessorqueue'''
                    ''' (objecttype text, data blob, UNIQUE(objecttype, data) ON CONFLICT REPLACE)''')
                item = '''update settings set value=? WHERE key='version';'''
                parameters = (6,)
                self.cur.execute(item, parameters)

            # changes related to protocol v3
            # In table inventory and objectprocessorqueue, objecttype is now
            # an integer (it was a human-friendly string previously)
            item = '''SELECT value FROM settings WHERE key='version';'''
            parameters = ''
            self.cur.execute(item, parameters)
            currentVersion = int(self.cur.fetchall()[0][0])
            if currentVersion == 6:
                logger.debug(
                    'In messages.dat database, dropping and recreating'
                    ' the inventory table.')
                self.cur.execute('''DROP TABLE inventory''')
                self.cur.execute(
                    '''CREATE TABLE inventory'''
                    ''' (hash blob, objecttype int, streamnumber int, payload blob, expirestime integer,'''
                    ''' tag blob, UNIQUE(hash) ON CONFLICT REPLACE)''')
                self.cur.execute('''DROP TABLE objectprocessorqueue''')
                self.cur.execute(
                    '''CREATE TABLE objectprocessorqueue'''
                    ''' (objecttype int, data blob, UNIQUE(objecttype, data) ON CONFLICT REPLACE)''')
                item = '''update settings set value=? WHERE key='version';'''
                parameters = (7,)
                self.cur.execute(item, parameters)
                logger.debug(
                    'Finished dropping and recreating the inventory table.')

            # The format of data stored in the pubkeys table has changed. Let's
            # clear it, and the pubkeys from inventory, so that they'll
            # be re-downloaded.
            item = '''SELECT value FROM settings WHERE key='version';'''
            parameters = ''
            self.cur.execute(item, parameters)
            currentVersion = int(self.cur.fetchall()[0][0])
            if currentVersion == 7:
                logger.debug(
                    'In messages.dat database, clearing pubkeys table'
                    ' because the data format has been updated.')
                self.cur.execute(
                    '''delete from inventory where objecttype = 1;''')
                self.cur.execute(
                    '''delete from pubkeys;''')
                # Any sending messages for which we *thought* that we had
                # the pubkey must be rechecked.
                self.cur.execute(
                    '''UPDATE sent SET status=? WHERE status=? or status=?''', 
                    ('msgqueued', 'doingmsgpow', 'badkey'))
                query = '''update settings set value=? WHERE key='version';'''
                parameters = (8,)
                self.cur.execute(query, parameters)
                logger.debug('Finished clearing currently held pubkeys.')

            # Add a new column to the inbox table to store the hash of
            # the message signature. We'll use this as temporary message UUID
            # in order to detect duplicates.
            item = '''SELECT value FROM settings WHERE key='version';'''
            parameters = ''
            self.cur.execute(item, parameters)
            currentVersion = int(self.cur.fetchall()[0][0])
            if currentVersion == 8:
                logger.debug(
                    'In messages.dat database, adding sighash field to'
                    ' the inbox table.')
                item = '''ALTER TABLE inbox ADD sighash blob DEFAULT '' '''
                parameters = ''
                self.cur.execute(item, parameters)
                item = '''update settings set value=? WHERE key='version';'''
                parameters = (9,)
                self.cur.execute(item, parameters)

            # We'll also need a `sleeptill` field and a `ttl` field. Also we
            # can combine the pubkeyretrynumber and msgretrynumber into one.

            item = '''SELECT value FROM settings WHERE key='version';'''
            parameters = ''
            self.cur.execute(item, parameters)
            currentVersion = int(self.cur.fetchall()[0][0])
            if currentVersion == 9:
                logger.info(
                    'In messages.dat database, making TTL-related changes:'
                    ' combining the pubkeyretrynumber and msgretrynumber'
                    ' fields into the retrynumber field and adding the'
                    ' sleeptill and ttl fields...')
                self.cur.execute(
                    '''CREATE TEMPORARY TABLE sent_backup'''
                    ''' (msgid blob, toaddress text, toripe blob, fromaddress text, subject text, message text,'''
                    ''' ackdata blob, lastactiontime integer, status text, retrynumber integer,'''
                    ''' folder text, encodingtype int)''')
                self.cur.execute(
                    '''INSERT INTO sent_backup SELECT msgid, toaddress, toripe, fromaddress,'''
                    ''' subject, message, ackdata, lastactiontime,'''
                    ''' status, 0, folder, encodingtype FROM sent;''')
                self.cur.execute('''DROP TABLE sent''')
                self.cur.execute(
                    '''CREATE TABLE sent'''
                    ''' (msgid blob, toaddress text, toripe blob, fromaddress text, subject text, message text,'''
                    ''' ackdata blob, senttime integer, lastactiontime integer, sleeptill int, status text,'''
                    ''' retrynumber integer, folder text, encodingtype int, ttl int)''')
                self.cur.execute(
                    '''INSERT INTO sent SELECT msgid, toaddress, toripe, fromaddress, subject, message, ackdata,'''
                    ''' lastactiontime, lastactiontime, 0, status, 0, folder, encodingtype, 216000 FROM sent_backup;''')
                self.cur.execute('''DROP TABLE sent_backup''')
                logger.info('In messages.dat database, finished making TTL-related changes.')
                logger.debug('In messages.dat database, adding address field to the pubkeys table.')
                # We're going to have to calculate the address for each row in the pubkeys
                # table. Then we can take out the hash field.
                self.cur.execute('''ALTER TABLE pubkeys ADD address text DEFAULT '' ;''')

                # replica for loop to update hashed address
                self.cur.execute('''UPDATE pubkeys SET address=(enaddr(pubkeys.addressversion, 1, hash)); ''')

                # Now we can remove the hash field from the pubkeys table.
                self.cur.execute(
                    '''CREATE TEMPORARY TABLE pubkeys_backup'''
                    ''' (address text, addressversion int, transmitdata blob, time int,'''
                    ''' usedpersonally text, UNIQUE(address) ON CONFLICT REPLACE)''')
                self.cur.execute(
                    '''INSERT INTO pubkeys_backup'''
                    ''' SELECT address, addressversion, transmitdata, time, usedpersonally FROM pubkeys;''')
                self.cur.execute('''DROP TABLE pubkeys''')
                self.cur.execute(
                    '''CREATE TABLE pubkeys'''
                    ''' (address text, addressversion int, transmitdata blob, time int, usedpersonally text,'''
                    ''' UNIQUE(address) ON CONFLICT REPLACE)''')
                self.cur.execute(
                    '''INSERT INTO pubkeys SELECT'''
                    ''' address, addressversion, transmitdata, time, usedpersonally FROM pubkeys_backup;''')
                self.cur.execute('''DROP TABLE pubkeys_backup''')
                logger.debug(
                    'In messages.dat database, done adding address field to the pubkeys table'
                    ' and removing the hash field.')
                self.cur.execute('''update settings set value=10 WHERE key='version';''')

            # Update the address colunm to unique in addressbook table
            item = '''SELECT value FROM settings WHERE key='version';'''
            parameters = ''
            self.cur.execute(item, parameters)
            currentVersion = int(self.cur.fetchall()[0][0])
            if currentVersion == 10:
                logger.debug(
                    'In messages.dat database, updating address column to UNIQUE'
                    ' in the addressbook table.')
                self.cur.execute(
                    '''ALTER TABLE addressbook RENAME TO old_addressbook''')
                self.cur.execute(
                    '''CREATE TABLE addressbook'''
                    ''' (label text, address text, UNIQUE(address) ON CONFLICT IGNORE)''')
                self.cur.execute(
                    '''INSERT INTO addressbook SELECT label, address FROM old_addressbook;''')
                self.cur.execute('''DROP TABLE old_addressbook''')
                self.cur.execute('''update settings set value=11 WHERE key='version';''')

            # Are you hoping to add a new option to the keys.dat file of existing
            # Bitmessage users or modify the SQLite database? Add it right
            # above this line!

            try:
                testpayload = '\x00\x00'
                t = ('1234', 1, testpayload, '12345678', 'no')
                self.cur.execute('''INSERT INTO pubkeys VALUES(?,?,?,?,?)''', t)
                self.conn.commit()
                self.cur.execute(
                    '''SELECT transmitdata FROM pubkeys WHERE address='1234' ''')
                queryreturn = self.cur.fetchall()
                for row in queryreturn:
                    transmitdata, = row
                self.cur.execute('''DELETE FROM pubkeys WHERE address='1234' ''')
                self.conn.commit()
                if transmitdata == '':
                    logger.fatal(
                        'Problem: The version of SQLite you have cannot store Null values.'
                        ' Please download and install the latest revision of your version of Python'
                        ' (for example, the latest Python 2.7 revision) and try again.\n')
                    logger.fatal(
                        'PyBitmessage will now exit very abruptly.'
                        ' You may now see threading errors related to this abrupt exit'
                        ' but the problem you need to solve is related to SQLite.\n\n')
                    helper_sql.sql_available = False
                    return
            except Exception as err:
                if str(err) == 'database or disk is full':
                    logger.fatal(
                        '(While null value test) Alert: Your disk or data storage volume is full.'
                        ' sqlThread will now exit.')
                    queues.UISignalQueue.put((
                        'alert', (
                            _translate(
                                "MainWindow",
                                "Disk full"),
                            _translate(
                                "MainWindow",
                                'Alert: Your disk or data storage volume is full. Bitmessage will now exit.'),
                            True)))
                    helper_sql.sql_available = False
                    return
                else:
                    logger.error('Error during null test: %s', err)

            # Let us check to see the last time we vaccumed the messages.dat file.
            # If it has been more than a month let's do it now.
            item = '''SELECT value FROM settings WHERE key='lastvacuumtime';'''
            parameters = ''
            self.cur.execute(item, parameters)
            queryreturn = self.cur.fetchall()
            for row in queryreturn:
                value, = row
                if int(value) < int(time.time()) - 86400:
                    logger.info('Skipping VACUUM (emergency patch) to prevent startup timeout...')
                    try:
                        self.cur.execute(''' VACUUM ''')
                    except Exception as err:
                        if str(err) == 'database or disk is full':
                            logger.fatal(
                                '(While VACUUM) Alert: Your disk or data storage volume is full.'
                                ' sqlThread will now exit.')
                            queues.UISignalQueue.put((
                                'alert', (
                                    _translate(
                                        "MainWindow",
                                        "Disk full"),
                                    _translate(
                                        "MainWindow",
                                        'Alert: Your disk or data storage volume is full. Bitmessage will now exit.'),
                                    True)))
                            helper_sql.sql_available = False
                            return
                    item = '''update settings set value=? WHERE key='lastvacuumtime';'''
                    parameters = (int(time.time()),)
                    self.cur.execute(item, parameters)

            helper_sql.sql_ready.set()

            while True:
                try:
                    item = helper_sql.sqlSubmitQueue.get()
                    
                    if item == 'commit':
                        try:
                            self.conn.commit()
                        except Exception as err:
                            if str(err) == 'database or disk is full':
                                logger.fatal(
                                    '(While committing) Alert: Your disk or data storage volume is full.'
                                    ' sqlThread will now exit.')
                                queues.UISignalQueue.put((
                                    'alert', (
                                        _translate(
                                            "MainWindow",
                                            "Disk full"),
                                        _translate(
                                            "MainWindow",
                                            'Alert: Your disk or data storage volume is full. Bitmessage will now exit.'),
                                        True)))
                                helper_sql.sql_available = False
                                return
                            else:
                                logger.error('Error during commit: %s', err)
                                # Rollback on error
                                try:
                                    self.conn.rollback()
                                except:
                                    pass
                                
                    elif item == 'exit':
                        try:
                            self.conn.close()
                        except:
                            pass
                        logger.info('sqlThread exiting gracefully.')
                        return
                        
                    elif item == 'movemessagstoprog':
                        logger.debug('the sqlThread is moving the messages.dat file to the local program directory.')
                        try:
                            self.conn.commit()
                            self.conn.close()
                            shutil.move(
                                paths.lookupAppdataFolder() + 'messages.dat', paths.lookupExeFolder() + 'messages.dat')
                            self.conn = sqlite3.connect(paths.lookupExeFolder() + 'messages.dat', detect_types=sqlite3.PARSE_DECLTYPES)
                            self.conn.text_factory = str
                            self.cur = self.conn.cursor()
                        except Exception as err:
                            logger.error('Error moving messages to program dir: %s', err)
                            # Try to reconnect
                            try:
                                self.conn = sqlite3.connect(state.appdata + 'messages.dat')
                                self.conn.text_factory = str
                                self.cur = self.conn.cursor()
                            except Exception as e2:
                                logger.error('Failed to reconnect: %s', e2)
                                helper_sql.sql_available = False
                                return
                                
                    elif item == 'movemessagstoappdata':
                        logger.debug('the sqlThread is moving the messages.dat file to the Appdata folder.')
                        try:
                            self.conn.commit()
                            self.conn.close()
                            shutil.move(
                                paths.lookupExeFolder() + 'messages.dat', paths.lookupAppdataFolder() + 'messages.dat')
                            self.conn = sqlite3.connect(paths.lookupAppdataFolder() + 'messages.dat', detect_types=sqlite3.PARSE_DECLTYPES)
                            self.conn.text_factory = str
                            self.cur = self.conn.cursor()
                        except Exception as err:
                            logger.error('Error moving messages to appdata: %s', err)
                            # Try to reconnect
                            try:
                                self.conn = sqlite3.connect(state.appdata + 'messages.dat', detect_types=sqlite3.PARSE_DECLTYPES)
                                self.conn.text_factory = str
                                self.cur = self.conn.cursor()
                            except Exception as e2:
                                logger.error('Failed to reconnect: %s', e2)
                                helper_sql.sql_available = False
                                return
                                
                    elif item == 'deleteandvacuume':
                        try:
                            self.cur.execute('''delete from inbox where folder='trash' ''')
                            self.cur.execute('''delete from sent where folder='trash' ''')
                            self.conn.commit()
                            self.cur.execute(''' VACUUM ''')
                        except Exception as err:
                            if str(err) == 'database or disk is full':
                                logger.fatal(
                                    '(while deleteandvacuume) Alert: Your disk or data storage volume is full.'
                                    ' sqlThread will now exit.')
                                queues.UISignalQueue.put((
                                    'alert', (
                                        _translate(
                                            "MainWindow",
                                            "Disk full"),
                                        _translate(
                                            "MainWindow",
                                            'Alert: Your disk or data storage volume is full. Bitmessage will now exit.'),
                                        True)))
                                helper_sql.sql_available = False
                                return
                            else:
                                logger.error('Error during deleteandvacuume: %s', err)
                                
                    else:
                        parameters = helper_sql.sqlSubmitQueue.get()
                        rowcount = 0
                        queryresult = []
                        
                        # DEBUG: Logge die SQL-Abfrage
                        logger.debug("SQL EXECUTE: %s", item)
                        logger.debug("SQL PARAMS: %s", repr(parameters)[:200])
                        
                        try:
                            self.cur.execute(item, parameters)
                            rowcount = self.cur.rowcount
                            
                            # DEBUG: Prüfe erwartete Spalten
                            if "SELECT" in str(item).upper() and hasattr(self.cur, 'description') and self.cur.description:
                                expected_columns = len(self.cur.description)
                                logger.debug("SQL EXPECTED COLUMNS: %d", expected_columns)
                                logger.debug("SQL COLUMN NAMES: %s", [col[0] for col in self.cur.description])
                            
                            queryresult = self.cur.fetchall()
                            
                            # DEBUG: Prüfe tatsächliche Spalten
                            if queryresult:
                                first_row = queryresult[0]
                                actual_columns = len(first_row)
                                logger.debug("SQL ACTUAL COLUMNS RETURNED: %d", actual_columns)
                                
                                # Wenn Spaltenanzahl nicht übereinstimmt
                                if hasattr(self.cur, 'description') and self.cur.description:
                                    expected_columns = len(self.cur.description)
                                    if actual_columns != expected_columns:
                                        logger.error("SQL COLUMN MISMATCH: Expected %d, got %d", 
                                                    expected_columns, actual_columns)
                                        logger.error("SQL QUERY: %s", str(item)[:500])
                                        logger.error("SQL PARAMS: %s", str(repr(parameters))[:500])
                                        logger.error("FIRST ROW: %s", str(first_row)[:500])
                                        
                                        # Versuche zu korrigieren
                                        if "SELECT" in str(item).upper():
                                            logger.warning("Attempting to fix column mismatch...")
                                            # Prüfe Tabellenstruktur
                                            try:
                                                if "FROM inbox" in str(item).upper():
                                                    self.cur.execute("PRAGMA table_info(inbox)")
                                                    inbox_info = self.cur.fetchall()
                                                    logger.error("Current inbox columns: %d", len(inbox_info))
                                                    for col in inbox_info:
                                                        logger.error("  %s: %s", col[1], col[2])
                                                elif "FROM sent" in str(item).upper():
                                                    self.cur.execute("PRAGMA table_info(sent)")
                                                    sent_info = self.cur.fetchall()
                                                    logger.error("Current sent columns: %d", len(sent_info))
                                                    for col in sent_info:
                                                        logger.error("  %s: %s", col[1], col[2])
                                            except Exception as debug_err:
                                                logger.error("Debug error: %s", debug_err)
                            
                        except Exception as err:
                            if str(err) == 'database or disk is full':
                                logger.fatal(
                                    '(while cur.execute) Alert: Your disk or data storage volume is full.'
                                    ' sqlThread will now exit.')
                                queues.UISignalQueue.put((
                                    'alert', (
                                        _translate(
                                            "MainWindow",
                                            "Disk full"),
                                        _translate(
                                            "MainWindow",
                                            'Alert: Your disk or data storage volume is full. Bitmessage will now exit.'),
                                        True)))
                                helper_sql.sql_available = False
                                return
                            else:
                                logger.error(
                                    'SQL ERROR DETAILS:')
                                logger.error('  Query: %s', str(item)[:500])
                                logger.error('  Params: %s', str(repr(parameters))[:500])
                                logger.error('  Error: %s', str(err))
                                
                                # Versuche, die erwartete Spaltenanzahl zu ermitteln
                                if hasattr(self.cur, 'description') and self.cur.description:
                                    expected_cols = len(self.cur.description)
                                    logger.error('  Expected columns: %d', expected_cols)
                                
                                # Falls es eine SELECT-Abfrage war, versuche die aktuelle Struktur zu prüfen
                                if "SELECT" in str(item).upper():
                                    table_name = None
                                    if "FROM inbox" in str(item).upper():
                                        table_name = "inbox"
                                    elif "FROM sent" in str(item).upper():
                                        table_name = "sent"
                                    elif "FROM pubkeys" in str(item).upper():
                                        table_name = "pubkeys"
                                    
                                    if table_name:
                                        try:
                                            self.cur.execute(f"PRAGMA table_info({table_name})")
                                            actual_cols = self.cur.fetchall()
                                            logger.error('  Actual %s columns: %d', table_name, len(actual_cols))
                                            for col in actual_cols:
                                                logger.error('    %s: %s', col[1], col[2])
                                        except Exception as debug_err:
                                            logger.error('  Debug error checking table: %s', debug_err)
                                
                                queryresult = []
                                rowcount = 0
                                # Versuche, die Datenbank-Verbindung wiederherzustellen
                                try:
                                    self.conn.rollback()
                                except:
                                    pass
                        
                        # Immer eine Antwort zurückgeben, auch wenn es eine leere ist
                        helper_sql.sqlReturnQueue.put((queryresult, rowcount))
                        
                except Exception as e:
                    logger.error('Unexpected error in sqlThread main loop: %s', e)
                    logger.error(traceback.format_exc())
                    # Kurze Pause, dann weiter versuchen
                    time.sleep(0.1)
                    
        except Exception as e:
            logger.critical('Fatal error in sqlThread: %s', e)
            logger.critical(traceback.format_exc())
            helper_sql.sql_available = False
            helper_sql.sql_ready.clear()

    def create_function(self):
        # create_function
        try:
            self.conn.create_function("enaddr", 3, func=encodeAddress, deterministic=True)
        except (TypeError, sqlite3.NotSupportedError) as err:
            logger.debug(
                "Got error while pass deterministic in sqlite create function {}, Passing 3 params".format(err))
            self.conn.create_function("enaddr", 3, encodeAddress)
