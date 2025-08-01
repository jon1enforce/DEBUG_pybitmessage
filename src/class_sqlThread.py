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

# Debug setup
DEBUG = True

def debug_print(message):
    if DEBUG:
        print(f"DEBUG: {message}")

debug_print("Initializing sqlThread module")

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
    debug_print("Imported modules using absolute imports")
except ImportError:
    from . import helper_sql, helper_startup, paths, queues, state
    from .addresses import encodeAddress
    from .bmconfigparser import config, config_ready
    from .debug import logger
    from .tr import _translate
    debug_print("Imported modules using relative imports")


class sqlThread(threading.Thread):
    """A thread for all SQL operations"""

    def __init__(self):
        debug_print("Initializing sqlThread instance")
        threading.Thread.__init__(self, name="SQL")
        debug_print("sqlThread initialized")

    def run(self):  # pylint: disable=too-many-locals, too-many-branches, too-many-statements
        """Process SQL queries from `.helper_sql.sqlSubmitQueue`"""
        debug_print("Starting sqlThread run method")
        helper_sql.sql_available = True
        config_ready.wait()
        
        debug_print(f"Connecting to database at: {state.appdata + 'messages.dat'}")
        self.conn = sqlite3.connect(state.appdata + 'messages.dat')
        self.conn.text_factory = bytes
        self.cur = self.conn.cursor()
        debug_print("Database connection established")

        self.cur.execute('PRAGMA secure_delete = true')
        debug_print("Set PRAGMA secure_delete = true")

        # call create_function for encode address
        self.create_function()
        debug_print("Called create_function for encode address")

        try:
            debug_print("Attempting to create database tables")
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
            debug_print("Successfully created all database tables")
        except Exception as err:
            if str(err) == 'table inbox already exists':
                logger.debug('Database file already exists.')
                debug_print("Database tables already exist")
            else:
                debug_print(f"Error creating database: {str(err)}")
                sys.stderr.write(
                    'ERROR trying to create database file (message.dat). Error message: %s\n' % str(err))
                os._exit(0)

        # If the settings version is equal to 2 or 3 then the
        # sqlThread will modify the pubkeys table and change
        # the settings version to 4.
        settingsversion = config.getint(
            'bitmessagesettings', 'settingsversion')
        debug_print(f"Current settings version: {settingsversion}")

        # People running earlier versions of PyBitmessage do not have the
        # usedpersonally field in their pubkeys table. Let's add it.
        if settingsversion == 2:
            debug_print("Upgrading database from version 2 to 3")
            item = '''ALTER TABLE pubkeys ADD usedpersonally text DEFAULT 'no' '''
            parameters = ''
            self.cur.execute(item, parameters)
            self.conn.commit()

            settingsversion = 3
            debug_print("Database upgraded to version 3")

        # People running earlier versions of PyBitmessage do not have the
        # encodingtype field in their inbox and sent tables or the read field
        # in the inbox table. Let's add them.
        if settingsversion == 3:
            debug_print("Upgrading database from version 3 to 4")
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
            debug_print("Database upgraded to version 4")

        config.set(
            'bitmessagesettings', 'settingsversion', str(settingsversion))
        config.save()
        debug_print("Saved updated settings version to config")

        helper_startup.updateConfig()
        debug_print("Updated config via helper_startup")

        # From now on, let us keep a 'version' embedded in the messages.dat
        # file so that when we make changes to the database, the database
        # version we are on can stay embedded in the messages.dat file. Let us
        # check to see if the settings table exists yet.
        item = '''SELECT name FROM sqlite_master WHERE type='table' AND name='settings';'''
        parameters = ''
        debug_print("Checking if settings table exists")
        self.cur.execute(item, parameters)
        if self.cur.fetchall() == []:
            # The settings table doesn't exist. We need to make it.
            debug_print("Creating settings table in database")
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
            debug_print("Completed initial database setup")

        # After code refactoring, the possible status values for sent messages
        # have changed.
        debug_print("Updating sent message status values")
        self.cur.execute(
            '''update sent set status='doingmsgpow' where status='doingpow'  ''')
        self.cur.execute(
            '''update sent set status='msgsent' where status='sentmessage'  ''')
        self.cur.execute(
            '''update sent set status='doingpubkeypow' where status='findingpubkey'  ''')
        self.cur.execute(
            '''update sent set status='broadcastqueued' where status='broadcastpending'  ''')
        self.conn.commit()
        debug_print("Completed status value updates")

        # Let's get rid of the first20bytesofencryptedmessage field in
        # the inventory table.
        item = '''SELECT value FROM settings WHERE key='version';'''
        parameters = ''
        debug_print("Checking database version for inventory table update")
        self.cur.execute(item, parameters)
        version_result = self.cur.fetchall()
        debug_print(f"Version query result: {version_result}")
        
        if version_result and int(version_result[0][0]) == 2:
            logger.debug(
                'In messages.dat database, removing an obsolete field from'
                ' the inventory table.')
            debug_print("Updating inventory table structure")
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
            debug_print("Completed inventory table update to version 3")

        # Add a new column to the inventory table to store tags.
        item = '''SELECT value FROM settings WHERE key='version';'''
        parameters = ''
        debug_print("Checking database version for tag field addition")
        self.cur.execute(item, parameters)
        currentVersion = int(self.cur.fetchall()[0][0])
        debug_print(f"Current database version: {currentVersion}")
        
        if currentVersion == 1 or currentVersion == 3:
            logger.debug(
                'In messages.dat database, adding tag field to'
                ' the inventory table.')
            debug_print("Adding tag field to inventory table")
            item = '''ALTER TABLE inventory ADD tag blob DEFAULT '' '''
            parameters = ''
            self.cur.execute(item, parameters)
            item = '''update settings set value=? WHERE key='version';'''
            parameters = (4,)
            self.cur.execute(item, parameters)
            debug_print("Added tag field to inventory table, version now 4")

        # Add a new column to the pubkeys table to store the address version.
        # We're going to trash all of our pubkeys and let them be redownloaded.
        item = '''SELECT value FROM settings WHERE key='version';'''
        parameters = ''
        debug_print("Checking database version for pubkeys table update")
        self.cur.execute(item, parameters)
        currentVersion = int(self.cur.fetchall()[0][0])
        if currentVersion == 4:
            debug_print("Updating pubkeys table structure to version 5")
            self.cur.execute('''DROP TABLE pubkeys''')
            self.cur.execute(
                '''CREATE TABLE pubkeys (hash blob, addressversion int, transmitdata blob, time int,'''
                '''usedpersonally text, UNIQUE(hash, addressversion) ON CONFLICT REPLACE)''')
            self.cur.execute(
                '''delete from inventory where objecttype = 'pubkey';''')
            item = '''update settings set value=? WHERE key='version';'''
            parameters = (5,)
            self.cur.execute(item, parameters)
            debug_print("Updated pubkeys table to version 5")

        # Add a new table: objectprocessorqueue with which to hold objects
        # that have yet to be processed if the user shuts down Bitmessage.
        item = '''SELECT value FROM settings WHERE key='version';'''
        parameters = ''
        debug_print("Checking database version for objectprocessorqueue addition")
        self.cur.execute(item, parameters)
        currentVersion = int(self.cur.fetchall()[0][0])
        if currentVersion == 5:
            debug_print("Updating database to version 6 with objectprocessorqueue")
            self.cur.execute('''DROP TABLE knownnodes''')
            self.cur.execute(
                '''CREATE TABLE objectprocessorqueue'''
                ''' (objecttype text, data blob, UNIQUE(objecttype, data) ON CONFLICT REPLACE)''')
            item = '''update settings set value=? WHERE key='version';'''
            parameters = (6,)
            self.cur.execute(item, parameters)
            debug_print("Added objectprocessorqueue, version now 6")

        # changes related to protocol v3
        # In table inventory and objectprocessorqueue, objecttype is now
        # an integer (it was a human-friendly string previously)
        item = '''SELECT value FROM settings WHERE key='version';'''
        parameters = ''
        debug_print("Checking database version for protocol v3 changes")
        self.cur.execute(item, parameters)
        currentVersion = int(self.cur.fetchall()[0][0])
        if currentVersion == 6:
            debug_print("Updating database for protocol v3 (version 7)")
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
            debug_print("Completed protocol v3 updates, version now 7")

        # The format of data stored in the pubkeys table has changed. Let's
        # clear it, and the pubkeys from inventory, so that they'll
        # be re-downloaded.
        item = '''SELECT value FROM settings WHERE key='version';'''
        parameters = ''
        debug_print("Checking database version for pubkeys format change")
        self.cur.execute(item, parameters)
        currentVersion = int(self.cur.fetchall()[0][0])
        if currentVersion == 7:
            debug_print("Updating pubkeys format (version 8)")
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
                '''UPDATE sent SET status='msgqueued' WHERE status='doingmsgpow' or status='badkey';''')
            query = '''update settings set value=? WHERE key='version';'''
            parameters = (8,)
            self.cur.execute(query, parameters)
            logger.debug('Finished clearing currently held pubkeys.')
            debug_print("Completed pubkeys format update, version now 8")

        # Add a new column to the inbox table to store the hash of
        # the message signature. We'll use this as temporary message UUID
        # in order to detect duplicates.
        item = '''SELECT value FROM settings WHERE key='version';'''
        parameters = ''
        debug_print("Checking database version for sighash field addition")
        self.cur.execute(item, parameters)
        currentVersion = int(self.cur.fetchall()[0][0])
        if currentVersion == 8:
            debug_print("Adding sighash field to inbox (version 9)")
            logger.debug(
                'In messages.dat database, adding sighash field to'
                ' the inbox table.')
            item = '''ALTER TABLE inbox ADD sighash blob DEFAULT '' '''
            parameters = ''
            self.cur.execute(item, parameters)
            item = '''update settings set value=? WHERE key='version';'''
            parameters = (9,)
            self.cur.execute(item, parameters)
            debug_print("Added sighash field, version now 9")

        # We'll also need a `sleeptill` field and a `ttl` field. Also we
        # can combine the pubkeyretrynumber and msgretrynumber into one.

        item = '''SELECT value FROM settings WHERE key='version';'''
        parameters = ''
        debug_print("Checking database version for TTL changes")
        self.cur.execute(item, parameters)
        currentVersion = int(self.cur.fetchall()[0][0])
        if currentVersion == 9:
            debug_print("Making TTL-related changes (version 10)")
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
            debug_print("Completed TTL changes and pubkeys update, version now 10")

        # Update the address colunm to unique in addressbook table
        item = '''SELECT value FROM settings WHERE key='version';'''
        parameters = ''
        debug_print("Checking database version for addressbook unique constraint")
        self.cur.execute(item, parameters)
        currentVersion = int(self.cur.fetchall()[0][0])
        if currentVersion == 10:
            debug_print("Updating addressbook table to version 11")
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
            debug_print("Updated addressbook table, version now 11")

        # Are you hoping to add a new option to the keys.dat file of existing
        # Bitmessage users or modify the SQLite database? Add it right
        # above this line!

        try:
            debug_print("Running SQLite null value test")
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
                os._exit(0)
            debug_print("SQLite null value test passed")
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
                os._exit(0)
            else:
                logger.error(err)
                debug_print(f"Error during null value test: {err}")

        # Let us check to see the last time we vaccumed the messages.dat file.
        # If it has been more than a month let's do it now.
        item = '''SELECT value FROM settings WHERE key='lastvacuumtime';'''
        parameters = ''
        debug_print("Checking last vacuum time")
        self.cur.execute(item, parameters)
        queryreturn = self.cur.fetchall()
        for row in queryreturn:
            value, = row
            if int(value) < int(time.time()) - 86400:
                logger.info('It has been a long time since the messages.dat file has been vacuumed. Vacuuming now...')
                debug_print("Performing database vacuum")
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
                        os._exit(0)
                item = '''update settings set value=? WHERE key='lastvacuumtime';'''
                parameters = (int(time.time()),)
                self.cur.execute(item, parameters)
                debug_print("Database vacuum completed")

        helper_sql.sql_ready.set()
        debug_print("Database initialization complete, entering main loop")

        while True:
            debug_print("Waiting for next SQL operation from queue")
            item = helper_sql.sqlSubmitQueue.get()
            debug_print(f"Processing SQL operation: {item}")

            if item == 'commit':
                try:
                    debug_print("Performing commit")
                    self.conn.commit()
                    debug_print("Commit completed")
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
                        os._exit(0)
            elif item == 'exit':
                debug_print("Received exit command")
                self.conn.close()
                logger.info('sqlThread exiting gracefully.')
                debug_print("sqlThread exiting")
                return
            elif item == 'movemessagstoprog':
                logger.debug('the sqlThread is moving the messages.dat file to the local program directory.')
                debug_print("Moving messages.dat to program directory")

                try:
                    self.conn.commit()
                except Exception as err:
                    if str(err) == 'database or disk is full':
                        logger.fatal(
                            '(while movemessagstoprog) Alert: Your disk or data storage volume is full.'
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
                        os._exit(0)
                self.conn.close()
                shutil.move(
                    paths.lookupAppdataFolder() + 'messages.dat', paths.lookupExeFolder() + 'messages.dat')
                self.conn = sqlite3.connect(paths.lookupExeFolder() + 'messages.dat')
                self.conn.text_factory = bytes
                self.cur = self.conn.cursor()
                debug_print("Successfully moved messages.dat to program directory")
            elif item == 'movemessagstoappdata':
                logger.debug('the sqlThread is moving the messages.dat file to the Appdata folder.')
                debug_print("Moving messages.dat to Appdata folder")

                try:
                    self.conn.commit()
                except Exception as err:
                    if str(err) == 'database or disk is full':
                        logger.fatal(
                            '(while movemessagstoappdata) Alert: Your disk or data storage volume is full.'
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
                        os._exit(0)
                self.conn.close()
                shutil.move(
                    paths.lookupExeFolder() + 'messages.dat', paths.lookupAppdataFolder() + 'messages.dat')
                self.conn = sqlite3.connect(paths.lookupAppdataFolder() + 'messages.dat')
                self.conn.text_factory = bytes
                self.cur = self.conn.cursor()
                debug_print("Successfully moved messages.dat to Appdata folder")
            elif item == 'deleteandvacuume':
                debug_print("Deleting trash and vacuuming database")
                self.cur.execute('''delete from inbox where folder='trash' ''')
                self.cur.execute('''delete from sent where folder='trash' ''')
                self.conn.commit()
                try:
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
                        os._exit(0)
                debug_print("Completed trash deletion and vacuum")
            else:
                parameters = helper_sql.sqlSubmitQueue.get()
                rowcount = 0
                debug_print(f"Executing SQL query: {item} with parameters: {parameters}")
                try:
                    self.cur.execute(item, parameters)
                    rowcount = self.cur.rowcount
                    debug_print(f"Query executed, affected {rowcount} rows")
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
                        os._exit(0)
                    else:
                        logger.fatal(
                            'Major error occurred when trying to execute a SQL statement within the sqlThread.'
                            ' Please tell Atheros about this error message or post it in the forum!'
                            ' Error occurred while trying to execute statement: "%s"  Here are the parameters;'
                            ' you might want to censor this data with asterisks (***)'
                            ' as it can contain private information: %s.'
                            ' Here is the actual error message thrown by the sqlThread: %s',
                            str(item),
                            str(repr(parameters)),
                            str(err))
                        logger.fatal('This program shall now abruptly exit!')
                        debug_print(f"SQL error: {err}")

                    os._exit(0)

                helper_sql.sqlReturnQueue.put((self.cur.fetchall(), rowcount))
                debug_print("Results placed in sqlReturnQueue")
                # helper_sql.sqlSubmitQueue.task_done()

    def create_function(self):
        # create_function
        debug_print("Creating SQL function 'enaddr'")
        try:
            self.conn.create_function("enaddr", 3, func=encodeAddress, deterministic=True)
            debug_print("Successfully created deterministic SQL function 'enaddr'")
        except (TypeError, sqlite3.NotSupportedError) as err:
            debug_print(f"Could not create deterministic function, trying without: {err}")
            logger.debug(
                "Got error while pass deterministic in sqlite create function {}, Passing 3 params".format(err))
            self.conn.create_function("enaddr", 3, encodeAddress)
            debug_print("Successfully created non-deterministic SQL function 'enaddr'")

debug_print("sqlThread module initialization complete")
