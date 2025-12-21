"""
Thread for performing PoW
"""
# pylint: disable=protected-access,too-many-branches,too-many-statements
# pylint: disable=no-self-use,too-many-lines,too-many-locals

from __future__ import division

import hashlib
import time
from binascii import hexlify, unhexlify
from struct import pack
from subprocess import call  # nosec
import sqlite3

import defaults
import helper_inbox
import helper_msgcoding
import helper_random
import helper_sql
import highlevelcrypto
import l10n
import proofofwork
import protocol
import queues
import shared
import state
from addresses import decodeAddress, decodeVarint, encodeVarint
from bmconfigparser import config
from helper_sql import sqlExecute, sqlQuery
from network import knownnodes, StoppableThread, invQueue
from six.moves import configparser, queue
from six.moves.reprlib import repr
import six
from dbcompat import dbstr
from tr import _translate


def sizeof_fmt(num, suffix='h/s'):
    """Format hashes per seconds nicely (SI prefix)"""

    for unit in ['', 'k', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1000.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


class singleWorker(StoppableThread):
    """Thread for performing PoW"""

    def __init__(self):
        super(singleWorker, self).__init__(name="singleWorker")
        self.digestAlg = config.safeGet(
            'bitmessagesettings', 'digestalg', 'sha256')
        proofofwork.init()

    def stopThread(self):
        """Signal through the queue that the thread should be stopped"""

        try:
            queues.workerQueue.put(("stopThread", "data"))
        except queue.Full:
            self.logger.error('workerQueue is Full')
        super(singleWorker, self).stopThread()

    def run(self):
        # pylint: disable=attribute-defined-outside-init

        while not helper_sql.sql_ready.wait(1.0) and state.shutdown == 0:
            self.stop.wait(1.0)
        if state.shutdown > 0:
            return

        # Initialize the neededPubkeys dictionary.
        queryreturn = sqlQuery(
            '''SELECT DISTINCT toaddress FROM sent'''
            ''' WHERE (status='awaitingpubkey' AND folder='sent')''')
        for toAddress, in queryreturn:
            toAddress = toAddress.decode("utf-8", "replace")
            toAddressVersionNumber, toStreamNumber, toRipe = \
                decodeAddress(toAddress)[1:]
            if toAddressVersionNumber <= 3:
                state.neededPubkeys[toAddress] = 0
            elif toAddressVersionNumber >= 4:
                doubleHashOfAddressData = highlevelcrypto.double_sha512(
                    encodeVarint(toAddressVersionNumber)
                    + encodeVarint(toStreamNumber) + toRipe
                )
                # Note that this is the first half of the sha512 hash.
                privEncryptionKey = doubleHashOfAddressData[:32]
                tag = doubleHashOfAddressData[32:]
                # We'll need this for when we receive a pubkey reply:
                # it will be encrypted and we'll need to decrypt it.
                state.neededPubkeys[bytes(tag)] = (
                    toAddress,
                    highlevelcrypto.makeCryptor(
                        hexlify(privEncryptionKey))
                )

        # Initialize the state.ackdataForWhichImWatching data structure
        queryreturn = sqlQuery(
            '''SELECT ackdata FROM sent WHERE status = 'msgsent' AND folder = 'sent' ''')
        for row in queryreturn:
            ackdata, = row
            self.logger.info('Watching for ackdata %s', hexlify(ackdata))
            state.ackdataForWhichImWatching[bytes(ackdata)] = 0

        # Fix legacy (headerless) watched ackdata to include header
        for oldack in state.ackdataForWhichImWatching:
            if len(oldack) == 32:
                # attach legacy header, always constant (msg/1/1)
                newack = b'\x00\x00\x00\x02\x01\x01' + oldack
                state.ackdataForWhichImWatching[bytes(newack)] = 0
                rowcount = sqlExecute(
                    '''UPDATE sent SET ackdata=? WHERE ackdata=? AND folder = 'sent' ''',
                    sqlite3.Binary(newack), sqlite3.Binary(oldack)
                )
                if rowcount < 1:
                    sqlExecute(
                        '''UPDATE sent SET ackdata=? WHERE ackdata=CAST(? AS TEXT) AND folder = 'sent' ''',
                        sqlite3.Binary(newack), oldack
                    )
                del state.ackdataForWhichImWatching[oldack]

        # For the case if user deleted knownnodes
        # but is still having onionpeer objects in inventory
        if not knownnodes.knownNodesActual:
            for item in state.Inventory.by_type_and_tag(protocol.OBJECT_ONIONPEER):
                queues.objectProcessorQueue.put((
                    protocol.OBJECT_ONIONPEER, item.payload
                ))
                # FIXME: should also delete from inventory

        # give some time for the GUI to start
        # before we start on existing POW tasks.
        self.stop.wait(10)

        if state.shutdown:
            return

        # just in case there are any pending tasks for msg
        # messages that have yet to be sent.
        queues.workerQueue.put(('sendmessage', ''))
        # just in case there are any tasks for Broadcasts
        # that have yet to be sent.
        queues.workerQueue.put(('sendbroadcast', ''))

        # send onionpeer object
        queues.workerQueue.put(('sendOnionPeerObj', ''))

        while state.shutdown == 0:
            self.busy = 0
            command, data = queues.workerQueue.get()
            self.busy = 1
            if command == 'sendmessage':
                try:
                    self.sendMsg()
                except Exception as e:  # Spezifische Exception fangen
                    self.logger.error(f"sendMsg failed: {type(e).__name__}: {e}")
                    import traceback
                    self.logger.error(f"Full traceback:\n{traceback.format_exc()}")
            elif command == 'sendbroadcast':
                try:
                    self.sendBroadcast()
                except Exception as e:  # Spezifische Exception fangen
                    self.logger.error(f"sendBroadcast failed: {type(e).__name__}: {e}")
                    import traceback
                    self.logger.error(f"Full traceback:\n{traceback.format_exc()}")
            elif command == 'doPOWForMyV2Pubkey':
                try:
                    self.doPOWForMyV2Pubkey(data)
                except Exception as e:  # Spezifische Exception fangen
                    self.logger.error(f"doPOWForMyV2Pubkey failed: {type(e).__name__}: {e}")
                    import traceback
                    self.logger.error(f"Full traceback:\n{traceback.format_exc()}")
            elif command == 'sendOutOrStoreMyV3Pubkey':
                try:
                    self.sendOutOrStoreMyV3Pubkey(data)
                except Exception as e:  # Spezifische Exception fangen
                    self.logger.error(f"sendOutOrStoreMyV3Pubkey failed: {type(e).__name__}: {e}")
                    import traceback
                    self.logger.error(f"Full traceback:\n{traceback.format_exc()}")
            elif command == 'sendOutOrStoreMyV4Pubkey':
                try:
                    self.sendOutOrStoreMyV4Pubkey(data)
                except Exception as e:  # Spezifische Exception fangen
                    self.logger.error(f"sendOutOrStoreMyV4Pubkey failed: {type(e).__name__}: {e}")
                    import traceback
                    self.logger.error(f"Full traceback:\n{traceback.format_exc()}")
            elif command == 'sendOnionPeerObj':
                try:
                    self.sendOnionPeerObj(data)
                except Exception as e:  # Spezifische Exception fangen
                    self.logger.error(f"sendOnionPeerObj failed: {type(e).__name__}: {e}")
                    import traceback
                    self.logger.error(f"Full traceback:\n{traceback.format_exc()}")
            elif command == 'resetPoW':
                try:
                    proofofwork.resetPoW()
                except Exception as e:  # Spezifische Exception fangen
                    self.logger.error(f"proofofwork.resetPoW failed: {type(e).__name__}: {e}")
                    import traceback
                    self.logger.error(f"Full traceback:\n{traceback.format_exc()}")
            elif command == 'stopThread':
                self.busy = 0
                return
            else:
                self.logger.error(
                    'Probable programming error: The command sent'
                    ' to the workerThread is weird. It is: %s\n',
                    command
                )

            queues.workerQueue.task_done()
        self.logger.info("Quitting...")
    def _getKeysForAddress(self, address):
        try:
            privSigningKeyBase58 = config.get(address, 'privsigningkey')
            privEncryptionKeyBase58 = config.get(address, 'privencryptionkey')
        except (configparser.NoSectionError, configparser.NoOptionError):
            self.logger.error(
                'Could not read or decode privkey for address %s', address)
            raise ValueError

        privSigningKeyHex = hexlify(highlevelcrypto.decodeWalletImportFormat(
            privSigningKeyBase58.encode()))
        privEncryptionKeyHex = hexlify(
            highlevelcrypto.decodeWalletImportFormat(
                privEncryptionKeyBase58.encode()))

        # The \x04 on the beginning of the public keys are not sent.
        # This way there is only one acceptable way to encode
        # and send a public key.
        pubSigningKey = unhexlify(highlevelcrypto.privToPub(
            privSigningKeyHex))[1:]
        pubEncryptionKey = unhexlify(highlevelcrypto.privToPub(
            privEncryptionKeyHex))[1:]

        return privSigningKeyHex, privEncryptionKeyHex, \
            pubSigningKey, pubEncryptionKey

    def _doPOWDefaults(
            self, payload, TTL, log_prefix='', log_time=False):
        target = 2 ** 64 / (
            defaults.networkDefaultProofOfWorkNonceTrialsPerByte * (
                len(payload) + 8
                + defaults.networkDefaultPayloadLengthExtraBytes + ((
                    TTL * (
                        len(payload) + 8
                        + defaults.networkDefaultPayloadLengthExtraBytes
                    )) / (2 ** 16))
            ))
        initialHash = hashlib.sha512(payload).digest()
        self.logger.info(
            '%s Doing proof of work... TTL set to %s', log_prefix, TTL)
        if log_time:
            start_time = time.time()
        trialValue, nonce = proofofwork.run(target, initialHash)
        self.logger.info(
            '%s Found proof of work %s Nonce: %s',
            log_prefix, trialValue, nonce
        )
        try:
            delta = time.time() - start_time
            self.logger.info(
                'PoW took %.1f seconds, speed %s.',
                delta, sizeof_fmt(nonce / delta)
            )
        except NameError:
            self.logger.warning("Proof of Work exception")
        payload = pack('>Q', nonce) + payload
        return payload

    def doPOWForMyV2Pubkey(self, adressHash):
        """
        This function also broadcasts out the pubkey message once it is
        done with the POW
        """
        # Look up my stream number based on my address hash
        myAddress = shared.myAddressesByHash[adressHash]
        addressVersionNumber, streamNumber = decodeAddress(myAddress)[1:3]

        # 28 days from now plus or minus five minutes
        TTL = int(28 * 24 * 60 * 60 + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)
        payload = pack('>Q', (embeddedTime))
        payload += b'\x00\x00\x00\x01'  # object type: pubkey
        payload += encodeVarint(addressVersionNumber)  # Address version number
        payload += encodeVarint(streamNumber)
        # bitfield of features supported by me (see the wiki).
        payload += protocol.getBitfield(myAddress)

        try:
            pubSigningKey, pubEncryptionKey = self._getKeysForAddress(
                myAddress)[2:]
        except ValueError:
            return
        except Exception:  # pylint:disable=broad-exception-caught
            self.logger.error(
                'Error within doPOWForMyV2Pubkey. Could not read'
                ' the keys from the keys.dat file for a requested'
                ' address. %s\n', exc_info=True)
            return

        payload += pubSigningKey + pubEncryptionKey

        # Do the POW for this pubkey message
        payload = self._doPOWDefaults(
            payload, TTL, log_prefix='(For pubkey message)')

        inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
        objectType = 1
        state.Inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime, '')

        self.logger.info(
            'broadcasting inv with hash: %s', hexlify(inventoryHash))

        invQueue.put((streamNumber, inventoryHash))
        queues.UISignalQueue.put(('updateStatusBar', ''))
        try:
            config.set(
                myAddress, 'lastpubkeysendtime', str(int(time.time())))
            config.save()
        except configparser.NoSectionError:
            # The user deleted the address out of the keys.dat file
            # before this finished.
            pass
        except:  # noqa:E722
            self.logger.warning("config.set didn't work")

    def sendOutOrStoreMyV3Pubkey(self, adressHash):
        """
        If this isn't a chan address, this function assembles the pubkey
        data, does the necessary POW and sends it out.
        If it *is* a chan then it assembles the pubkey and stores it in
        the pubkey table so that we can send messages to "ourselves".
        """
        try:
            myAddress = shared.myAddressesByHash[adressHash]
        except KeyError:
            self.logger.warning(  # The address has been deleted.
                "Can't find %s in myAddressByHash", hexlify(adressHash))
            return
        if config.safeGetBoolean(myAddress, 'chan'):
            self.logger.info('This is a chan address. Not sending pubkey.')
            return
        _, addressVersionNumber, streamNumber, adressHash = decodeAddress(
            myAddress)

        # 28 days from now plus or minus five minutes
        TTL = int(28 * 24 * 60 * 60 + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)

        # signedTimeForProtocolV2 = embeddedTime - TTL
        # According to the protocol specification, the expiresTime
        # along with the pubkey information is signed. But to be
        # backwards compatible during the upgrade period, we shall sign
        # not the expiresTime but rather the current time. There must be
        # precisely a 28 day difference between the two. After the upgrade
        # period we'll switch to signing the whole payload with the
        # expiresTime time.

        payload = pack('>Q', (embeddedTime))
        payload += b'\x00\x00\x00\x01'  # object type: pubkey
        payload += encodeVarint(addressVersionNumber)  # Address version number
        payload += encodeVarint(streamNumber)
        # bitfield of features supported by me (see the wiki).
        payload += protocol.getBitfield(myAddress)

        try:
            # , privEncryptionKeyHex
            privSigningKeyHex, _, pubSigningKey, pubEncryptionKey = \
                self._getKeysForAddress(myAddress)
        except ValueError:
            return
        except Exception:  # pylint:disable=broad-exception-caught
            self.logger.error(
                'Error within sendOutOrStoreMyV3Pubkey. Could not read'
                ' the keys from the keys.dat file for a requested'
                ' address. %s\n', exc_info=True)
            return

        payload += pubSigningKey + pubEncryptionKey

        payload += encodeVarint(config.getint(
            myAddress, 'noncetrialsperbyte'))
        payload += encodeVarint(config.getint(
            myAddress, 'payloadlengthextrabytes'))

        signature = highlevelcrypto.sign(
            payload, privSigningKeyHex, self.digestAlg)
        payload += encodeVarint(len(signature))
        payload += signature

        # Do the POW for this pubkey message
        payload = self._doPOWDefaults(
            payload, TTL, log_prefix='(For pubkey message)')

        inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
        objectType = 1
        state.Inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime, '')

        self.logger.info(
            'broadcasting inv with hash: %s', hexlify(inventoryHash))

        invQueue.put((streamNumber, inventoryHash))
        queues.UISignalQueue.put(('updateStatusBar', ''))
        try:
            config.set(
                myAddress, 'lastpubkeysendtime', str(int(time.time())))
            config.save()
        except configparser.NoSectionError:
            # The user deleted the address out of the keys.dat file
            # before this finished.
            pass
        except:  # noqa:E722
            self.logger.warning("BMConfigParser().set didn't work")

    def sendOutOrStoreMyV4Pubkey(self, myAddress):
        """
        It doesn't send directly anymore. It put is to a queue for
        another thread to send at an appropriate time, whereas in the
        past it directly appended it to the outgoing buffer, I think.
        Same with all the other methods in this class.
        """
        if not config.has_section(myAddress):
            # The address has been deleted.
            return
        if config.safeGetBoolean(myAddress, 'chan'):
            self.logger.info('This is a chan address. Not sending pubkey.')
            return
        _, addressVersionNumber, streamNumber, addressHash = decodeAddress(
            myAddress)

        # 28 days from now plus or minus five minutes
        TTL = int(28 * 24 * 60 * 60 + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)
        payload = pack('>Q', (embeddedTime))
        payload += b'\x00\x00\x00\x01'  # object type: pubkey
        payload += encodeVarint(addressVersionNumber)  # Address version number
        payload += encodeVarint(streamNumber)
        dataToEncrypt = protocol.getBitfield(myAddress)

        try:
            # , privEncryptionKeyHex
            privSigningKeyHex, _, pubSigningKey, pubEncryptionKey = \
                self._getKeysForAddress(myAddress)
        except ValueError:
            return
        except Exception:  # pylint:disable=broad-exception-caught
            self.logger.error(
                'Error within sendOutOrStoreMyV4Pubkey. Could not read'
                ' the keys from the keys.dat file for a requested'
                ' address. %s\n', exc_info=True)
            return

        dataToEncrypt += pubSigningKey + pubEncryptionKey

        dataToEncrypt += encodeVarint(config.getint(
            myAddress, 'noncetrialsperbyte'))
        dataToEncrypt += encodeVarint(config.getint(
            myAddress, 'payloadlengthextrabytes'))

        # When we encrypt, we'll use a hash of the data
        # contained in an address as a decryption key. This way
        # in order to read the public keys in a pubkey message,
        # a node must know the address first. We'll also tag,
        # unencrypted, the pubkey with part of the hash so that nodes
        # know which pubkey object to try to decrypt
        # when they want to send a message.
        doubleHashOfAddressData = highlevelcrypto.double_sha512(
            encodeVarint(addressVersionNumber)
            + encodeVarint(streamNumber) + addressHash
        )
        payload += doubleHashOfAddressData[32:]  # the tag
        signature = highlevelcrypto.sign(
            payload + dataToEncrypt, privSigningKeyHex, self.digestAlg)
        dataToEncrypt += encodeVarint(len(signature))
        dataToEncrypt += signature

        privEncryptionKey = doubleHashOfAddressData[:32]
        pubEncryptionKey = highlevelcrypto.pointMult(privEncryptionKey)
        payload += highlevelcrypto.encrypt(
            dataToEncrypt, hexlify(pubEncryptionKey))

        # Do the POW for this pubkey message
        payload = self._doPOWDefaults(
            payload, TTL, log_prefix='(For pubkey message)')

        inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
        objectType = 1
        state.Inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime,
            doubleHashOfAddressData[32:]
        )

        self.logger.info(
            'broadcasting inv with hash: %s', hexlify(inventoryHash))

        invQueue.put((streamNumber, inventoryHash))
        queues.UISignalQueue.put(('updateStatusBar', ''))
        try:
            config.set(
                myAddress, 'lastpubkeysendtime', str(int(time.time())))
            config.save()
        except Exception as err:
            self.logger.error(
                'Error: Couldn\'t add the lastpubkeysendtime'
                ' to the keys.dat file. Error message: %s', err
            )

    def sendOnionPeerObj(self, peer=None):
        """Send onionpeer object representing peer"""
        if not peer:  # find own onionhostname
            for peer in state.ownAddresses:
                if peer.host.endswith('.onion'):
                    break
            else:
                return
        TTL = int(7 * 24 * 60 * 60 + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)
        streamNumber = 1  # Don't know yet what should be here
        objectType = protocol.OBJECT_ONIONPEER
        # FIXME: ideally the objectPayload should be signed
        objectPayload = encodeVarint(peer.port) + protocol.encodeHost(peer.host)
        tag = highlevelcrypto.calculateInventoryHash(objectPayload)

        if state.Inventory.by_type_and_tag(objectType, tag):
            return  # not expired

        payload = pack('>Q', embeddedTime)
        payload += pack('>I', objectType)
        payload += encodeVarint(2 if len(peer.host) == 22 else 3)
        payload += encodeVarint(streamNumber)
        payload += objectPayload

        payload = self._doPOWDefaults(
            payload, TTL, log_prefix='(For onionpeer object)')

        inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
        if six.PY2:
            payload_buffer = buffer(payload)
            tag_buffer = buffer(tag)
        else:  # assume six.PY3
            payload_buffer = memoryview(payload)
            tag_buffer = memoryview(tag)
        state.Inventory[inventoryHash] = (
            objectType, streamNumber, payload_buffer,  # noqa: F821
            embeddedTime, tag_buffer  # noqa: F821
        )
        self.logger.info(
            'sending inv (within sendOnionPeerObj function) for object: %s',
            hexlify(inventoryHash))
        invQueue.put((streamNumber, inventoryHash))

    def sendBroadcast(self):
        """
        Send a broadcast-type object (assemble the object, perform PoW
        and put it to the inv announcement queue)
        """
        # Reset just in case
        sqlExecute(
            '''UPDATE sent SET status='broadcastqueued' '''
            '''WHERE status = 'doingbroadcastpow' AND folder = 'sent' ''')
        
        # DEBUG: Teste die Datenbankverbindung zuerst
        self.logger.debug("=== DEBUG START sendBroadcast ===")
        
        # Teste eine einfache Query zuerst
        test_query = sqlQuery("SELECT 1")
        if not test_query:
            self.logger.error("ERROR: Simple test query failed!")
            return
        
        # Überprüfe die Tabellenstruktur
        try:
            table_info = sqlQuery("PRAGMA table_info(sent)")
            self.logger.debug(f"Sent table has {len(table_info)} columns")
            for i, col in enumerate(table_info):
                if isinstance(col, (tuple, list)) and len(col) > 1:
                    self.logger.debug(f"  Column {i}: {col[1]} (type: {col[2]})")
                else:
                    self.logger.debug(f"  Column {i}: {col}")
        except Exception as e:
            self.logger.error(f"Error getting table info: {e}")
        
        # Teste, ob die benötigten Spalten existieren
        test_columns = sqlQuery('''
            SELECT 
                COUNT(CASE WHEN name='fromaddress' THEN 1 END) as has_fromaddress,
                COUNT(CASE WHEN name='subject' THEN 1 END) as has_subject,
                COUNT(CASE WHEN name='message' THEN 1 END) as has_message,
                COUNT(CASE WHEN name='ackdata' THEN 1 END) as has_ackdata,
                COUNT(CASE WHEN name='ttl' THEN 1 END) as has_ttl,
                COUNT(CASE WHEN name='encodingtype' THEN 1 END) as has_encodingtype
            FROM pragma_table_info('sent')
        ''')
        
        if test_columns:
            self.logger.debug(f"Column check result: {test_columns[0]}")
        
        # Die eigentliche Query
        queryreturn = sqlQuery(
            '''SELECT fromaddress, subject, message, '''
            ''' ackdata, ttl, encodingtype FROM sent '''
            ''' WHERE status=? and folder='sent' ''', 'broadcastqueued')
        
        self.logger.debug(f"=== QUERY RESULTS ===")
        self.logger.debug(f"Query returned {len(queryreturn)} rows")
        
        for i, row in enumerate(queryreturn):
            self.logger.debug(f"Row {i}: {type(row)} = {row}")
            
            if not isinstance(row, (tuple, list)):
                self.logger.error(f"ERROR: Row {i} is not a tuple/list: {type(row)}")
                continue
                
            if len(row) == 1:
                # NUR 1 WERT - das ist das Problem!
                self.logger.error(f"CRITICAL ERROR: Query returned only 1 value: {row[0]}")
                self.logger.error("This suggests either:")
                self.logger.error("1. The query failed and returned an error message")
                self.logger.error("2. The database table is missing columns")
                self.logger.error("3. sqlQuery function is broken")
                
                # Debug: Was ist das einzelne Element?
                single_item = row[0]
                if isinstance(single_item, bytes):
                    self.logger.error(f"Single item is bytes: {single_item[:100]}")
                    try:
                        decoded = single_item.decode('utf-8', errors='replace')
                        self.logger.error(f"Decoded as string: {decoded[:200]}")
                    except:
                        pass
                elif isinstance(single_item, str):
                    self.logger.error(f"Single item is string: {single_item[:200]}")
                
                continue  # Überspringe diese fehlerhafte Zeile
            
            elif len(row) != 6:
                self.logger.error(f"ERROR: Expected 6 columns, got {len(row)}")
                self.logger.error(f"Row: {row}")
                continue
            
            # Jetzt sicher entpacken
            try:
                fromaddress, subject, message, ackdata, ttl, encodingtype = row
                
                # Debug die Werte
                self.logger.debug(f"  fromaddress: {type(fromaddress)} = {fromaddress[:50] if fromaddress else 'None'}")
                self.logger.debug(f"  subject: {type(subject)} = {subject[:50] if subject else 'None'}")
                self.logger.debug(f"  message: {type(message)} = {message[:50] if message else 'None'}")
                self.logger.debug(f"  ackdata: {type(ackdata)} = {ackdata[:20] if ackdata else 'None'}")
                self.logger.debug(f"  ttl: {type(ttl)} = {ttl}")
                self.logger.debug(f"  encodingtype: {type(encodingtype)} = {encodingtype}")
                
                # Decodieren
                fromaddress = fromaddress.decode("utf-8", "replace") if fromaddress else ""
                subject = subject.decode("utf-8", "replace") if subject else ""
                body = message.decode("utf-8", "replace") if message else ""
                TTL = ttl if ttl else 216000  # Default TTL
                encoding = encodingtype if encodingtype else 2  # Default encoding
                
                self.logger.debug(f"Processing broadcast from: {fromaddress}")
                
                # Rest des Originalcodes (unverändert)
                _, addressVersionNumber, streamNumber, ripe = \
                    decodeAddress(fromaddress)
                if addressVersionNumber <= 1:
                    self.logger.error(
                        'Error: In the singleWorker thread, the '
                        ' sendBroadcast function doesn\'t understand'
                        ' the address version.\n')
                    return
                
                # ... Rest des Codes (Zeilen 587-695) ...
                # We need to convert our private keys to public keys in order
                # to include them.
                try:
                    # , privEncryptionKeyHex
                    privSigningKeyHex, _, pubSigningKey, pubEncryptionKey = \
                        self._getKeysForAddress(fromaddress)
                except ValueError:
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata, _translate(
                                "MainWindow",
                                "Error! Could not find sender address"
                                " (your address) in the keys.dat file."))
                    ))
                    continue
                except Exception as err:
                    self.logger.error(
                        'Error within sendBroadcast. Could not read'
                        ' the keys from the keys.dat file for a requested'
                        ' address. %s\n', err
                    )
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata,
                            _translate(
                                "MainWindow",
                                "Error, can't send."))
                    ))
                    continue

                rowcount = sqlExecute(
                        '''UPDATE sent SET status='doingbroadcastpow' '''
                        ''' WHERE ackdata=? AND status='broadcastqueued' '''
                        ''' AND folder='sent' ''',
                        sqlite3.Binary(ackdata))
                if rowcount < 1:
                    rowcount = sqlExecute(
                            '''UPDATE sent SET status='doingbroadcastpow' '''
                            ''' WHERE ackdata=CAST(? AS TEXT) AND status='broadcastqueued' '''
                            ''' AND folder='sent' ''',
                            ackdata)
                if rowcount < 1:
                    continue

                # At this time these pubkeys are 65 bytes long
                # because they include the encoding byte which we won't
                # be sending in the broadcast message.
                # pubSigningKey = \
                #     highlevelcrypto.privToPub(privSigningKeyHex).decode('hex')

                if TTL > 28 * 24 * 60 * 60:
                    TTL = 28 * 24 * 60 * 60
                if TTL < 60 * 60:
                    TTL = 60 * 60
                # add some randomness to the TTL
                TTL = int(TTL + helper_random.randomrandrange(-300, 300))
                embeddedTime = int(time.time() + TTL)
                payload = pack('>Q', embeddedTime)
                payload += b'\x00\x00\x00\x03'  # object type: broadcast

                if addressVersionNumber <= 3:
                    payload += encodeVarint(4)  # broadcast version
                else:
                    payload += encodeVarint(5)  # broadcast version

                payload += encodeVarint(streamNumber)
                if addressVersionNumber >= 4:
                    doubleHashOfAddressData = highlevelcrypto.double_sha512(
                        encodeVarint(addressVersionNumber)
                        + encodeVarint(streamNumber) + ripe
                    )
                    tag = doubleHashOfAddressData[32:]
                    payload += tag
                else:
                    tag = b''

                dataToEncrypt = encodeVarint(addressVersionNumber)
                dataToEncrypt += encodeVarint(streamNumber)
                # behavior bitfield
                dataToEncrypt += protocol.getBitfield(fromaddress)
                dataToEncrypt += pubSigningKey + pubEncryptionKey
                if addressVersionNumber >= 3:
                    dataToEncrypt += encodeVarint(config.getint(
                        fromaddress, 'noncetrialsperbyte'))
                    dataToEncrypt += encodeVarint(config.getint(
                        fromaddress, 'payloadlengthextrabytes'))
                # message encoding type
                dataToEncrypt += encodeVarint(encoding)
                encodedMessage = helper_msgcoding.MsgEncode(
                    {"subject": subject, "body": body}, encoding)
                dataToEncrypt += encodeVarint(encodedMessage.length)
                dataToEncrypt += encodedMessage.data
                dataToSign = payload + dataToEncrypt

                signature = highlevelcrypto.sign(
                    dataToSign, privSigningKeyHex, self.digestAlg)
                dataToEncrypt += encodeVarint(len(signature))
                dataToEncrypt += signature

                # Encrypt the broadcast with the information
                # contained in the broadcaster's address.
                # Anyone who knows the address can generate
                # the private encryption key to decrypt the broadcast.
                # This provides virtually no privacy; its purpose is to keep
                # questionable and illegal content from flowing through the
                # Internet connections and being stored on the disk of 3rd parties.
                if addressVersionNumber <= 3:
                    privEncryptionKey = hashlib.sha512(
                        encodeVarint(addressVersionNumber)
                        + encodeVarint(streamNumber) + ripe
                    ).digest()[:32]
                else:
                    privEncryptionKey = doubleHashOfAddressData[:32]

                pubEncryptionKey = highlevelcrypto.pointMult(privEncryptionKey)
                payload += highlevelcrypto.encrypt(
                    dataToEncrypt, hexlify(pubEncryptionKey))

                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata, _translate(
                            "MainWindow",
                            "Doing work necessary to send broadcast..."))
                ))
                payload = self._doPOWDefaults(
                    payload, TTL, log_prefix='(For broadcast message)')

                # Sanity check. The payload size should never be larger
                # than 256 KiB. There should be checks elsewhere in the code
                # to not let the user try to send a message this large
                # until we implement message continuation.
                if len(payload) > 2 ** 18:  # 256 KiB
                    self.logger.critical(
                        'This broadcast object is too large to send.'
                        ' This should never happen. Object size: %s',
                        len(payload)
                    )
                    continue

                inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
                objectType = 3
                state.Inventory[inventoryHash] = (
                    objectType, streamNumber, payload, embeddedTime, tag)
                self.logger.info(
                    'sending inv (within sendBroadcast function)'
                    ' for object: %s',
                    hexlify(inventoryHash)
                )
                invQueue.put((streamNumber, inventoryHash))

                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata, _translate(
                            "MainWindow", "Broadcast sent on {0}"
                        ).format(l10n.formatTimestamp()))
                ))

                # Update the status of the message in the 'sent' table to have
                # a 'broadcastsent' status
                rowcount = sqlExecute(
                    '''UPDATE sent SET msgid=?, status=?, lastactiontime=? '''
                    ''' WHERE ackdata=? AND folder='sent' ''',
                    sqlite3.Binary(inventoryHash), dbstr('broadcastsent'), int(time.time()), sqlite3.Binary(ackdata)
                )
                if rowcount < 1:
                    sqlExecute(
                        '''UPDATE sent SET msgid=?, status=?, lastactiontime=? '''
                        ''' WHERE ackdata=CAST(? AS TEXT) AND folder='sent' ''',
                        sqlite3.Binary(inventoryHash), 'broadcastsent', int(time.time()), ackdata
                    )
                    
            except Exception as e:
                self.logger.error(f"Error processing row {i}: {e}")
                import traceback
                self.logger.error(traceback.format_exc())
                continue
        
        self.logger.debug("=== DEBUG END sendBroadcast ===")
    def sendMsg(self):
        """
        Send a message-type object (assemble the object, perform PoW
        and put it to the inv announcement queue)
        """
        # pylint: disable=too-many-nested-blocks
        # Reset just in case
        sqlExecute(
            '''UPDATE sent SET status='msgqueued' '''
            ''' WHERE status IN ('doingpubkeypow', 'doingmsgpow') '''
            ''' AND folder='sent' ''')
        
        # DEBUG: Zuerst überprüfen wir die Query
        self.logger.debug("=== DEBUG sendMsg START ===")
        
        queryreturn = sqlQuery(
            '''SELECT toaddress, fromaddress, subject, message, '''
            ''' ackdata, status, ttl, retrynumber, encodingtype FROM '''
            ''' sent WHERE (status='msgqueued' or status='forcepow') '''
            ''' and folder='sent' ''')
        
        self.logger.debug(f"sendMsg: Query returned {len(queryreturn)} rows")
        
        # while we have a msg that needs some work
        for i, row in enumerate(queryreturn):
            self.logger.debug(f"Processing row {i}: {row[:3] if row else 'Empty'}")
            
            # Sicherheitscheck
            if not isinstance(row, (tuple, list)):
                self.logger.error(f"Row {i} is not a tuple/list: {type(row)}")
                continue
                
            if len(row) != 9:
                self.logger.error(f"ERROR: Expected 9 columns, got {len(row)}")
                self.logger.error(f"Row: {row}")
                continue
            
            # KORREKTUR: Richtig entpacken mit den tatsächlichen Spaltennamen
            toaddress, fromaddress, subject, message, ackdata, status, ttl, retrynumber, encodingtype = row
            
            # Decodieren
            toaddress = toaddress.decode("utf-8", "replace") if toaddress else ""
            fromaddress = fromaddress.decode("utf-8", "replace") if fromaddress else ""
            subject = subject.decode("utf-8", "replace") if subject else ""
            # WICHTIG: message bleibt message, wird nicht in body umbenannt!
            message = message.decode("utf-8", "replace") if message else ""
            TTL = ttl if ttl else 216000  # Default TTL
            retryNumber = retrynumber if retrynumber else 0
            encoding = encodingtype if encodingtype else 2  # Default encoding
            status = status.decode("utf-8", "replace") if status else "msgqueued"
            
            self.logger.debug(f"  To: {toaddress}")
            self.logger.debug(f"  From: {fromaddress}")
            self.logger.debug(f"  Subject: {subject[:50]}")
            self.logger.debug(f"  Message length: {len(message) if message else 0}")
            self.logger.debug(f"  TTL: {TTL}, Retry: {retryNumber}, Encoding: {encoding}")
            
            # toStatus
            _, toAddressVersionNumber, toStreamNumber, toRipe = \
                decodeAddress(toaddress)
            # fromStatus, , ,fromRipe
            _, fromAddressVersionNumber, fromStreamNumber, _ = \
                decodeAddress(fromaddress)

            # We may or may not already have the pubkey
            # for this toAddress. Let's check.
            if status == 'forcepow':
                # if the status of this msg is 'forcepow'
                # then clearly we have the pubkey already
                # because the user could not have overridden the message
                # about the POW being too difficult without knowing
                # the required difficulty.
                pass
            elif status == 'doingmsgpow':
                # We wouldn't have set the status to doingmsgpow
                # if we didn't already have the pubkey so let's assume
                # that we have it.
                pass
            # If we are sending a message to ourselves or a chan
            # then we won't need an entry in the pubkeys table;
            # we can calculate the needed pubkey using the private keys
            # in our keys.dat file.
            elif config.has_section(toaddress):
                if not sqlExecute(
                    '''UPDATE sent SET status='doingmsgpow' '''
                    ''' WHERE toaddress=? AND status='msgqueued' AND folder='sent' ''',
                    dbstr(toaddress)
                ):
                    continue
                status = 'doingmsgpow'
            elif status == 'msgqueued':
                # Let's see if we already have the pubkey in our pubkeys table
                queryreturn2 = sqlQuery(
                    '''SELECT address FROM pubkeys WHERE address=?''',
                    dbstr(toaddress)
                )
                # If we have the needed pubkey in the pubkey table already,
                if queryreturn2 != []:
                    # set the status of this msg to doingmsgpow
                    if not sqlExecute(
                        '''UPDATE sent SET status='doingmsgpow' '''
                        ''' WHERE toaddress=? AND status='msgqueued' AND folder='sent' ''',
                        dbstr(toaddress)
                    ):
                        continue
                    status = 'doingmsgpow'
                    # mark the pubkey as 'usedpersonally' so that
                    # we don't delete it later. If the pubkey version
                    # is >= 4 then usedpersonally will already be set
                    # to yes because we'll only ever have
                    # usedpersonally v4 pubkeys in the pubkeys table.
                    sqlExecute(
                        '''UPDATE pubkeys SET usedpersonally='yes' '''
                        ''' WHERE address=?''',
                        dbstr(toaddress)
                    )
                # We don't have the needed pubkey in the pubkeys table already.
                else:
                    if toAddressVersionNumber <= 3:
                        toTag = b''
                    else:
                        toTag = highlevelcrypto.double_sha512(
                            encodeVarint(toAddressVersionNumber)
                            + encodeVarint(toStreamNumber) + toRipe
                        )[32:]
                    toTag_bytes = bytes(toTag)
                    if toaddress in state.neededPubkeys or \
                            toTag_bytes in state.neededPubkeys:
                        # We already sent a request for the pubkey
                        sqlExecute(
                            '''UPDATE sent SET status='awaitingpubkey', '''
                            ''' sleeptill=? WHERE toaddress=? '''
                            ''' AND status='msgqueued' ''',
                            int(time.time()) + 2.5 * 24 * 60 * 60,
                            dbstr(toaddress)
                        )
                        queues.UISignalQueue.put((
                            'updateSentItemStatusByToAddress', (
                                toaddress, _translate(
                                    "MainWindow",
                                    "Encryption key was requested earlier."))
                        ))
                        # on with the next msg on which we can do some work
                        continue
                    else:
                        # We have not yet sent a request for the pubkey
                        needToRequestPubkey = True
                        # If we are trying to send to address
                        # version >= 4 then the needed pubkey might be
                        # encrypted in the inventory.
                        # If we have it we'll need to decrypt it
                        # and put it in the pubkeys table.

                        # The decryptAndCheckPubkeyPayload function
                        # expects that the shared.neededPubkeys dictionary
                        # already contains the toAddress and cryptor
                        # object associated with the tag for this toAddress.
                        if toAddressVersionNumber >= 4:
                            doubleHashOfToAddressData = \
                                highlevelcrypto.double_sha512(
                                    encodeVarint(toAddressVersionNumber)
                                    + encodeVarint(toStreamNumber) + toRipe
                                )
                            # The first half of the sha512 hash.
                            privEncryptionKey = doubleHashOfToAddressData[:32]
                            # The second half of the sha512 hash.
                            tag = doubleHashOfToAddressData[32:]
                            tag_bytes = bytes(tag)
                            state.neededPubkeys[tag_bytes] = (
                                toaddress,
                                highlevelcrypto.makeCryptor(
                                    hexlify(privEncryptionKey))
                            )

                            for value in state.Inventory.by_type_and_tag(1, toTag):
                                # if valid, this function also puts it
                                # in the pubkeys table.
                                if protocol.decryptAndCheckPubkeyPayload(
                                        value.payload, toaddress
                                ) == 'successful':
                                    needToRequestPubkey = False
                                    sqlExecute(
                                        '''UPDATE sent SET '''
                                        ''' status='doingmsgpow', '''
                                        ''' retrynumber=0 WHERE '''
                                        ''' toaddress=? AND '''
                                        ''' (status='msgqueued' or '''
                                        ''' status='awaitingpubkey' or '''
                                        ''' status='doingpubkeypow') AND '''
                                        ''' folder='sent' ''',
                                        dbstr(toaddress))
                                    del state.neededPubkeys[tag_bytes]
                                    break
                                # else:
                                # There was something wrong with this
                                # pubkey object even though it had
                                # the correct tag- almost certainly
                                # because of malicious behavior or
                                # a badly programmed client. If there are
                                # any other pubkeys in our inventory
                                # with the correct tag then we'll try
                                # to decrypt those.
                        if needToRequestPubkey:
                            sqlExecute(
                                '''UPDATE sent SET '''
                                ''' status='doingpubkeypow' WHERE '''
                                ''' toaddress=? AND status='msgqueued' AND folder='sent' ''',
                                dbstr(toaddress)
                            )
                            queues.UISignalQueue.put((
                                'updateSentItemStatusByToAddress', (
                                    toaddress, _translate(
                                        "MainWindow",
                                        "Sending a request for the"
                                        " recipient\'s encryption key."))
                            ))
                            self.requestPubKey(toaddress)
                            # on with the next msg on which we can do some work
                            continue

            # At this point we know that we have the necessary pubkey
            # in the pubkeys table.

            TTL *= 2**retryNumber
            if TTL > 28 * 24 * 60 * 60:
                TTL = 28 * 24 * 60 * 60
            # add some randomness to the TTL
            TTL = int(TTL + helper_random.randomrandrange(-300, 300))
            embeddedTime = int(time.time() + TTL)

            # if we aren't sending this to ourselves or a chan
            if not config.has_section(toaddress):
                state.ackdataForWhichImWatching[bytes(ackdata)] = 0
                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata, _translate(
                            "MainWindow",
                            "Looking up the receiver\'s public key"))
                ))
                self.logger.info('Sending a message.')
                self.logger.debug(
                    'First 150 characters of message: %s',
                    repr(message[:150])
                )

                # Let us fetch the recipient's public key out of
                # our database. If the required proof of work difficulty
                # is too hard then we'll abort.
                queryreturn3 = sqlQuery(
                    'SELECT transmitdata FROM pubkeys WHERE address=?',
                    dbstr(toaddress))
                for row2 in queryreturn3:
                    pubkeyPayload, = row2

                # The pubkey message is stored with the following items
                # all appended:
                #    -address version
                #    -stream number
                #    -behavior bitfield
                #    -pub signing key
                #    -pub encryption key
                #    -nonce trials per byte (if address version is >= 3)
                #    -length extra bytes (if address version is >= 3)

                # to bypass the address version whose length is definitely 1
                readPosition = 1
                _, streamNumberLength = decodeVarint(
                    pubkeyPayload[readPosition:readPosition + 10])
                readPosition += streamNumberLength
                behaviorBitfield = pubkeyPayload[readPosition:readPosition + 4]
                # Mobile users may ask us to include their address's
                # RIPE hash on a message unencrypted. Before we actually
                # do it the sending human must check a box
                # in the settings menu to allow it.

                # if receiver is a mobile device who expects that their
                # address RIPE is included unencrypted on the front of
                # the message..
                if protocol.isBitSetWithinBitfield(behaviorBitfield, 30):
                    # if we are Not willing to include the receiver's
                    # RIPE hash on the message..
                    if not config.safeGetBoolean(
                            'bitmessagesettings', 'willinglysendtomobile'
                    ):
                        self.logger.info(
                            'The receiver is a mobile user but the'
                            ' sender (you) has not selected that you'
                            ' are willing to send to mobiles. Aborting'
                            ' send.'
                        )
                        queues.UISignalQueue.put((
                            'updateSentItemStatusByAckdata', (
                                ackdata, _translate(
                                    "MainWindow",
                                    "Problem: Destination is a mobile"
                                    " device who requests that the"
                                    " destination be included in the"
                                    " message but this is disallowed in"
                                    " your settings.  {0}"
                                ).format(l10n.formatTimestamp()))
                        ))
                        # if the human changes their setting and then
                        # sends another message or restarts their client,
                        # this one will send at that time.
                        continue
                readPosition += 4  # to bypass the bitfield of behaviors
                # We don't use this key for anything here.
                # pubSigningKeyBase256 =
                # pubkeyPayload[readPosition:readPosition+64]
                readPosition += 64
                pubEncryptionKeyBase256 = pubkeyPayload[
                    readPosition:readPosition + 64]
                readPosition += 64

                # Let us fetch the amount of work required by the recipient.
                if toAddressVersionNumber == 2:
                    requiredAverageProofOfWorkNonceTrialsPerByte = \
                        defaults.networkDefaultProofOfWorkNonceTrialsPerByte
                    requiredPayloadLengthExtraBytes = \
                        defaults.networkDefaultPayloadLengthExtraBytes
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata, _translate(
                                "MainWindow",
                                "Doing work necessary to send message.\n"
                                "There is no required difficulty for"
                                " version 2 addresses like this."))
                    ))
                elif toAddressVersionNumber >= 3:
                    requiredAverageProofOfWorkNonceTrialsPerByte, \
                        varintLength = decodeVarint(
                            pubkeyPayload[readPosition:readPosition + 10])
                    readPosition += varintLength
                    requiredPayloadLengthExtraBytes, varintLength = \
                        decodeVarint(
                            pubkeyPayload[readPosition:readPosition + 10])
                    readPosition += varintLength
                    # We still have to meet a minimum POW difficulty
                    # regardless of what they say is allowed in order
                    # to get our message to propagate through the network.
                    if requiredAverageProofOfWorkNonceTrialsPerByte < \
                            defaults.networkDefaultProofOfWorkNonceTrialsPerByte:
                        requiredAverageProofOfWorkNonceTrialsPerByte = \
                            defaults.networkDefaultProofOfWorkNonceTrialsPerByte
                    if requiredPayloadLengthExtraBytes < \
                            defaults.networkDefaultPayloadLengthExtraBytes:
                        requiredPayloadLengthExtraBytes = \
                            defaults.networkDefaultPayloadLengthExtraBytes
                    self.logger.debug(
                        'Using averageProofOfWorkNonceTrialsPerByte: %s'
                        ' and payloadLengthExtraBytes: %s.',
                        requiredAverageProofOfWorkNonceTrialsPerByte,
                        requiredPayloadLengthExtraBytes
                    )
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata, _translate(
                                "MainWindow",
                                "Doing work necessary to send message.\n"
                                "Receiver\'s required difficulty: {0} and {1}"
                            ).format(
                                float(requiredAverageProofOfWorkNonceTrialsPerByte)
                                / defaults.networkDefaultProofOfWorkNonceTrialsPerByte,
                                float(requiredPayloadLengthExtraBytes)
                                / defaults.networkDefaultPayloadLengthExtraBytes
                            ))
                    ))
                    if status != 'forcepow':
                        maxacceptablenoncetrialsperbyte = config.getint(
                            'bitmessagesettings', 'maxacceptablenoncetrialsperbyte')
                        maxacceptablepayloadlengthextrabytes = config.getint(
                            'bitmessagesettings', 'maxacceptablepayloadlengthextrabytes')
                        cond1 = maxacceptablenoncetrialsperbyte and \
                            requiredAverageProofOfWorkNonceTrialsPerByte > maxacceptablenoncetrialsperbyte
                        cond2 = maxacceptablepayloadlengthextrabytes and \
                            requiredPayloadLengthExtraBytes > maxacceptablepayloadlengthextrabytes

                        if cond1 or cond2:
                            # The demanded difficulty is more than
                            # we are willing to do.
                            rowcount = sqlExecute(
                                '''UPDATE sent SET status='toodifficult' '''
                                ''' WHERE ackdata=? AND folder='sent' ''',
                                sqlite3.Binary(ackdata))
                            if rowcount < 1:
                                sqlExecute(
                                    '''UPDATE sent SET status='toodifficult' '''
                                    ''' WHERE ackdata=CAST(? AS TEXT) AND folder='sent' ''',
                                    ackdata)
                            queues.UISignalQueue.put((
                                'updateSentItemStatusByAckdata', (
                                    ackdata, _translate(
                                        "MainWindow",
                                        "Problem: The work demanded by the"
                                        " recipient ({0} and {1}) is more"
                                        " difficult than you are willing"
                                        " to do. {2}"
                                    ).format(
                                        float(requiredAverageProofOfWorkNonceTrialsPerByte)
                                        / defaults.networkDefaultProofOfWorkNonceTrialsPerByte,
                                        float(requiredPayloadLengthExtraBytes)
                                        / defaults.networkDefaultPayloadLengthExtraBytes,
                                        l10n.formatTimestamp()))
                            ))
                            continue
            else:  # if we are sending a message to ourselves or a chan..
                self.logger.info('Sending a message.')
                self.logger.debug(
                    'First 150 characters of message: %r', message[:150])
                behaviorBitfield = protocol.getBitfield(fromaddress)

                try:
                    privEncryptionKeyBase58 = config.get(
                        toaddress, 'privencryptionkey')
                except (configparser.NoSectionError, configparser.NoOptionError) as err:
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata, _translate(
                                "MainWindow",
                                "Problem: You are trying to send a"
                                " message to yourself or a chan but your"
                                " encryption key could not be found in"
                                " the keys.dat file. Could not encrypt"
                                " message. {0}"
                            ).format(l10n.formatTimestamp()))
                    ))
                    self.logger.error(
                        'Error within sendMsg. Could not read the keys'
                        ' from the keys.dat file for our own address. %s\n',
                        err)
                    continue
                privEncryptionKeyHex = hexlify(
                    highlevelcrypto.decodeWalletImportFormat(
                        privEncryptionKeyBase58.encode()))
                pubEncryptionKeyBase256 = unhexlify(highlevelcrypto.privToPub(
                    privEncryptionKeyHex))[1:]
                requiredAverageProofOfWorkNonceTrialsPerByte = \
                    defaults.networkDefaultProofOfWorkNonceTrialsPerByte
                requiredPayloadLengthExtraBytes = \
                    defaults.networkDefaultPayloadLengthExtraBytes
                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata, _translate(
                            "MainWindow",
                            "Doing work necessary to send message."))
                ))
                # Setze pubkeyPayload auf None für den Fall, dass später darauf zugegriffen wird
                pubkeyPayload = None

            # Now we can start to assemble our message.
            payload = encodeVarint(fromAddressVersionNumber)
            payload += encodeVarint(fromStreamNumber)
            # Bitfield of features and behaviors
            # that can be expected from me. (See
            # https://bitmessage.org/wiki/Protocol_specification#Pubkey_bitfield_features)
            payload += protocol.getBitfield(fromaddress)

            # We need to convert our private keys to public keys in order
            # to include them.
            try:
                privSigningKeyHex, privEncryptionKeyHex, \
                    pubSigningKey, pubEncryptionKey = self._getKeysForAddress(
                        fromaddress)
            except ValueError:
                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata, _translate(
                            "MainWindow",
                            "Error! Could not find sender address"
                            " (your address) in the keys.dat file."))
                ))
                continue
            except Exception as err:
                self.logger.error(
                    'Error within sendMsg. Could not read'
                    ' the keys from the keys.dat file for a requested'
                    ' address. %s\n', err
                )
                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata,
                        _translate(
                            "MainWindow",
                            "Error, can't send."))
                ))
                continue

            payload += pubSigningKey + pubEncryptionKey

            if fromAddressVersionNumber >= 3:
                # If the receiver of our message is in our address book,
                # subscriptions list, or whitelist then we will allow them to
                # do the network-minimum proof of work. Let us check to see if
                # the receiver is in any of those lists.
                if shared.isAddressInMyAddressBookSubscriptionsListOrWhitelist(
                        toaddress):
                    payload += encodeVarint(
                        defaults.networkDefaultProofOfWorkNonceTrialsPerByte)
                    payload += encodeVarint(
                        defaults.networkDefaultPayloadLengthExtraBytes)
                else:
                    payload += encodeVarint(config.getint(
                        fromaddress, 'noncetrialsperbyte'))
                    payload += encodeVarint(config.getint(
                        fromaddress, 'payloadlengthextrabytes'))

            # This hash will be checked by the receiver of the message
            # to verify that toRipe belongs to them. This prevents
            # a Surreptitious Forwarding Attack.
            payload += toRipe
            payload += encodeVarint(encoding)  # message encoding type
            encodedMessage = helper_msgcoding.MsgEncode(
                {"subject": subject, "body": message}, encoding
            )
            payload += encodeVarint(encodedMessage.length)
            payload += encodedMessage.data
            if config.has_section(toaddress):
                self.logger.info(
                    'Not bothering to include ackdata because we are'
                    ' sending to ourselves or a chan.'
                )
                fullAckPayload = b''
            elif not protocol.checkBitfield(
                    behaviorBitfield, protocol.BITFIELD_DOESACK):
                self.logger.info(
                    'Not bothering to include ackdata because'
                    ' the receiver said that they won\'t relay it anyway.'
                )
                fullAckPayload = b''
            else:
                # The fullAckPayload is a normal msg protocol message
                # with the proof of work already completed that the
                # receiver of this message can easily send out.
                fullAckPayload = self.generateFullAckMessage(ackdata, TTL)
            payload += encodeVarint(len(fullAckPayload))
            payload += fullAckPayload
            dataToSign = pack('>Q', embeddedTime) + b'\x00\x00\x00\x02' + \
                encodeVarint(1) + encodeVarint(toStreamNumber) + payload
            signature = highlevelcrypto.sign(
                dataToSign, privSigningKeyHex, self.digestAlg)
            payload += encodeVarint(len(signature))
            payload += signature

            # We have assembled the data that will be encrypted.
            try:
                encrypted = highlevelcrypto.encrypt(
                    payload, b"04" + hexlify(pubEncryptionKeyBase256)
                )
            except:  # noqa:E722
                self.logger.warning("highlevelcrypto.encrypt didn't work")
                rowcount = sqlExecute(
                    '''UPDATE sent SET status='badkey' WHERE ackdata=? AND folder='sent' ''',
                    sqlite3.Binary(ackdata)
                )
                if rowcount < 1:
                    sqlExecute(
                        '''UPDATE sent SET status='badkey' WHERE ackdata=CAST(? AS TEXT) AND folder='sent' ''',
                        ackdata
                    )
                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata, _translate(
                            "MainWindow",
                            "Problem: The recipient\'s encryption key is"
                            " no good. Could not encrypt message. {0}"
                        ).format(l10n.formatTimestamp()))
                ))
                continue

            encryptedPayload = pack('>Q', embeddedTime)
            encryptedPayload += b'\x00\x00\x00\x02'  # object type: msg
            encryptedPayload += encodeVarint(1)  # msg version
            encryptedPayload += encodeVarint(toStreamNumber) + encrypted
            target = 2 ** 64 / (
                requiredAverageProofOfWorkNonceTrialsPerByte * (
                    len(encryptedPayload) + 8
                    + requiredPayloadLengthExtraBytes + ((
                        TTL * (
                            len(encryptedPayload) + 8
                            + requiredPayloadLengthExtraBytes
                        )) / (2 ** 16))
                ))
            self.logger.info(
                '(For msg message) Doing proof of work. Total required'
                ' difficulty: %f. Required small message difficulty: %f.',
                float(requiredAverageProofOfWorkNonceTrialsPerByte)
                / defaults.networkDefaultProofOfWorkNonceTrialsPerByte,
                float(requiredPayloadLengthExtraBytes)
                / defaults.networkDefaultPayloadLengthExtraBytes
            )

            powStartTime = time.time()
            initialHash = hashlib.sha512(encryptedPayload).digest()
            trialValue, nonce = proofofwork.run(target, initialHash)
            self.logger.info(
                '(For msg message) Found proof of work %s Nonce: %s',
                trialValue, nonce
            )
            try:
                self.logger.info(
                    'PoW took %.1f seconds, speed %s.',
                    time.time() - powStartTime,
                    sizeof_fmt(nonce / (time.time() - powStartTime))
                )
            except:  # noqa:E722
                self.logger.warning("Proof of Work exception")

            encryptedPayload = pack('>Q', nonce) + encryptedPayload

            # Sanity check. The encryptedPayload size should never be
            # larger than 256 KiB. There should be checks elsewhere
            # in the code to not let the user try to send a message
            # this large until we implement message continuation.
            if len(encryptedPayload) > 2 ** 18:  # 256 KiB
                self.logger.critical(
                    'This msg object is too large to send. This should'
                    ' never happen. Object size: %i',
                    len(encryptedPayload)
                )
                continue

            inventoryHash = highlevelcrypto.calculateInventoryHash(encryptedPayload)
            objectType = 2
            state.Inventory[inventoryHash] = (
                objectType, toStreamNumber, encryptedPayload, embeddedTime, '')
            if config.has_section(toaddress) or \
               not protocol.checkBitfield(behaviorBitfield, protocol.BITFIELD_DOESACK):
                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata, _translate(
                            "MainWindow", "Message sent. Sent at {0}"
                        ).format(l10n.formatTimestamp()))
                ))
            else:
                # not sending to a chan or one of my addresses
                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata, _translate(
                            "MainWindow",
                            "Message sent. Waiting for acknowledgement."
                            " Sent on {0}"
                        ).format(l10n.formatTimestamp()))
                ))
            self.logger.info(
                'Broadcasting inv for my msg(within sendmsg function): %s',
                hexlify(inventoryHash)
            )
            invQueue.put((toStreamNumber, inventoryHash))

            # Update the sent message in the sent table with the
            # necessary information.
            if config.has_section(toaddress) or \
               not protocol.checkBitfield(behaviorBitfield, protocol.BITFIELD_DOESACK):
                newStatus = 'msgsentnoackexpected'
            else:
                newStatus = 'msgsent'
            # wait 10% past expiration
            sleepTill = int(time.time() + TTL * 1.1)
            rowcount = sqlExecute(
                '''UPDATE sent SET msgid=?, status=?, retrynumber=?, '''
                ''' sleeptill=?, lastactiontime=? WHERE ackdata=? AND folder='sent' ''',
                sqlite3.Binary(inventoryHash), dbstr(newStatus), retryNumber + 1,
                sleepTill, int(time.time()), sqlite3.Binary(ackdata)
            )
            if rowcount < 1:
                sqlExecute(
                    '''UPDATE sent SET msgid=?, status=?, retrynumber=?, '''
                    ''' sleeptill=?, lastactiontime=? WHERE ackdata=CAST(? AS TEXT) AND folder='sent' ''',
                    sqlite3.Binary(inventoryHash), newStatus, retryNumber + 1,
                    sleepTill, int(time.time()), ackdata
                )

            # If we are sending to ourselves or a chan, let's put
            # the message in our own inbox.
            if config.has_section(toaddress):
                # Used to detect and ignore duplicate messages in our inbox
                sigHash = highlevelcrypto.double_sha512(signature)[32:]
                t = (inventoryHash, toaddress, fromaddress, subject, int(
                    time.time()), message, 'inbox', encoding, 0, sigHash)
                helper_inbox.insert(t)

                queues.UISignalQueue.put(('displayNewInboxMessage', (
                    inventoryHash, toaddress, fromaddress, subject, message)))

                # If we are behaving as an API then we might need to run an
                # outside command to let some program know that a new message
                # has arrived.
                if config.safeGetBoolean(
                        'bitmessagesettings', 'apienabled'):

                    apiNotifyPath = config.safeGet(
                        'bitmessagesettings', 'apinotifypath')

                    if apiNotifyPath:
                        # There is no additional risk of remote exploitation or
                        # privilege escalation
                        call([apiNotifyPath, "newMessage"])  # nosec B603
        
        self.logger.debug("=== DEBUG sendMsg END ===")
    def requestPubKey(self, toAddress):
        """Send a getpubkey object"""
        toStatus, addressVersionNumber, streamNumber, ripe = decodeAddress(
            toAddress)
        if toStatus != 'success':
            self.logger.error(
                'Very abnormal error occurred in requestPubKey.'
                ' toAddress is: %r. Please report this error to Atheros.',
                toAddress
            )
            return

        queryReturn = sqlQuery(
            '''SELECT retrynumber FROM sent WHERE toaddress=? '''
            ''' AND (status='doingpubkeypow' OR status='awaitingpubkey') '''
            ''' AND folder='sent' LIMIT 1''',
            dbstr(toAddress)
        )
        if not queryReturn:
            self.logger.critical(
                'BUG: Why are we requesting the pubkey for %s'
                ' if there are no messages in the sent folder'
                ' to that address?', toAddress
            )
            return
        retryNumber = queryReturn[0][0]

        if addressVersionNumber <= 3:
            state.neededPubkeys[toAddress] = 0
        elif addressVersionNumber >= 4:
            # If the user just clicked 'send' then the tag
            # (and other information) will already be in the
            # neededPubkeys dictionary. But if we are recovering
            # from a restart of the client then we have to put it in now.

            doubleHashOfAddressData = highlevelcrypto.double_sha512(
                encodeVarint(addressVersionNumber)
                + encodeVarint(streamNumber) + ripe
            )
            privEncryptionKey = doubleHashOfAddressData[:32]
            # Note that this is the second half of the sha512 hash.
            tag = doubleHashOfAddressData[32:]
            tag_bytes = bytes(tag)
            if tag_bytes not in state.neededPubkeys:
                # We'll need this for when we receive a pubkey reply:
                # it will be encrypted and we'll need to decrypt it.
                state.neededPubkeys[tag_bytes] = (
                    toAddress,
                    highlevelcrypto.makeCryptor(hexlify(privEncryptionKey))
                )

        # 2.5 days. This was chosen fairly arbitrarily.
        TTL = 2.5 * 24 * 60 * 60
        TTL *= 2 ** retryNumber
        if TTL > 28 * 24 * 60 * 60:
            TTL = 28 * 24 * 60 * 60
        # add some randomness to the TTL
        TTL = TTL + helper_random.randomrandrange(-300, 300)
        embeddedTime = int(time.time() + TTL)
        payload = pack('>Q', embeddedTime)
        payload += b'\x00\x00\x00\x00'  # object type: getpubkey
        payload += encodeVarint(addressVersionNumber)
        payload += encodeVarint(streamNumber)
        if addressVersionNumber <= 3:
            payload += ripe
            self.logger.info(
                'making request for pubkey with ripe: %s', hexlify(ripe))
        else:
            payload += tag
            self.logger.info(
                'making request for v4 pubkey with tag: %s', hexlify(tag))

        statusbar = 'Doing the computations necessary to request' +\
            ' the recipient\'s public key.'
        queues.UISignalQueue.put(('updateStatusBar', statusbar))
        queues.UISignalQueue.put((
            'updateSentItemStatusByToAddress', (
                toAddress, _translate(
                    "MainWindow",
                    "Doing work necessary to request encryption key."))
        ))

        payload = self._doPOWDefaults(payload, TTL)

        inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
        objectType = 1
        state.Inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime, '')
        self.logger.info('sending inv (for the getpubkey message)')
        invQueue.put((streamNumber, inventoryHash))

        # wait 10% past expiration
        sleeptill = int(time.time() + TTL * 1.1)
        sqlExecute(
            '''UPDATE sent SET lastactiontime=?, '''
            ''' status='awaitingpubkey', retrynumber=?, sleeptill=? '''
            ''' WHERE toaddress=? AND (status='doingpubkeypow' OR '''
            ''' status='awaitingpubkey') AND folder='sent' ''',
            int(time.time()), retryNumber + 1, sleeptill, dbstr(toAddress))

        queues.UISignalQueue.put((
            'updateStatusBar', _translate(
                "MainWindow",
                "Broadcasting the public key request. This program will"
                " auto-retry if they are offline.")
        ))
        queues.UISignalQueue.put((
            'updateSentItemStatusByToAddress', (
                toAddress, _translate(
                    "MainWindow",
                    "Sending public key request. Waiting for reply."
                    " Requested at {0}"
                ).format(l10n.formatTimestamp()))
        ))

    def generateFullAckMessage(self, ackdata, TTL):
        """Create ACK packet"""
        # It might be perfectly fine to just use the same TTL for
        # the ackdata that we use for the message. But I would rather
        # it be more difficult for attackers to associate ackData with
        # the associated msg object. However, users would want the TTL
        # of the acknowledgement to be about the same as they set
        # for the message itself. So let's set the TTL of the
        # acknowledgement to be in one of three 'buckets': 1 hour, 7
        # days, or 28 days, whichever is relatively close to what the
        # user specified.
        if TTL < 24 * 60 * 60:  # 1 day
            TTL = 24 * 60 * 60  # 1 day
        elif TTL < 7 * 24 * 60 * 60:  # 1 week
            TTL = 7 * 24 * 60 * 60  # 1 week
        else:
            TTL = 28 * 24 * 60 * 60  # 4 weeks
        # Add some randomness to the TTL
        TTL = int(TTL + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)

        # type/version/stream already included
        payload = pack('>Q', (embeddedTime)) + ackdata

        payload = self._doPOWDefaults(
            payload, TTL, log_prefix='(For ack message)', log_time=True)

        return protocol.CreatePacket(b'object', payload)
