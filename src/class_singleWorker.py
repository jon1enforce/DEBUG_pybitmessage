"""
Thread for performing PoW
"""
# pylint: disable=protected-access,too-many-branches,too-many-statements
# pylint: disable=no-self-use,too-many-lines,too-many-locals

from __future__ import division
import sys
import hashlib
import time
from binascii import hexlify, unhexlify
import binascii
from struct import pack
from subprocess import call  # nosec
import sqlite3
import logging
import traceback

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

logger = logging.getLogger('default')

def sizeof_fmt(num, suffix='h/s'):
    """Format hashes per seconds nicely (SI prefix)"""
    logger.debug("DEBUG: Formatting hash rate for display")
    for unit in ['', 'k', 'M', 'G', 'T', 'P', 'E', 'Z']:
        if abs(num) < 1000.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


class singleWorker(StoppableThread):
    """Thread for performing PoW"""

    def __init__(self):
        logger.debug("DEBUG: Initializing singleWorker thread")
        super(singleWorker, self).__init__(name="singleWorker")
        self.digestAlg = config.safeGet(
            'bitmessagesettings', 'digestalg', 'sha256')
        proofofwork.init()
        logger.debug("DEBUG: singleWorker initialized with digest algorithm: %s", self.digestAlg)

    def stopThread(self):
        """Signal through the queue that the thread should be stopped"""
        logger.debug("DEBUG: Stopping singleWorker thread")
        try:
            queues.workerQueue.put(("stopThread", "data"))
            logger.debug("DEBUG: Stop signal sent to workerQueue")
        except queue.Full:
            logger.error('DEBUG: workerQueue is Full')
        super(singleWorker, self).stopThread()
        logger.debug("DEBUG: singleWorker thread stopped")

    def run(self):
        # pylint: disable=attribute-defined-outside-init
        logger.debug("DEBUG: Starting singleWorker main loop")

        while not helper_sql.sql_ready.wait(1.0) and state.shutdown == 0:
            self.stop.wait(1.0)
        if state.shutdown > 0:
            logger.debug("DEBUG: Shutdown detected, exiting singleWorker")
            return

        # Initialize the neededPubkeys dictionary.
        logger.debug("DEBUG: Initializing neededPubkeys")
        queryreturn = sqlQuery(
            '''SELECT DISTINCT toaddress FROM sent'''
            ''' WHERE (status='awaitingpubkey' AND folder='sent')''')
        for toAddress, in queryreturn:
            toAddress = toAddress.decode("utf-8", "replace")
            toAddressVersionNumber, toStreamNumber, toRipe = \
                decodeAddress(toAddress)[1:]
            logger.debug("DEBUG: Processing address %s (v%d)", toAddress, toAddressVersionNumber)
            if toAddressVersionNumber <= 3:
                state.neededPubkeys[toAddress] = 0
                logger.debug("DEBUG: Added v3/v2 pubkey request for %s", toAddress)
            elif toAddressVersionNumber >= 4:
                doubleHashOfAddressData = highlevelcrypto.double_sha512(
                    encodeVarint(toAddressVersionNumber)
                    + encodeVarint(toStreamNumber) + toRipe
                )
                privEncryptionKey = doubleHashOfAddressData[:32]
                tag = doubleHashOfAddressData[32:]
                state.neededPubkeys[bytes(tag)] = (
                    toAddress,
                    highlevelcrypto.makeCryptor(
                        hexlify(privEncryptionKey)))
                logger.debug("DEBUG: Added v4+ pubkey request with tag %s", hexlify(tag))

        # Initialize the state.ackdataForWhichImWatching data structure
        logger.debug("DEBUG: Initializing ackdata watcher")
        queryreturn = sqlQuery(
            '''SELECT ackdata FROM sent WHERE status = 'msgsent' AND folder = 'sent' ''')
        for row in queryreturn:
            ackdata, = row
            logger.info('DEBUG: Watching for ackdata %s', hexlify(ackdata))
            state.ackdataForWhichImWatching[bytes(ackdata)] = 0

        # Fix legacy (headerless) watched ackdata to include header
        logger.debug("DEBUG: Fixing legacy ackdata headers")
        for oldack in state.ackdataForWhichImWatching:
            if len(oldack) == 32:
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
                logger.debug("DEBUG: Fixed legacy ackdata %s", hexlify(oldack))

        # For the case if user deleted knownnodes but is still having onionpeer objects in inventory
        if not knownnodes.knownNodesActual:
            logger.debug("DEBUG: Processing orphaned onionpeer objects")
            for item in state.Inventory.by_type_and_tag(protocol.OBJECT_ONIONPEER):
                queues.objectProcessorQueue.put((
                    protocol.OBJECT_ONIONPEER, item.payload
                ))
                logger.debug("DEBUG: Queued orphaned onionpeer object for processing")

        # give some time for the GUI to start before we start on existing POW tasks.
        logger.debug("DEBUG: Waiting 10 seconds for GUI initialization")
        self.stop.wait(10)

        if state.shutdown:
            logger.debug("DEBUG: Shutdown detected during GUI wait")
            return

        logger.debug("DEBUG: Queuing initial work tasks")
        queues.workerQueue.put(('sendmessage', ''))
        queues.workerQueue.put(('sendbroadcast', ''))
        queues.workerQueue.put(('sendOnionPeerObj', ''))

        while state.shutdown == 0:
            self.busy = 0
            try:
                # Warte auf SQL-Bereitschaft
                while not helper_sql.sql_ready.wait(1.0) and state.shutdown == 0:
                    self.stop.wait(1.0)
            
                if state.shutdown > 0:
                    logger.debug("DEBUG: Shutdown detected, exiting singleWorker")
                    return

                # Queue-Item verarbeiten
                item = queues.workerQueue.get()
                if not isinstance(item, tuple):
                    logger.error("RAW INVALID ITEM: %s (Type: %s)", item, type(item))
                    logger.error("FULL TRACEBACK:\n%s", "".join(traceback.format_stack()))
                    continue
                
                if len(item) != 2:
                    logger.error("MALFORMED TUPLE: %s (Length: %d)", item, len(item))
                    logger.error("ORIGIN TRACE:\n%s", "".join(traceback.extract_stack()))
                    continue
                # Validierung des Queue-Items
                if not isinstance(item, tuple) or len(item) != 2:
                    logger.error("INVALID QUEUE ITEM RECEIVED: %s (Type: %s)", item, type(item))
                    logger.error("TRACE: %s", ''.join(traceback.format_stack()))
                    queues.workerQueue.task_done()  # Wichtig für Queue-Handling
                    continue
                
                command, data = item
                logger.debug("DEBUG: Processing command: %s", command)

                if command == 'sendmessage':
                    try:
                        logger.debug("DEBUG: Processing sendmessage command")
                        self.sendMsg()
                    except Exception as e:
                        logger.error("DEBUG: Error in sendMsg: %s", str(e))
                        logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())

                elif command == 'sendbroadcast':
                    try:
                        logger.debug("DEBUG: Processing sendbroadcast command")
                        self.sendBroadcast()
                    except Exception as e:
                        logger.error("DEBUG: Error in sendBroadcast: %s", str(e))
                        logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())

                elif command == 'doPOWForMyV2Pubkey':
                    try:
                        logger.debug("DEBUG: Processing doPOWForMyV2Pubkey command")
                        self.doPOWForMyV2Pubkey(data)
                    except Exception as e:
                        logger.error("DEBUG: Error in doPOWForMyV2Pubkey: %s", str(e))
                        logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())

                elif command == 'sendOutOrStoreMyV3Pubkey':
                    try:
                        logger.debug("DEBUG: Processing sendOutOrStoreMyV3Pubkey command")
                        self.sendOutOrStoreMyV3Pubkey(data)
                    except Exception as e:
                        logger.error("DEBUG: Error in sendOutOrStoreMyV3Pubkey: %s", str(e))
                        logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())

                elif command == 'sendOutOrStoreMyV4Pubkey':
                    try:
                        logger.debug("DEBUG: Processing sendOutOrStoreMyV4Pubkey command")
                        self.sendOutOrStoreMyV4Pubkey(data)
                    except Exception as e:
                        logger.error("DEBUG: Error in sendOutOrStoreMyV4Pubkey: %s", str(e))
                        logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())

                elif command == 'sendOnionPeerObj':
                    try:
                        logger.debug("DEBUG: Processing sendOnionPeerObj command")
                        self.sendOnionPeerObj(data)
                    except Exception as e:
                        logger.error("DEBUG: Error in sendOnionPeerObj: %s", str(e))
                        logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())

                elif command == 'resetPoW':
                    try:
                        logger.debug("DEBUG: Resetting PoW")
                        proofofwork.resetPoW()
                    except Exception as e:
                        logger.error("DEBUG: Error in resetPoW: %s", str(e))
                        logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())

                elif command == 'stopThread':
                    logger.debug("DEBUG: Received stopThread command")
                    self.busy = 0
                    return

                else:
                    logger.error(
                        'DEBUG: Probable programming error: The command sent'
                        ' to the workerThread is weird. It is: %s\n',
                        command
                    )

                queues.workerQueue.task_done()
            except Exception as e:
                logger.error("DEBUG: Error in singleWorker main loop: %s", str(e))
                logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())

        logger.info("DEBUG: singleWorker quitting...")

    def _getKeysForAddress(self, address):
        logger.debug("DEBUG: Getting keys for address %s", address)
        try:
            privSigningKeyBase58 = config.get(address, 'privsigningkey')
            privEncryptionKeyBase58 = config.get(address, 'privencryptionkey')
            logger.debug("DEBUG: Retrieved keys from config for %s", address)
        except (configparser.NoSectionError, configparser.NoOptionError):
            logger.error(
                'DEBUG: Could not read or decode privkey for address %s', address)
            raise ValueError

        privSigningKeyHex = hexlify(highlevelcrypto.decodeWalletImportFormat(
            privSigningKeyBase58.encode()))
        privEncryptionKeyHex = hexlify(
            highlevelcrypto.decodeWalletImportFormat(
                privEncryptionKeyBase58.encode()))
        logger.debug("DEBUG: Converted keys to hex format")

        pubSigningKey = unhexlify(highlevelcrypto.privToPub(
            privSigningKeyHex))[1:]
        pubEncryptionKey = unhexlify(highlevelcrypto.privToPub(
            privEncryptionKeyHex))[1:]
        logger.debug("DEBUG: Generated public keys from private keys")

        return privSigningKeyHex, privEncryptionKeyHex, \
            pubSigningKey, pubEncryptionKey

    def _doPOWDefaults(
            self, payload, TTL, log_prefix='', log_time=False):
        logger.debug("DEBUG: Calculating PoW target for payload length %d, TTL %d", len(payload), TTL)
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
        logger.info(
            '%s Doing proof of work... TTL set to %s', log_prefix, TTL)
        if log_time:
            start_time = time.time()
            logger.debug("DEBUG: Starting PoW timer")

        trialValue, nonce = proofofwork.run(target, initialHash)
        logger.info(
            '%s Found proof of work %s Nonce: %s',
            log_prefix, trialValue, nonce
        )
        try:
            delta = time.time() - start_time
            logger.info(
                'DEBUG: PoW took %.1f seconds, speed %s.',
                delta, sizeof_fmt(nonce / delta)
            )
        except NameError:
            logger.warning("DEBUG: Proof of Work exception - timer not started")
        payload = pack('>Q', nonce) + payload
        return payload

    def doPOWForMyV2Pubkey(self, adressHash):
        """
        This function also broadcasts out the pubkey message once it is
        done with the POW
        """
        logger.debug("DEBUG: Starting PoW for v2 pubkey with hash %s", hexlify(adressHash))
        myAddress = shared.myAddressesByHash[adressHash]
        addressVersionNumber, streamNumber = decodeAddress(myAddress)[1:3]
        logger.debug("DEBUG: Address details - version %d, stream %d", addressVersionNumber, streamNumber)

        TTL = int(28 * 24 * 60 * 60 + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)
        payload = pack('>Q', (embeddedTime))
        payload += b'\x00\x00\x00\x01'  # object type: pubkey
        payload += encodeVarint(addressVersionNumber)
        payload += encodeVarint(streamNumber)
        payload += protocol.getBitfield(myAddress)

        try:
            pubSigningKey, pubEncryptionKey = self._getKeysForAddress(
                myAddress)[2:]
            logger.debug("DEBUG: Retrieved keys for address %s", myAddress)
        except ValueError:
            logger.error("DEBUG: Failed to get keys for address %s", myAddress)
            return
        except Exception as e:
            logger.error(
                'DEBUG: Error getting keys from keys.dat for %s: %s',
                myAddress, str(e))
            logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())
            return

        payload += pubSigningKey + pubEncryptionKey

        payload = self._doPOWDefaults(
            payload, TTL, log_prefix='(For pubkey message)')

        inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
        objectType = 1
        state.Inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime, '')
        logger.info(
            'DEBUG: broadcasting inv with hash: %s', hexlify(inventoryHash))

        invQueue.put((streamNumber, inventoryHash))
        queues.UISignalQueue.put(('updateStatusBar', ''))
        try:
            config.set(
                myAddress, 'lastpubkeysendtime', str(int(time.time())))
            config.save()
            logger.debug("DEBUG: Updated lastpubkeysendtime for %s", myAddress)
        except configparser.NoSectionError:
            logger.warning("DEBUG: Address %s deleted before completion", myAddress)
        except Exception as e:
            logger.warning("DEBUG: Error updating config: %s", str(e))
            logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())

    def sendOutOrStoreMyV3Pubkey(self, adressHash):
        """
        If this isn't a chan address, this function assembles the pubkey
        data, does the necessary POW and sends it out.
        If it *is* a chan then it assembles the pubkey and stores it in
        the pubkey table so that we can send messages to "ourselves".
        """
        logger.debug("DEBUG: Processing v3 pubkey for hash %s", hexlify(adressHash))
        try:
            myAddress = shared.myAddressesByHash[adressHash]
            logger.debug("DEBUG: Found address %s for hash", myAddress)
        except KeyError:
            logger.warning(
                "DEBUG: Can't find %s in myAddressByHash", hexlify(adressHash))
            return

        if config.safeGetBoolean(myAddress, 'chan'):
            logger.info('DEBUG: This is a chan address. Not sending pubkey.')
            return

        _, addressVersionNumber, streamNumber, adressHash = decodeAddress(
            myAddress)
        logger.debug("DEBUG: Address details - version %d, stream %d", addressVersionNumber, streamNumber)

        TTL = int(28 * 24 * 60 * 60 + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)

        payload = pack('>Q', (embeddedTime))
        payload += b'\x00\x00\x00\x01'  # object type: pubkey
        payload += encodeVarint(addressVersionNumber)
        payload += encodeVarint(streamNumber)
        payload += protocol.getBitfield(myAddress)

        try:
            privSigningKeyHex, _, pubSigningKey, pubEncryptionKey = \
                self._getKeysForAddress(myAddress)
            logger.debug("DEBUG: Retrieved keys for address %s", myAddress)
        except ValueError:
            logger.error("DEBUG: Failed to get keys for address %s", myAddress)
            return
        except Exception as e:
            logger.error(
                'DEBUG: Error getting keys from keys.dat for %s: %s',
                myAddress, str(e))
            logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())
            return

        payload += pubSigningKey + pubEncryptionKey

        payload += encodeVarint(config.getint(
            myAddress, 'noncetrialsperbyte'))
        payload += encodeVarint(config.getint(
            myAddress, 'payloadlengthextrabytes'))
        logger.debug("DEBUG: Added PoW parameters to payload")

        signature = highlevelcrypto.sign(
            payload, privSigningKeyHex, self.digestAlg)
        payload += encodeVarint(len(signature))
        payload += signature
        logger.debug("DEBUG: Added signature to payload")

        payload = self._doPOWDefaults(
            payload, TTL, log_prefix='(For pubkey message)')

        inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
        objectType = 1
        state.Inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime, '')
        logger.info(
            'DEBUG: broadcasting inv with hash: %s', hexlify(inventoryHash))

        invQueue.put((streamNumber, inventoryHash))
        queues.UISignalQueue.put(('updateStatusBar', ''))
        try:
            config.set(
                myAddress, 'lastpubkeysendtime', str(int(time.time())))
            config.save()
            logger.debug("DEBUG: Updated lastpubkeysendtime for %s", myAddress)
        except configparser.NoSectionError:
            logger.warning("DEBUG: Address %s deleted before completion", myAddress)
        except Exception as e:
            logger.warning("DEBUG: Error updating config: %s", str(e))
            logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())

    def sendOutOrStoreMyV4Pubkey(self, myAddress):
        """
        It doesn't send directly anymore. It put is to a queue for
        another thread to send at an appropriate time, whereas in the
        past it directly appended it to the outgoing buffer, I think.
        Same with all the other methods in this class.
        """
        logger.debug("DEBUG: Processing v4 pubkey for address %s", myAddress)
        if not config.has_section(myAddress):
            logger.warning("DEBUG: Address %s has been deleted", myAddress)
            return
        if config.safeGetBoolean(myAddress, 'chan'):
            logger.info('DEBUG: This is a chan address. Not sending pubkey.')
            return

        _, addressVersionNumber, streamNumber, addressHash = decodeAddress(
            myAddress)
        logger.debug("DEBUG: Address details - version %d, stream %d", addressVersionNumber, streamNumber)

        TTL = int(28 * 24 * 60 * 60 + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)
        payload = pack('>Q', (embeddedTime))
        payload += b'\x00\x00\x00\x01'  # object type: pubkey
        payload += encodeVarint(addressVersionNumber)
        payload += encodeVarint(streamNumber)
        dataToEncrypt = protocol.getBitfield(myAddress)

        try:
            privSigningKeyHex, _, pubSigningKey, pubEncryptionKey = \
                self._getKeysForAddress(myAddress)
            logger.debug("DEBUG: Retrieved keys for address %s", myAddress)
        except ValueError:
            logger.error("DEBUG: Failed to get keys for address %s", myAddress)
            return
        except Exception as e:
            logger.error(
                'DEBUG: Error getting keys from keys.dat for %s: %s',
                myAddress, str(e))
            logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())
            return

        dataToEncrypt += pubSigningKey + pubEncryptionKey

        dataToEncrypt += encodeVarint(config.getint(
            myAddress, 'noncetrialsperbyte'))
        dataToEncrypt += encodeVarint(config.getint(
            myAddress, 'payloadlengthextrabytes'))
        logger.debug("DEBUG: Added PoW parameters to encrypted data")

        doubleHashOfAddressData = highlevelcrypto.double_sha512(
            encodeVarint(addressVersionNumber)
            + encodeVarint(streamNumber) + addressHash
        )
        payload += doubleHashOfAddressData[32:]  # the tag
        signature = highlevelcrypto.sign(
            payload + dataToEncrypt, privSigningKeyHex, self.digestAlg)
        dataToEncrypt += encodeVarint(len(signature))
        dataToEncrypt += signature
        logger.debug("DEBUG: Added signature to encrypted data")

        privEncryptionKey = doubleHashOfAddressData[:32]
        pubEncryptionKey = highlevelcrypto.pointMult(privEncryptionKey)
        payload += highlevelcrypto.encrypt(
            dataToEncrypt, hexlify(pubEncryptionKey))
        logger.debug("DEBUG: Encrypted payload data")

        payload = self._doPOWDefaults(
            payload, TTL, log_prefix='(For pubkey message)')

        inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
        objectType = 1
        state.Inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime,
            doubleHashOfAddressData[32:]
        )
        logger.info(
            'DEBUG: broadcasting inv with hash: %s', hexlify(inventoryHash))

        invQueue.put((streamNumber, inventoryHash))
        queues.UISignalQueue.put(('updateStatusBar', ''))
        try:
            config.set(
                myAddress, 'lastpubkeysendtime', str(int(time.time())))
            config.save()
            logger.debug("DEBUG: Updated lastpubkeysendtime for %s", myAddress)
        except Exception as err:
            logger.error(
                'DEBUG: Error updating lastpubkeysendtime: %s', err)

    def sendOnionPeerObj(self, peer=None):
        """Send onionpeer object representing peer"""
        logger.debug("DEBUG: Processing sendOnionPeerObj command")
        if not peer:  # find own onionhostname
            for peer in state.ownAddresses:
                if peer.host.endswith('.onion'):
                    break
            else:
                logger.debug("DEBUG: No onion address found")
                return

        logger.debug("DEBUG: Found onion peer: %s:%d", peer.host, peer.port)
        TTL = int(7 * 24 * 60 * 60 + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)
        streamNumber = 1  # Don't know yet what should be here
        objectType = protocol.OBJECT_ONIONPEER
        objectPayload = encodeVarint(peer.port) + protocol.encodeHost(peer.host)
        tag = highlevelcrypto.calculateInventoryHash(objectPayload)
        logger.debug("DEBUG: Created onionpeer object payload")

        if state.Inventory.by_type_and_tag(objectType, tag):
            logger.debug("DEBUG: Onionpeer object already exists and not expired")
            return

        payload = pack('>Q', embeddedTime)
        payload += pack('>I', objectType)
        payload += encodeVarint(2 if len(peer.host) == 22 else 3)
        payload += encodeVarint(streamNumber)
        payload += objectPayload
        logger.debug("DEBUG: Assembled onionpeer object")

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
            objectType, streamNumber, payload_buffer,
            embeddedTime, tag_buffer
        )
        logger.info(
            'DEBUG: sending inv for onionpeer object: %s',
            hexlify(inventoryHash))
        invQueue.put((streamNumber, inventoryHash))

    def sendBroadcast(self):
        """
        Send a broadcast-type object (assemble the object, perform PoW
        and put it to the inv announcement queue)
        """
        logger.debug("DEBUG: Starting sendBroadcast processing")
        sqlExecute(
            '''UPDATE sent SET status='broadcastqueued' '''
            '''WHERE status = 'doingbroadcastpow' AND folder = 'sent' ''')
        queryreturn = sqlQuery(
            '''SELECT fromaddress, subject, message, '''
            ''' ackdata, ttl, encodingtype FROM sent '''
            ''' WHERE status=? and folder='sent' ''', dbstr('broadcastqueued'))

        for row in queryreturn:
            fromaddress, subject, body, ackdata, TTL, encoding = row
            fromaddress = fromaddress.decode("utf-8", "replace")
            subject = subject.decode("utf-8", "replace")
            body = body.decode("utf-8", "replace")
            logger.debug("DEBUG: Processing broadcast from %s, subject: %s", fromaddress, subject)

            _, addressVersionNumber, streamNumber, ripe = \
                decodeAddress(fromaddress)
            if addressVersionNumber <= 1:
                logger.error(
                    'DEBUG: Unsupported address version %d for broadcast',
                    addressVersionNumber)
                return

            try:
                privSigningKeyHex, _, pubSigningKey, pubEncryptionKey = \
                    self._getKeysForAddress(fromaddress)
                logger.debug("DEBUG: Retrieved keys for address %s", fromaddress)
            except ValueError:
                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata, _translate(
                            "MainWindow",
                            "Error! Could not find sender address"
                            " (your address) in the keys.dat file."))
                ))
                logger.error("DEBUG: Could not find keys for %s", fromaddress)
                continue
            except Exception as err:
                logger.error(
                    'DEBUG: Error getting keys for %s: %s',
                    fromaddress, str(err))
                logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())
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
                logger.debug("DEBUG: No rows updated for ackdata %s", hexlify(ackdata))
                continue

            if TTL > 28 * 24 * 60 * 60:
                TTL = 28 * 24 * 60 * 60
            if TTL < 60 * 60:
                TTL = 60 * 60
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
            dataToEncrypt += protocol.getBitfield(fromaddress)
            dataToEncrypt += pubSigningKey + pubEncryptionKey
            if addressVersionNumber >= 3:
                dataToEncrypt += encodeVarint(config.getint(
                    fromaddress, 'noncetrialsperbyte'))
                dataToEncrypt += encodeVarint(config.getint(
                    fromaddress, 'payloadlengthextrabytes'))
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
            logger.debug("DEBUG: Assembled broadcast data")

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
            logger.debug("DEBUG: Encrypted broadcast data")

            queues.UISignalQueue.put((
                'updateSentItemStatusByAckdata', (
                    ackdata, _translate(
                        "MainWindow",
                        "Doing work necessary to send broadcast..."))
            ))
            payload = self._doPOWDefaults(
                payload, TTL, log_prefix='(For broadcast message)')

            if len(payload) > 2 ** 18:  # 256 KiB
                logger.critical(
                    'DEBUG: Broadcast too large to send: %d bytes',
                    len(payload)
                )
                continue

            inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
            objectType = 3
            state.Inventory[inventoryHash] = (
                objectType, streamNumber, payload, embeddedTime, tag)
            logger.info(
                'DEBUG: sending inv for broadcast: %s',
                hexlify(inventoryHash)
            )
            invQueue.put((streamNumber, inventoryHash))

            queues.UISignalQueue.put((
                'updateSentItemStatusByAckdata', (
                    ackdata, _translate(
                        "MainWindow", "Broadcast sent on {0}"
                    ).format(l10n.formatTimestamp()))
            ))

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
            logger.debug("DEBUG: Updated sent table for broadcast")

    def sendMsg(self):
        """
        Send a message-type object (assemble the object, perform PoW
        and put it to the inv announcement queue)
        """
        logger.debug("DEBUG: Starting sendMsg processing")
        sqlExecute(
            '''UPDATE sent SET status='msgqueued' '''
            ''' WHERE status IN ('doingpubkeypow', 'doingmsgpow') '''
            ''' AND folder='sent' ''')
        queryreturn = sqlQuery(
            '''SELECT toaddress, fromaddress, subject, message, '''
            ''' ackdata, status, ttl, retrynumber, encodingtype FROM '''
            ''' sent WHERE (status='msgqueued' or status='forcepow') '''
            ''' and folder='sent' ''')
        
        for row in queryreturn:
            toaddress, fromaddress, subject, message, \
                ackdata, status, TTL, retryNumber, encoding = row
            toaddress = toaddress.decode("utf-8", "replace")
            fromaddress = fromaddress.decode("utf-8", "replace")
            subject = subject.decode("utf-8", "replace")
            message = message.decode("utf-8", "replace")
            status = status.decode("utf-8", "replace")
            logger.debug("DEBUG: Processing message to %s, subject: %s", toaddress, subject)

            _, toAddressVersionNumber, toStreamNumber, toRipe = \
                decodeAddress(toaddress)
            _, fromAddressVersionNumber, fromStreamNumber, _ = \
                decodeAddress(fromaddress)

            if status == 'forcepow':
                logger.debug("DEBUG: ForcePoW status for message")
            elif status == 'doingmsgpow':
                logger.debug("DEBUG: DoingMsgPoW status for message")
            elif config.has_section(toaddress):
                if not sqlExecute(
                    '''UPDATE sent SET status='doingmsgpow' '''
                    ''' WHERE toaddress=? AND status='msgqueued' AND folder='sent' ''',
                    dbstr(toaddress)
                ):
                    continue
                status = 'doingmsgpow'
                logger.debug("DEBUG: Updated status to doingmsgpow")
            elif status == 'msgqueued':
                queryreturn = sqlQuery(
                    '''SELECT address FROM pubkeys WHERE address=?''',
                    dbstr(toaddress)
                )
                if queryreturn != []:
                    if not sqlExecute(
                        '''UPDATE sent SET status='doingmsgpow' '''
                        ''' WHERE toaddress=? AND status='msgqueued' AND folder='sent' ''',
                        dbstr(toaddress)
                    ):
                        continue
                    status = 'doingmsgpow'
                    sqlExecute(
                        '''UPDATE pubkeys SET usedpersonally='yes' '''
                        ''' WHERE address=?''',
                        dbstr(toaddress)
                    )
                    logger.debug("DEBUG: Found pubkey in database")
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
                        logger.debug("DEBUG: Already requested pubkey for %s", toaddress)
                        continue
                    else:
                        needToRequestPubkey = True
                        if toAddressVersionNumber >= 4:
                            doubleHashOfToAddressData = \
                                highlevelcrypto.double_sha512(
                                    encodeVarint(toAddressVersionNumber)
                                    + encodeVarint(toStreamNumber) + toRipe
                                )
                            privEncryptionKey = doubleHashOfToAddressData[:32]
                            tag = doubleHashOfToAddressData[32:]
                            tag_bytes = bytes(tag)
                            state.neededPubkeys[tag_bytes] = (
                                toaddress,
                                highlevelcrypto.makeCryptor(
                                    hexlify(privEncryptionKey))
                            )

                            for value in state.Inventory.by_type_and_tag(1, toTag):
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
                                    logger.debug("DEBUG: Found and decrypted pubkey in inventory")
                                    break

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
                            logger.debug("DEBUG: Requesting pubkey for %s", toaddress)
                            continue

            TTL *= 2**retryNumber
            if TTL > 28 * 24 * 60 * 60:
                TTL = 28 * 24 * 60 * 60
            TTL = int(TTL + helper_random.randomrandrange(-300, 300))
            embeddedTime = int(time.time() + TTL)

            if not config.has_section(toaddress):
                state.ackdataForWhichImWatching[bytes(ackdata)] = 0
                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata, _translate(
                            "MainWindow",
                            "Looking up the receiver\'s public key"))
                ))
                logger.info('DEBUG: Sending a message to external recipient')
                logger.debug(
                    'DEBUG: First 150 characters of message: %s',
                    repr(message[:150])
                )

                queryreturn = sqlQuery(
                    'SELECT transmitdata FROM pubkeys WHERE address=?',
                    dbstr(toaddress))
                for row in queryreturn:
                    pubkeyPayload, = row

                readPosition = 1
                _, streamNumberLength = decodeVarint(
                    pubkeyPayload[readPosition:readPosition + 10])
                readPosition += streamNumberLength
                behaviorBitfield = pubkeyPayload[readPosition:readPosition + 4]
                if protocol.isBitSetWithinBitfield(behaviorBitfield, 30):
                    if not config.safeGetBoolean(
                            'bitmessagesettings', 'willinglysendtomobile'
                    ):
                        logger.info(
                            'DEBUG: Receiver is mobile but sending disabled in settings')
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
                        continue
                readPosition += 4
                readPosition += 64
                pubEncryptionKeyBase256 = pubkeyPayload[
                    readPosition:readPosition + 64]
                readPosition += 64

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
                    if requiredAverageProofOfWorkNonceTrialsPerByte < \
                            defaults.networkDefaultProofOfWorkNonceTrialsPerByte:
                        requiredAverageProofOfWorkNonceTrialsPerByte = \
                            defaults.networkDefaultProofOfWorkNonceTrialsPerByte
                    if requiredPayloadLengthExtraBytes < \
                            defaults.networkDefaultPayloadLengthExtraBytes:
                        requiredPayloadLengthExtraBytes = \
                            defaults.networkDefaultPayloadLengthExtraBytes
                    logger.debug(
                        'DEBUG: Using averageProofOfWorkNonceTrialsPerByte: %s'
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
                            logger.info("DEBUG: PoW requirements too difficult")
                            continue
            else:
                logger.info('DEBUG: Sending message to self or chan')
                logger.debug(
                    'DEBUG: First 150 characters of message: %r', message[:150])
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
                    logger.error(
                        'DEBUG: Error getting encryption key for %s: %s',
                        toaddress, str(err))
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

            payload = encodeVarint(fromAddressVersionNumber)
            payload += encodeVarint(fromStreamNumber)
            payload += protocol.getBitfield(fromaddress)

            try:
                privSigningKeyHex, privEncryptionKeyHex, \
                    pubSigningKey, pubEncryptionKey = self._getKeysForAddress(
                        fromaddress)
                logger.debug("DEBUG: Retrieved keys for sender address %s", fromaddress)
            except ValueError:
                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata, _translate(
                            "MainWindow",
                            "Error! Could not find sender address"
                            " (your address) in the keys.dat file."))
                ))
                logger.error("DEBUG: Could not find keys for sender %s", fromaddress)
                continue
            except Exception as err:
                logger.error(
                    'DEBUG: Error getting keys for %s: %s',
                    fromaddress, str(err))
                logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())
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

            payload += toRipe
            payload += encodeVarint(encoding)
            encodedMessage = helper_msgcoding.MsgEncode(
                {"subject": subject, "body": message}, encoding
            )
            payload += encodeVarint(encodedMessage.length)
            payload += encodedMessage.data
            logger.debug("DEBUG: Assembled message payload")

            if config.has_section(toaddress):
                logger.debug("DEBUG: Sending to self/chan - no ackdata needed")
                fullAckPayload = b''
            elif not protocol.checkBitfield(
                    behaviorBitfield, protocol.BITFIELD_DOESACK):
                logger.debug("DEBUG: Receiver doesn't support ackdata")
                fullAckPayload = b''
            else:
                logger.debug("DEBUG: Generating ackdata")
                fullAckPayload = self.generateFullAckMessage(ackdata, TTL)
            payload += encodeVarint(len(fullAckPayload))
            payload += fullAckPayload
            dataToSign = pack('>Q', embeddedTime) + b'\x00\x00\x00\x02' + \
                encodeVarint(1) + encodeVarint(toStreamNumber) + payload
            signature = highlevelcrypto.sign(
                dataToSign, privSigningKeyHex, self.digestAlg)
            payload += encodeVarint(len(signature))
            payload += signature
            logger.debug("DEBUG: Signed message payload")

            try:
                encrypted = highlevelcrypto.encrypt(
                    payload, b"04" + hexlify(pubEncryptionKeyBase256)
                )
                logger.debug("DEBUG: Encrypted message payload")
            except Exception as e:
                logger.error("DEBUG: Encryption failed: %s", str(e))
                logger.debug("DEBUG: Stack trace: %s", traceback.format_exc())
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
            logger.info(
                'DEBUG: (For msg message) Doing proof of work. Total required'
                ' difficulty: %f. Required small message difficulty: %f.',
                float(requiredAverageProofOfWorkNonceTrialsPerByte)
                / defaults.networkDefaultProofOfWorkNonceTrialsPerByte,
                float(requiredPayloadLengthExtraBytes)
                / defaults.networkDefaultPayloadLengthExtraBytes
            )

            powStartTime = time.time()
            initialHash = hashlib.sha512(encryptedPayload).digest()
            trialValue, nonce = proofofwork.run(target, initialHash)
            logger.info(
                'DEBUG: (For msg message) Found proof of work %s Nonce: %s',
                trialValue, nonce
            )
            try:
                logger.info(
                    'DEBUG: PoW took %.1f seconds, speed %s.',
                    time.time() - powStartTime,
                    sizeof_fmt(nonce / (time.time() - powStartTime))
                )
            except Exception as e:
                logger.warning("DEBUG: PoW timing exception: %s", str(e))

            encryptedPayload = pack('>Q', nonce) + encryptedPayload

            if len(encryptedPayload) > 2 ** 18:  # 256 KiB
                logger.critical(
                    'DEBUG: Message too large to send: %d bytes',
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
                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata, _translate(
                            "MainWindow",
                            "Message sent. Waiting for acknowledgement."
                            " Sent on {0}"
                        ).format(l10n.formatTimestamp()))
                ))
            logger.info(
                'DEBUG: Broadcasting inv for message: %s',
                hexlify(inventoryHash)
            )
            invQueue.put((toStreamNumber, inventoryHash))

            if config.has_section(toaddress) or \
               not protocol.checkBitfield(behaviorBitfield, protocol.BITFIELD_DOESACK):
                newStatus = 'msgsentnoackexpected'
            else:
                newStatus = 'msgsent'
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
            logger.debug("DEBUG: Updated sent table for message")

            if config.has_section(toaddress):
                sigHash = highlevelcrypto.double_sha512(signature)[32:]
                t = (inventoryHash, toaddress, fromaddress, subject, int(
                    time.time()), message, 'inbox', encoding, 0, sigHash)
                helper_inbox.insert(t)

                queues.UISignalQueue.put(('displayNewInboxMessage', (
                    inventoryHash, toaddress, fromaddress, subject, message)))

                if config.safeGetBoolean(
                        'bitmessagesettings', 'apienabled'):
                    apiNotifyPath = config.safeGet(
                        'bitmessagesettings', 'apinotifypath')
                    if apiNotifyPath:
                        logger.debug("DEBUG: Calling API notify path")
                        call([apiNotifyPath, "newMessage"])  # nosec B603

    def requestPubKey(self, toAddress):
        """Send a getpubkey object"""
        logger.debug("DEBUG: Requesting pubkey for %s", toAddress)
        toStatus, addressVersionNumber, streamNumber, ripe = decodeAddress(
            toAddress)
        if toStatus != 'success':
            logger.error(
                'DEBUG: Abnormal error in requestPubKey for %s', toAddress)
            return

        queryReturn = sqlQuery(
            '''SELECT retrynumber FROM sent WHERE toaddress=? '''
            ''' AND (status='doingpubkeypow' OR status='awaitingpubkey') '''
            ''' AND folder='sent' LIMIT 1''',
            dbstr(toAddress)
        )
        if not queryReturn:
            logger.critical(
                'DEBUG: BUG: No messages to %s but requesting pubkey', toAddress)
            return
        retryNumber = queryReturn[0][0]

        if addressVersionNumber <= 3:
            state.neededPubkeys[toAddress] = 0
            logger.debug("DEBUG: Added v3/v2 pubkey request for %s", toAddress)
        elif addressVersionNumber >= 4:
            doubleHashOfAddressData = highlevelcrypto.double_sha512(
                encodeVarint(addressVersionNumber)
                + encodeVarint(streamNumber) + ripe
            )
            privEncryptionKey = doubleHashOfAddressData[:32]
            tag = doubleHashOfAddressData[32:]
            tag_bytes = bytes(tag)
            if tag_bytes not in state.neededPubkeys:
                state.neededPubkeys[tag_bytes] = (
                    toAddress,
                    highlevelcrypto.makeCryptor(hexlify(privEncryptionKey)))
                logger.debug("DEBUG: Added v4+ pubkey request with tag %s", hexlify(tag))

        TTL = 2.5 * 24 * 60 * 60
        TTL *= 2 ** retryNumber
        if TTL > 28 * 24 * 60 * 60:
            TTL = 28 * 24 * 60 * 60
        TTL = TTL + helper_random.randomrandrange(-300, 300)
        embeddedTime = int(time.time() + TTL)
        payload = pack('>Q', embeddedTime)
        payload += b'\x00\x00\x00\x00'  # object type: getpubkey
        payload += encodeVarint(addressVersionNumber)
        payload += encodeVarint(streamNumber)
        if addressVersionNumber <= 3:
            payload += ripe
            logger.info(
                'DEBUG: making request for pubkey with ripe: %s', hexlify(ripe))
        else:
            payload += tag
            logger.info(
                'DEBUG: making request for v4 pubkey with tag: %s', hexlify(tag))

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
        logger.info('DEBUG: sending inv (for the getpubkey message)')
        invQueue.put((streamNumber, inventoryHash))

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
        logger.debug("DEBUG: Generating ack message for %s", hexlify(ackdata))
        if TTL < 24 * 60 * 60:  # 1 day
            TTL = 24 * 60 * 60  # 1 day
        elif TTL < 7 * 24 * 60 * 60:  # 1 week
            TTL = 7 * 24 * 60 * 60  # 1 week
        else:
            TTL = 28 * 24 * 60 * 60  # 4 weeks
        TTL = int(TTL + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)

        payload = pack('>Q', (embeddedTime)) + ackdata

        payload = self._doPOWDefaults(
            payload, TTL, log_prefix='(For ack message)', log_time=True)
        logger.debug("DEBUG: Finished generating ack message")

        return protocol.CreatePacket(b'object', payload)
