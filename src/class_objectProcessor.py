"""
The objectProcessor thread, of which there is only one,
processes the network objects
"""
# pylint: disable=too-many-locals,too-many-return-statements
# pylint: disable=too-many-branches,too-many-statements
import hashlib
import logging
import os
import helper_random as random
import subprocess  # nosec B404
import threading
import time
from binascii import hexlify
import sqlite3

import helper_bitcoin
import helper_inbox
import helper_msgcoding
import helper_sent
import highlevelcrypto
import l10n
import protocol
import queues
import shared
import state
from addresses import (
    decodeAddress, decodeVarint,
    encodeAddress, encodeVarint, varintDecodeError
)
from bmconfigparser import config
from helper_sql import (
    sql_ready, sql_timeout, SqlBulkExecute, sqlExecute, sqlQuery)
from network import knownnodes, invQueue
from network.node import Peer
from tr import _translate
from dbcompat import dbstr

logger = logging.getLogger('default')


class objectProcessor(threading.Thread):
    """
    The objectProcessor thread, of which there is only one, receives network
    objects (msg, broadcast, pubkey, getpubkey) from the receiveDataThreads.
    """
    def __init__(self):
        threading.Thread.__init__(self, name="objectProcessor")
        random.seed()
        print("DEBUG: Initializing objectProcessor thread")
        if sql_ready.wait(sql_timeout) is False:
            logger.fatal('SQL thread is not started in %s sec', sql_timeout)
            os._exit(1)  # pylint: disable=protected-access
        print("DEBUG: SQL thread is ready")
        shared.reloadMyAddressHashes()
        shared.reloadBroadcastSendersForWhichImWatching()
        # It may be the case that the last time Bitmessage was running,
        # the user closed it before it finished processing everything in the
        # objectProcessorQueue. Assuming that Bitmessage wasn't closed
        # forcefully, it should have saved the data in the queue into the
        # objectprocessorqueue table. Let's pull it out.
        queryreturn = sqlQuery(
            'SELECT objecttype, data FROM objectprocessorqueue')
        for objectType, data in queryreturn:
            queues.objectProcessorQueue.put((objectType, data))
        sqlExecute('DELETE FROM objectprocessorqueue')
        logger.debug(
            'Loaded %s objects from disk into the objectProcessorQueue.',
            len(queryreturn))
        print(f"DEBUG: Loaded {len(queryreturn)} objects from disk queue")
        self.successfullyDecryptMessageTimings = []

    def run(self):
        """Process the objects from `.queues.objectProcessorQueue`"""
        print("DEBUG: Starting objectProcessor main loop")
        while True:
            objectType, data = queues.objectProcessorQueue.get()
            print(f"DEBUG: Processing object type: {objectType}, data length: {len(data)}")

            self.checkackdata(data)

            try:
                if objectType == protocol.OBJECT_GETPUBKEY:
                    print("DEBUG: Processing GETPUBKEY object")
                    self.processgetpubkey(data)
                elif objectType == protocol.OBJECT_PUBKEY:
                    print("DEBUG: Processing PUBKEY object")
                    self.processpubkey(data)
                elif objectType == protocol.OBJECT_MSG:
                    print("DEBUG: Processing MSG object")
                    self.processmsg(data)
                elif objectType == protocol.OBJECT_BROADCAST:
                    print("DEBUG: Processing BROADCAST object")
                    self.processbroadcast(data)
                elif objectType == protocol.OBJECT_ONIONPEER:
                    print("DEBUG: Processing ONIONPEER object")
                    self.processonion(data)
                # is more of a command, not an object type. Is used to get
                # this thread past the queue.get() so that it will check
                # the shutdown variable.
                elif objectType == 'checkShutdownVariable':
                    print("DEBUG: Checking shutdown variable")
                    pass
                else:
                    if isinstance(objectType, int):
                        logger.info(
                            'Don\'t know how to handle object type 0x%08X',
                            objectType)
                        print(f"DEBUG: Unknown object type: 0x{objectType:08X}")
                    else:
                        logger.info(
                            'Don\'t know how to handle object type %s',
                            objectType)
                        print(f"DEBUG: Unknown object type: {objectType}")
            except helper_msgcoding.DecompressionSizeException as e:
                logger.error(
                    'The object is too big after decompression (stopped'
                    ' decompressing at %ib, your configured limit %ib).'
                    ' Ignoring',
                    e.size, config.safeGetInt('zlib', 'maxsize'))
                print(f"DEBUG: Decompression size exception: {e.size} > {config.safeGetInt('zlib', 'maxsize')}")
            except varintDecodeError as e:
                logger.debug(
                    'There was a problem with a varint while processing an'
                    ' object. Some details: %s', e)
                print(f"DEBUG: Varint decode error: {str(e)}")
            except Exception:
                logger.critical(
                    'Critical error within objectProcessorThread: \n',
                    exc_info=True)
                print("DEBUG: Critical error in objectProcessor:")
                traceback.print_exc()
            if state.shutdown:
                print("DEBUG: Shutdown detected, saving queue to disk")
                # Wait just a moment for most of the connections to close
                time.sleep(.5)
                numberOfObjectsThatWereInTheObjectProcessorQueue = 0
                with SqlBulkExecute() as sql:
                    while queues.objectProcessorQueue.curSize > 0:
                        objectType, data = queues.objectProcessorQueue.get()
                        # Korrigierte Zeile:
                        sql.execute('INSERT INTO objectprocessorqueue VALUES (?,?)', 
                                   (objectType, sqlite3.Binary(data.encode() if isinstance(data, str) else data)))
                        numberOfObjectsThatWereInTheObjectProcessorQueue += 1
                logger.debug(
                    'Saved %s objects from the objectProcessorQueue to'
                    ' disk. objectProcessorThread exiting.',
                    numberOfObjectsThatWereInTheObjectProcessorQueue)
                print(f"DEBUG: Saved {numberOfObjectsThatWereInTheObjectProcessorQueue} objects to disk")
                state.shutdown = 2
                break


    @staticmethod
    def checkackdata(data):
        """Checking Acknowledgement of message received or not?"""
        print("DEBUG: Checking ackdata")
        # Let's check whether this is a message acknowledgement bound for us.
        if len(data) < 32:
            print("DEBUG: Data too short for ack check")
            return

        # bypass nonce and time, retain object type/version/stream + body
        readPosition = 16

        data_bytes = bytes(data[readPosition:])
        if data_bytes in state.ackdataForWhichImWatching:
            logger.info('This object is an acknowledgement bound for me.')
            print(f"DEBUG: Found matching ackdata: {hexlify(data_bytes)}")
            del state.ackdataForWhichImWatching[data_bytes]
            rowcount = sqlExecute(
                "UPDATE sent SET status='ackreceived', lastactiontime=?"
                " WHERE ackdata=?", int(time.time()), sqlite3.Binary(data_bytes))
            if rowcount < 1:
                rowcount = sqlExecute(
                    "UPDATE sent SET status='ackreceived', lastactiontime=?"
                    " WHERE ackdata=CAST(? AS TEXT)", int(time.time()), data_bytes)
            print(f"DEBUG: Updated {rowcount} rows in sent table")
            queues.UISignalQueue.put((
                'updateSentItemStatusByAckdata', (
                    data_bytes, _translate(
                        "MainWindow",
                        "Acknowledgement of the message received {0}"
                    ).format(l10n.formatTimestamp()))
            ))
        else:
            logger.debug('This object is not an acknowledgement bound for me.')
            print("DEBUG: No matching ackdata found")

    @staticmethod
    def processonion(data):
        """Process onionpeer object"""
        print("DEBUG: Processing onion peer object")
        readPosition = 20  # bypass the nonce, time, and object type
        length = decodeVarint(data[readPosition:readPosition + 10])[1]
        readPosition += length
        stream, length = decodeVarint(data[readPosition:readPosition + 10])
        readPosition += length
        # it seems that stream is checked in network.bmproto
        port, length = decodeVarint(data[readPosition:readPosition + 10])
        host = protocol.checkIPAddress(data[readPosition + length:])

        if not host:
            print("DEBUG: Invalid host in onion peer object")
            return
        peer = Peer(host, port)
        print(f"DEBUG: Adding onion peer: {host}:{port} for stream {stream}")
        with knownnodes.knownNodesLock:
            # FIXME: adjust expirestime
            knownnodes.addKnownNode(
                stream, peer, is_self=state.ownAddresses.get(peer))

    @staticmethod
    def processgetpubkey(data):
        """Process getpubkey object"""
        print("DEBUG: Processing getpubkey object")
        if len(data) > 200:
            print("DEBUG: Getpubkey too long, ignoring")
            return logger.info(
                'getpubkey is abnormally long. Sanity check failed.'
                ' Ignoring object.')
        readPosition = 20  # bypass the nonce, time, and object type
        requestedAddressVersionNumber, addressVersionLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += addressVersionLength
        streamNumber, streamNumberLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += streamNumberLength

        print(f"DEBUG: Getpubkey details - version: {requestedAddressVersionNumber}, stream: {streamNumber}")

        if requestedAddressVersionNumber == 0:
            print("DEBUG: Invalid address version 0")
            return logger.debug(
                'The requestedAddressVersionNumber of the pubkey request'
                ' is zero. That doesn\'t make any sense. Ignoring it.')
        if requestedAddressVersionNumber == 1:
            print("DEBUG: Unsupported address version 1")
            return logger.debug(
                'The requestedAddressVersionNumber of the pubkey request'
                ' is 1 which isn\'t supported anymore. Ignoring it.')
        if requestedAddressVersionNumber > 4:
            print("DEBUG: Unsupported high address version")
            return logger.debug(
                'The requestedAddressVersionNumber of the pubkey request'
                ' is too high. Can\'t understand. Ignoring it.')

        myAddress = ''
        if requestedAddressVersionNumber <= 3:
            requestedHash = data[readPosition:readPosition + 20]
            if len(requestedHash) != 20:
                print("DEBUG: Invalid hash length")
                return logger.debug(
                    'The length of the requested hash is not 20 bytes.'
                    ' Something is wrong. Ignoring.')
            logger.info(
                'the hash requested in this getpubkey request is: %s',
                hexlify(requestedHash))
            print(f"DEBUG: Requested hash: {hexlify(requestedHash)}")
            requestedHash_bytes = bytes(requestedHash)
            # if this address hash is one of mine
            if requestedHash_bytes in shared.myAddressesByHash:
                myAddress = shared.myAddressesByHash[requestedHash_bytes]
                print(f"DEBUG: Found matching address: {myAddress}")
        elif requestedAddressVersionNumber >= 4:
            requestedTag = data[readPosition:readPosition + 32]
            if len(requestedTag) != 32:
                print("DEBUG: Invalid tag length")
                return logger.debug(
                    'The length of the requested tag is not 32 bytes.'
                    ' Something is wrong. Ignoring.')
            logger.debug(
                'the tag requested in this getpubkey request is: %s',
                hexlify(requestedTag))
            print(f"DEBUG: Requested tag: {hexlify(requestedTag)}")
            requestedTag_bytes = bytes(requestedTag)
            if requestedTag_bytes in shared.myAddressesByTag:
                myAddress = shared.myAddressesByTag[requestedTag_bytes]
                print(f"DEBUG: Found matching address: {myAddress}")

        if myAddress == '':
            logger.info('This getpubkey request is not for any of my keys.')
            print("DEBUG: Getpubkey not for any of my addresses")
            return

        if decodeAddress(myAddress)[1] != requestedAddressVersionNumber:
            print("DEBUG: Address version mismatch")
            return logger.warning(
                '(Within the processgetpubkey function) Someone requested'
                ' one of my pubkeys but the requestedAddressVersionNumber'
                ' doesn\'t match my actual address version number.'
                ' Ignoring.')
        if decodeAddress(myAddress)[2] != streamNumber:
            print("DEBUG: Stream number mismatch")
            return logger.warning(
                '(Within the processgetpubkey function) Someone requested'
                ' one of my pubkeys but the stream number on which we'
                ' heard this getpubkey object doesn\'t match this'
                ' address\' stream number. Ignoring.')
        if config.safeGetBoolean(myAddress, 'chan'):
            print("DEBUG: Ignoring chan address request")
            return logger.info(
                'Ignoring getpubkey request because it is for one of my'
                ' chan addresses. The other party should already have'
                ' the pubkey.')
        lastPubkeySendTime = config.safeGetInt(
            myAddress, 'lastpubkeysendtime')
        # If the last time we sent our pubkey was more recent than
        # 28 days ago...
        if lastPubkeySendTime > time.time() - 2419200:
            print("DEBUG: Pubkey sent recently, ignoring")
            return logger.info(
                'Found getpubkey-requested-item in my list of EC hashes'
                ' BUT we already sent it recently. Ignoring request.'
                ' The lastPubkeySendTime is: %s', lastPubkeySendTime)
        logger.info(
            'Found getpubkey-requested-hash in my list of EC hashes.'
            ' Telling Worker thread to do the POW for a pubkey message'
            ' and send it out.')
        print("DEBUG: Queueing pubkey response")
        if requestedAddressVersionNumber == 2:
            queues.workerQueue.put(('doPOWForMyV2Pubkey', requestedHash))
        elif requestedAddressVersionNumber == 3:
            queues.workerQueue.put(('sendOutOrStoreMyV3Pubkey', requestedHash))
        elif requestedAddressVersionNumber == 4:
            queues.workerQueue.put(('sendOutOrStoreMyV4Pubkey', myAddress))

    def processpubkey(self, data):
        """Process a pubkey object"""
        pubkeyProcessingStartTime = time.time()
        state.numberOfPubkeysProcessed += 1
        queues.UISignalQueue.put((
            'updateNumberOfPubkeysProcessed', 'no data'))
        print("DEBUG: Processing pubkey object")
        readPosition = 20  # bypass the nonce, time, and object type
        addressVersion, varintLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += varintLength
        streamNumber, varintLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += varintLength
        print(f"DEBUG: Pubkey details - version: {addressVersion}, stream: {streamNumber}")
        if addressVersion == 0:
            print("DEBUG: Invalid address version 0")
            return logger.debug(
                '(Within processpubkey) addressVersion of 0 doesn\'t'
                ' make sense.')
        if addressVersion > 4 or addressVersion == 1:
            print(f"DEBUG: Unsupported address version {addressVersion}")
            return logger.info(
                'This version of Bitmessage cannot handle version %s'
                ' addresses.', addressVersion)
        if addressVersion == 2:
            # sanity check. This is the minimum possible length.
            if len(data) < 146:
                print("DEBUG: Pubkey too short for version 2")
                return logger.debug(
                    '(within processpubkey) payloadLength less than 146.'
                    ' Sanity check failed.')
            readPosition += 4
            pubSigningKey = b'\x04' + data[readPosition:readPosition + 64]
            # Is it possible for a public key to be invalid such that trying to
            # encrypt or sign with it will cause an error? If it is, it would
            # be easiest to test them here.
            readPosition += 64
            pubEncryptionKey = b'\x04' + data[readPosition:readPosition + 64]
            if len(pubEncryptionKey) < 65:
                print("DEBUG: Invalid encryption key length")
                return logger.debug(
                    'publicEncryptionKey length less than 64. Sanity check'
                    ' failed.')
            readPosition += 64
            # The data we'll store in the pubkeys table.
            dataToStore = data[20:readPosition]
            ripe = highlevelcrypto.to_ripe(pubSigningKey, pubEncryptionKey)

            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    'within recpubkey, addressVersion: %s, streamNumber: %s'
                    '\nripe %s\npublicSigningKey in hex: %s'
                    '\npublicEncryptionKey in hex: %s',
                    addressVersion, streamNumber, hexlify(ripe),
                    hexlify(pubSigningKey), hexlify(pubEncryptionKey)
                )
            print(f"DEBUG: RIPE: {hexlify(ripe)}")

            address = encodeAddress(addressVersion, streamNumber, ripe)
            print(f"DEBUG: Derived address: {address}")

            queryreturn = sqlQuery(
                "SELECT usedpersonally FROM pubkeys WHERE address=?"
                " AND usedpersonally='yes'", dbstr(address))
            # if this pubkey is already in our database and if we have
            # used it personally:
            if queryreturn != []:
                logger.info(
                    'We HAVE used this pubkey personally. Updating time.')
                print("DEBUG: Updating existing pubkey record")
                t = (dbstr(address), addressVersion, sqlite3.Binary(dataToStore),
                     int(time.time()), 'yes')
            else:
                logger.info(
                    'We have NOT used this pubkey personally. Inserting'
                    ' in database.')
                print("DEBUG: Inserting new pubkey record")
                t = (dbstr(address), addressVersion, sqlite3.Binary(dataToStore),
                     int(time.time()), 'no')
            sqlExecute('''INSERT INTO pubkeys VALUES (?,?,?,?,?)''', *t)
            print("DEBUG: Checking if pubkey is needed")
            self.possibleNewPubkey(address)
        if addressVersion == 3:
            if len(data) < 170:  # sanity check.
                print("DEBUG: Pubkey too short for version 3")
                logger.warning(
                    '(within processpubkey) payloadLength less than 170.'
                    ' Sanity check failed.')
                return
            readPosition += 4
            pubSigningKey = b'\x04' + data[readPosition:readPosition + 64]
            readPosition += 64
            pubEncryptionKey = b'\x04' + data[readPosition:readPosition + 64]
            readPosition += 64
            specifiedNonceTrialsPerByteLength = decodeVarint(
                data[readPosition:readPosition + 10])[1]
            readPosition += specifiedNonceTrialsPerByteLength
            specifiedPayloadLengthExtraBytesLength = decodeVarint(
                data[readPosition:readPosition + 10])[1]
            readPosition += specifiedPayloadLengthExtraBytesLength
            endOfSignedDataPosition = readPosition
            # The data we'll store in the pubkeys table.
            dataToStore = data[20:readPosition]
            signatureLength, signatureLengthLength = decodeVarint(
                data[readPosition:readPosition + 10])
            readPosition += signatureLengthLength
            signature = data[readPosition:readPosition + signatureLength]
            if highlevelcrypto.verify(
                    data[8:endOfSignedDataPosition],
                    signature, hexlify(pubSigningKey)):
                logger.debug('ECDSA verify passed (within processpubkey)')
                print("DEBUG: ECDSA verification passed")
            else:
                logger.warning('ECDSA verify failed (within processpubkey)')
                print("DEBUG: ECDSA verification failed")
                return

            ripe = highlevelcrypto.to_ripe(pubSigningKey, pubEncryptionKey)
            print(f"DEBUG: RIPE: {hexlify(ripe)}")

            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    'within recpubkey, addressVersion: %s, streamNumber: %s'
                    '\nripe %s\npublicSigningKey in hex: %s'
                    '\npublicEncryptionKey in hex: %s',
                    addressVersion, streamNumber, hexlify(ripe),
                    hexlify(pubSigningKey), hexlify(pubEncryptionKey)
                )

            address = encodeAddress(addressVersion, streamNumber, ripe)
            print(f"DEBUG: Derived address: {address}")
            queryreturn = sqlQuery(
                "SELECT usedpersonally FROM pubkeys WHERE address=?"
                " AND usedpersonally='yes'", dbstr(address))
            # if this pubkey is already in our database and if we have
            # used it personally:
            if queryreturn != []:
                logger.info(
                    'We HAVE used this pubkey personally. Updating time.')
                print("DEBUG: Updating existing pubkey record")
                t = (dbstr(address), addressVersion, sqlite3.Binary(dataToStore),
                     int(time.time()), dbstr('yes'))
            else:
                logger.info(
                    'We have NOT used this pubkey personally. Inserting'
                    ' in database.')
                print("DEBUG: Inserting new pubkey record")
                t = (dbstr(address), addressVersion, sqlite3.Binary(dataToStore),
                     int(time.time()), dbstr('no'))
            sqlExecute('''INSERT INTO pubkeys VALUES (?,?,?,?,?)''', *t)
            print("DEBUG: Checking if pubkey is needed")
            self.possibleNewPubkey(address)

        if addressVersion == 4:
            if len(data) < 350:  # sanity check.
                print("DEBUG: Pubkey too short for version 4")
                return logger.debug(
                    '(within processpubkey) payloadLength less than 350.'
                    ' Sanity check failed.')

            tag = data[readPosition:readPosition + 32]
            tag_bytes = bytes(tag)
            print(f"DEBUG: V4 pubkey tag: {hexlify(tag)}")
            if tag_bytes not in state.neededPubkeys:
                print("DEBUG: Not a needed pubkey")
                return logger.info(
                    'We don\'t need this v4 pubkey. We didn\'t ask for it.')

            # Let us try to decrypt the pubkey
            toAddress = state.neededPubkeys[tag_bytes][0]
            print(f"DEBUG: Trying to decrypt for address: {toAddress}")
            if protocol.decryptAndCheckPubkeyPayload(data, toAddress) == \
                    'successful':
                print("DEBUG: Pubkey decryption successful")
                # At this point we know that we have been waiting on this
                # pubkey. This function will command the workerThread
                # to start work on the messages that require it.
                self.possibleNewPubkey(toAddress)
            else:
                print("DEBUG: Pubkey decryption failed")

        # Display timing data
        processingTime = time.time() - pubkeyProcessingStartTime
        logger.debug(
            'Time required to process this pubkey: %s',
            processingTime)
        print(f"DEBUG: Pubkey processing time: {processingTime} seconds")

    def processmsg(self, data):
        """Process a message object"""
        messageProcessingStartTime = time.time()
        state.numberOfMessagesProcessed += 1
        queues.UISignalQueue.put((
            'updateNumberOfMessagesProcessed', 'no data'))
        print("DEBUG: Processing message object")
        readPosition = 20  # bypass the nonce, time, and object type
        msgVersion, msgVersionLength = decodeVarint(
            data[readPosition:readPosition + 9])
        if msgVersion != 1:
            print(f"DEBUG: Unsupported message version {msgVersion}")
            return logger.info(
                'Cannot understand message versions other than one.'
                ' Ignoring message.')
        readPosition += msgVersionLength

        streamNumberAsClaimedByMsg, streamNumberAsClaimedByMsgLength = \
            decodeVarint(data[readPosition:readPosition + 9])
        readPosition += streamNumberAsClaimedByMsgLength
        inventoryHash = highlevelcrypto.calculateInventoryHash(data)
        print(f"DEBUG: Message inventory hash: {hexlify(inventoryHash)}")
        initialDecryptionSuccessful = False

        # This is not an acknowledgement bound for me. See if it is a message
        # bound for me by trying to decrypt it with my private keys.

        print("DEBUG: Trying to decrypt message with my keys")
        for key, cryptorObject in sorted(
                shared.myECCryptorObjects.items(),
                key=lambda x: random.random()):  # nosec B311
            try:
                # continue decryption attempts to avoid timing attacks
                if initialDecryptionSuccessful:
                    cryptorObject.decrypt(data[readPosition:])
                else:
                    decryptedData = cryptorObject.decrypt(data[readPosition:])
                    # This is the RIPE hash of my pubkeys. We need this
                    # below to compare to the destination_ripe included
                    # in the encrypted data.
                    toRipe = key
                    initialDecryptionSuccessful = True
                    logger.info(
                        'EC decryption successful using key associated'
                        ' with ripe hash: %s.', hexlify(key))
                    print(f"DEBUG: Decryption successful with RIPE: {hexlify(key)}")
            except Exception:  # nosec B110
                print(f"DEBUG: Decryption failed with RIPE: {hexlify(key)}")
                pass
        if not initialDecryptionSuccessful:
            # This is not a message bound for me.
            print("DEBUG: Message decryption failed with all keys")
            return logger.info(
                'Length of time program spent failing to decrypt this'
                ' message: %s seconds.',
                time.time() - messageProcessingStartTime)

        # This is a message bound for me.
        # Look up my address based on the RIPE hash.
        toAddress = shared.myAddressesByHash[bytes(toRipe)]
        print(f"DEBUG: Message is for my address: {toAddress}")
        readPosition = 0
        sendersAddressVersionNumber, sendersAddressVersionNumberLength = \
            decodeVarint(decryptedData[readPosition:readPosition + 10])
        readPosition += sendersAddressVersionNumberLength
        if sendersAddressVersionNumber == 0:
            print("DEBUG: Invalid sender address version 0")
            return logger.info(
                'Cannot understand sendersAddressVersionNumber = 0.'
                ' Ignoring message.')
        if sendersAddressVersionNumber > 4:
            print(f"DEBUG: Unsupported sender address version {sendersAddressVersionNumber}")
            return logger.info(
                'Sender\'s address version number %s not yet supported.'
                ' Ignoring message.', sendersAddressVersionNumber)
        if len(decryptedData) < 170:
            print("DEBUG: Decrypted data too short")
            return logger.info(
                'Length of the unencrypted data is unreasonably short.'
                ' Sanity check failed. Ignoring message.')
        sendersStreamNumber, sendersStreamNumberLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        if sendersStreamNumber == 0:
            print("DEBUG: Invalid sender stream number 0")
            logger.info('sender\'s stream number is 0. Ignoring message.')
            return
        readPosition += sendersStreamNumberLength
        readPosition += 4
        pubSigningKey = b'\x04' + decryptedData[readPosition:readPosition + 64]
        readPosition += 64
        pubEncryptionKey = b'\x04' + decryptedData[readPosition:readPosition + 64]
        readPosition += 64
        if sendersAddressVersionNumber >= 3:
            requiredAverageProofOfWorkNonceTrialsPerByte, varintLength = \
                decodeVarint(decryptedData[readPosition:readPosition + 10])
            readPosition += varintLength
            logger.info(
                'sender\'s requiredAverageProofOfWorkNonceTrialsPerByte is %s',
                requiredAverageProofOfWorkNonceTrialsPerByte)
            print(f"DEBUG: Sender's nonce trials: {requiredAverageProofOfWorkNonceTrialsPerByte}")
            requiredPayloadLengthExtraBytes, varintLength = decodeVarint(
                decryptedData[readPosition:readPosition + 10])
            readPosition += varintLength
            logger.info(
                'sender\'s requiredPayloadLengthExtraBytes is %s',
                requiredPayloadLengthExtraBytes)
            print(f"DEBUG: Sender's extra bytes: {requiredPayloadLengthExtraBytes}")
        # needed for when we store the pubkey in our database of pubkeys
        # for later use.
        endOfThePublicKeyPosition = readPosition
        if toRipe != decryptedData[readPosition:readPosition + 20]:
            print("DEBUG: RIPE mismatch - possible forwarding attack")
            return logger.info(
                'The original sender of this message did not send it to'
                ' you. Someone is attempting a Surreptitious Forwarding'
                ' Attack.\nSee: '
                'http://world.std.com/~dtd/sign_encrypt/sign_encrypt7.html'
                '\nyour toRipe: %s\nembedded destination toRipe: %s',
                hexlify(toRipe),
                hexlify(decryptedData[readPosition:readPosition + 20]))
        readPosition += 20
        messageEncodingType, messageEncodingTypeLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        readPosition += messageEncodingTypeLength
        messageLength, messageLengthLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        readPosition += messageLengthLength
        message = decryptedData[readPosition:readPosition + messageLength]
        readPosition += messageLength
        ackLength, ackLengthLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        readPosition += ackLengthLength
        ackData = decryptedData[readPosition:readPosition + ackLength]
        readPosition += ackLength
        # needed to mark the end of what is covered by the signature
        positionOfBottomOfAckData = readPosition
        signatureLength, signatureLengthLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        readPosition += signatureLengthLength
        signature = decryptedData[
            readPosition:readPosition + signatureLength]
        signedData = bytes(data[8:20]) + encodeVarint(1) + encodeVarint(
            streamNumberAsClaimedByMsg
        ) + decryptedData[:positionOfBottomOfAckData]

        if not highlevelcrypto.verify(
                signedData, signature, hexlify(pubSigningKey)):
            print("DEBUG: ECDSA verification failed")
            return logger.debug('ECDSA verify failed')
        logger.debug('ECDSA verify passed')
        print("DEBUG: ECDSA verification passed")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                'As a matter of intellectual curiosity, here is the Bitcoin'
                ' address associated with the keys owned by the other person:'
                ' %s  ..and here is the testnet address: %s. The other person'
                ' must take their private signing key from Bitmessage and'
                ' import it into Bitcoin (or a service like Blockchain.info)'
                ' for it to be of any use. Do not use this unless you know'
                ' what you are doing.',
                helper_bitcoin.calculateBitcoinAddressFromPubkey(pubSigningKey),
                helper_bitcoin.calculateTestnetAddressFromPubkey(pubSigningKey)
            )
        # Used to detect and ignore duplicate messages in our inbox
        sigHash = highlevelcrypto.double_sha512(signature)[32:]
        print(f"DEBUG: Signature hash: {hexlify(sigHash)}")

        # calculate the fromRipe.
        ripe = highlevelcrypto.to_ripe(pubSigningKey, pubEncryptionKey)
        fromAddress = encodeAddress(
            sendersAddressVersionNumber, sendersStreamNumber, ripe)
        print(f"DEBUG: Derived sender address: {fromAddress}")

        # Let's store the public key in case we want to reply to this
        # person.
        sqlExecute(
            '''INSERT INTO pubkeys VALUES (?,?,?,?,?)''',
            dbstr(fromAddress),
            sendersAddressVersionNumber,
            sqlite3.Binary(decryptedData[:endOfThePublicKeyPosition]),
            int(time.time()),
            dbstr('yes'))
        print("DEBUG: Stored sender's pubkey in database")

        # Check to see whether we happen to be awaiting this
        # pubkey in order to send a message. If we are, it will do the POW
        # and send it.
        self.possibleNewPubkey(fromAddress)

        # If this message is bound for one of my version 3 addresses (or
        # higher), then we must check to make sure it meets our demanded
        # proof of work requirement. If this is bound for one of my chan
        # addresses then we skip this check; the minimum network POW is
        # fine.
        # If the toAddress version number is 3 or higher and not one of
        # my chan addresses:
        if decodeAddress(toAddress)[1] >= 3 \
                and not config.safeGetBoolean(toAddress, 'chan'):
            # If I'm not friendly with this person:
            if not shared.isAddressInMyAddressBookSubscriptionsListOrWhitelist(
                    fromAddress):
                requiredNonceTrialsPerByte = config.getint(
                    toAddress, 'noncetrialsperbyte')
                requiredPayloadLengthExtraBytes = config.getint(
                    toAddress, 'payloadlengthextrabytes')
                if not protocol.isProofOfWorkSufficient(
                        data, requiredNonceTrialsPerByte,
                        requiredPayloadLengthExtraBytes):
                    print("DEBUG: Insufficient proof of work")
                    return logger.info(
                        'Proof of work in msg is insufficient only because'
                        ' it does not meet our higher requirement.')
        # Gets set to True if the user shouldn't see the message according
        # to black or white lists.
        blockMessage = False
        # If we are using a blacklist
        if config.get(
                'bitmessagesettings', 'blackwhitelist') == 'black':
            queryreturn = sqlQuery(
                "SELECT label FROM blacklist where address=? and enabled='1'",
                dbstr(fromAddress))
            if queryreturn != []:
                logger.info('Message ignored because address is in blacklist.')
                print("DEBUG: Sender is in blacklist")
                blockMessage = True
        else:  # We're using a whitelist
            queryreturn = sqlQuery(
                "SELECT label FROM whitelist where address=? and enabled='1'",
                dbstr(fromAddress))
            if queryreturn == []:
                logger.info(
                    'Message ignored because address not in whitelist.')
                print("DEBUG: Sender not in whitelist")
                blockMessage = True

        # toLabel = config.safeGet(toAddress, 'label', toAddress)
        try:
            decodedMessage = helper_msgcoding.MsgDecode(
                messageEncodingType, message)
        except helper_msgcoding.MsgDecodeException:
            print("DEBUG: Message decode exception")
            return
        subject = decodedMessage.subject
        body = decodedMessage.body
        print(f"DEBUG: Message subject: {subject}")

        # Let us make sure that we haven't already received this message
        if helper_inbox.isMessageAlreadyInInbox(sigHash):
            logger.info('This msg is already in our inbox. Ignoring it.')
            print("DEBUG: Duplicate message detected")
            blockMessage = True
        if not blockMessage:
            if messageEncodingType != 0:
                t = (inventoryHash, toAddress, fromAddress, subject,
                     int(time.time()), body, 'inbox', messageEncodingType,
                     0, sigHash)
                helper_inbox.insert(t)
                print("DEBUG: Inserted message into inbox")

                queues.UISignalQueue.put(('displayNewInboxMessage', (
                    inventoryHash, toAddress, fromAddress, subject, body)))

            # If we are behaving as an API then we might need to run an
            # outside command to let some program know that a new message
            # has arrived.
            if config.safeGetBoolean(
                    'bitmessagesettings', 'apienabled'):
                apiNotifyPath = config.safeGet(
                    'bitmessagesettings', 'apinotifypath')
                if apiNotifyPath:
                    print("DEBUG: Calling API notify path")
                    subprocess.call([apiNotifyPath, "newMessage"])  # nosec B603

            # Let us now check and see whether our receiving address is
            # behaving as a mailing list
            if config.safeGetBoolean(toAddress, 'mailinglist') \
                    and messageEncodingType != 0:
                mailingListName = config.safeGet(
                    toAddress, 'mailinglistname', '')
                print(f"DEBUG: Processing as mailing list: {mailingListName}")
                # Let us send out this message as a broadcast
                subject = self.addMailingListNameToSubject(
                    subject, mailingListName)
                # Let us now send this message out as a broadcast
                message = time.strftime(
                    "%a, %Y-%m-%d %H:%M:%S UTC", time.gmtime()
                ) + '   Message ostensibly from ' + fromAddress \
                    + ':\n\n' + body
                # The fromAddress for the broadcast that we are about to
                # send is the toAddress (my address) for the msg message
                # we are currently processing.
                fromAddress = toAddress
                # We don't actually need the ackdata for acknowledgement
                # since this is a broadcast message but we can use it to
                # update the user interface when the POW is done generating.
                toAddress = '[Broadcast subscribers]'

                ackdata = helper_sent.insert(
                    fromAddress=fromAddress,
                    status='broadcastqueued',
                    subject=subject,
                    message=message,
                    encoding=messageEncodingType)
                print("DEBUG: Queued broadcast message")

                queues.UISignalQueue.put((
                    'displayNewSentMessage', (
                        toAddress, '[Broadcast subscribers]', fromAddress,
                        subject, message, ackdata)
                ))
                queues.workerQueue.put(('sendbroadcast', ''))

        # Don't send ACK if invalid, blacklisted senders, invisible
        # messages, disabled or chan
        if (
            self.ackDataHasAValidHeader(ackData) and not blockMessage
            and messageEncodingType != 0
            and not config.safeGetBoolean(toAddress, 'dontsendack')
            and not config.safeGetBoolean(toAddress, 'chan')
        ):
            print("DEBUG: Queueing ACK message")
            ackPayload = ackData[24:]
            objectType, toStreamNumber, expiresTime = \
                protocol.decodeObjectParameters(ackPayload)
            inventoryHash = highlevelcrypto.calculateInventoryHash(ackPayload)
            state.Inventory[inventoryHash] = (
                objectType, toStreamNumber, ackPayload, expiresTime, b'')
            invQueue.put((toStreamNumber, inventoryHash))
        else:
            print("DEBUG: Not sending ACK due to conditions")

        # Display timing data
        timeRequiredToAttemptToDecryptMessage = time.time(
        ) - messageProcessingStartTime
        self.successfullyDecryptMessageTimings.append(
            timeRequiredToAttemptToDecryptMessage)
        timing_sum = 0
        for item in self.successfullyDecryptMessageTimings:
            timing_sum += item
        logger.debug(
            'Time to decrypt this message successfully: %s'
            '\nAverage time for all message decryption successes since'
            ' startup: %s.',
            timeRequiredToAttemptToDecryptMessage,
            timing_sum / len(self.successfullyDecryptMessageTimings)
        )
        print(f"DEBUG: Message processing time: {timeRequiredToAttemptToDecryptMessage} seconds")

    def processbroadcast(self, data):
        """Process a broadcast object"""
        messageProcessingStartTime = time.time()
        state.numberOfBroadcastsProcessed += 1
        queues.UISignalQueue.put((
            'updateNumberOfBroadcastsProcessed', 'no data'))
        print("DEBUG: Processing broadcast object")
        inventoryHash = highlevelcrypto.calculateInventoryHash(data)
        print(f"DEBUG: Broadcast inventory hash: {hexlify(inventoryHash)}")
        readPosition = 20  # bypass the nonce, time, and object type
        broadcastVersion, broadcastVersionLength = decodeVarint(
            data[readPosition:readPosition + 9])
        readPosition += broadcastVersionLength
        print(f"DEBUG: Broadcast version: {broadcastVersion}")
        if broadcastVersion < 4 or broadcastVersion > 5:
            print("DEBUG: Unsupported broadcast version")
            return logger.info(
                'Cannot decode incoming broadcast versions less than 4'
                ' or higher than 5. Assuming the sender isn\'t being silly,'
                ' you should upgrade Bitmessage because this message shall'
                ' be ignored.'
            )
        cleartextStreamNumber, cleartextStreamNumberLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += cleartextStreamNumberLength
        print(f"DEBUG: Broadcast stream: {cleartextStreamNumber}")
        if broadcastVersion == 4:
            # v4 broadcasts are encrypted the same way the msgs are
            # encrypted. To see if we are interested in a v4 broadcast,
            # we try to decrypt it. This was replaced with v5 broadcasts
            # which include a tag which we check instead, just like we do
            # with v4 pubkeys.
            signedData = data[8:readPosition]
            initialDecryptionSuccessful = False
            print("DEBUG: Trying to decrypt v4 broadcast")
            for key, cryptorObject in sorted(
                    shared.MyECSubscriptionCryptorObjects.items(),
                    key=lambda x: random.random()):  # nosec B311
                try:
                    # continue decryption attempts to avoid timing attacks
                    if initialDecryptionSuccessful:
                        cryptorObject.decrypt(data[readPosition:])
                    else:
                        decryptedData = cryptorObject.decrypt(
                            data[readPosition:])
                        # This is the RIPE hash of the sender's pubkey.
                        # We need this below to compare to the RIPE hash
                        # of the sender's address to verify that it was
                        # encrypted by with their key rather than some
                        # other key.
                        toRipe = key
                        initialDecryptionSuccessful = True
                        logger.info(
                            'EC decryption successful using key associated'
                            ' with ripe hash: %s', hexlify(key))
                        print(f"DEBUG: Decryption successful with RIPE: {hexlify(key)}")
                except Exception:
                    logger.debug(
                        'cryptorObject.decrypt Exception:', exc_info=True)
                    print(f"DEBUG: Decryption failed with RIPE: {hexlify(key)}")
            if not initialDecryptionSuccessful:
                # This is not a broadcast I am interested in.
                print("DEBUG: Broadcast decryption failed with all keys")
                return logger.debug(
                    'Length of time program spent failing to decrypt this'
                    ' v4 broadcast: %s seconds.',
                    time.time() - messageProcessingStartTime)
        elif broadcastVersion == 5:
            embeddedTag = data[readPosition:readPosition + 32]
            readPosition += 32
            embeddedTag_bytes = bytes(embeddedTag)
            print(f"DEBUG: Broadcast tag: {hexlify(embeddedTag)}")
            if embeddedTag_bytes not in shared.MyECSubscriptionCryptorObjects:
                logger.debug('We\'re not interested in this broadcast.')
                print("DEBUG: Not subscribed to this broadcast tag")
                return
            # We are interested in this broadcast because of its tag.
            # We're going to add some more data which is signed further down.
            signedData = bytes(data[8:readPosition])
            cryptorObject = shared.MyECSubscriptionCryptorObjects[embeddedTag_bytes]
            try:
                decryptedData = cryptorObject.decrypt(data[readPosition:])
                logger.debug('EC decryption successful')
                print("DEBUG: Broadcast decryption successful")
            except Exception:
                print("DEBUG: Broadcast decryption failed")
                return logger.debug(
                    'Broadcast version %s decryption Unsuccessful.',
                    broadcastVersion)
        # At this point this is a broadcast I have decrypted and am
        # interested in.
        readPosition = 0
        sendersAddressVersion, sendersAddressVersionLength = decodeVarint(
            decryptedData[readPosition:readPosition + 9])
        print(f"DEBUG: Sender address version: {sendersAddressVersion}")
        if broadcastVersion == 4:
            if sendersAddressVersion < 2 or sendersAddressVersion > 3:
                print("DEBUG: Unsupported sender address version for v4 broadcast")
                return logger.warning(
                    'Cannot decode senderAddressVersion other than 2 or 3.'
                    ' Assuming the sender isn\'t being silly, you should'
                    ' upgrade Bitmessage because this message shall be'
                    ' ignored.'
                )
        elif broadcastVersion == 5:
            if sendersAddressVersion < 4:
                print("DEBUG: Unsupported sender address version for v5 broadcast")
                return logger.info(
                    'Cannot decode senderAddressVersion less than 4 for'
                    ' broadcast version number 5. Assuming the sender'
                    ' isn\'t being silly, you should upgrade Bitmessage'
                    ' because this message shall be ignored.'
                )
        readPosition += sendersAddressVersionLength
        sendersStream, sendersStreamLength = decodeVarint(
            decryptedData[readPosition:readPosition + 9])
        print(f"DEBUG: Sender stream: {sendersStream}")
        if sendersStream != cleartextStreamNumber:
            print("DEBUG: Stream number mismatch")
            return logger.info(
                'The stream number outside of the encryption on which the'
                ' POW was completed doesn\'t match the stream number'
                ' inside the encryption. Ignoring broadcast.'
            )
        readPosition += sendersStreamLength
        readPosition += 4
        sendersPubSigningKey = b'\x04' + \
            decryptedData[readPosition:readPosition + 64]
        readPosition += 64
        sendersPubEncryptionKey = b'\x04' + \
            decryptedData[readPosition:readPosition + 64]
        readPosition += 64
        if sendersAddressVersion >= 3:
            requiredAverageProofOfWorkNonceTrialsPerByte, varintLength = \
                decodeVarint(decryptedData[readPosition:readPosition + 10])
            readPosition += varintLength
            logger.debug(
                'sender\'s requiredAverageProofOfWorkNonceTrialsPerByte'
                ' is %s', requiredAverageProofOfWorkNonceTrialsPerByte)
            print(f"DEBUG: Sender's nonce trials: {requiredAverageProofOfWorkNonceTrialsPerByte}")
            requiredPayloadLengthExtraBytes, varintLength = decodeVarint(
                decryptedData[readPosition:readPosition + 10])
            readPosition += varintLength
            logger.debug(
                'sender\'s requiredPayloadLengthExtraBytes is %s',
                requiredPayloadLengthExtraBytes)
            print(f"DEBUG: Sender's extra bytes: {requiredPayloadLengthExtraBytes}")
        endOfPubkeyPosition = readPosition

        calculatedRipe = highlevelcrypto.to_ripe(
            sendersPubSigningKey, sendersPubEncryptionKey)
        print(f"DEBUG: Calculated RIPE: {hexlify(calculatedRipe)}")

        if broadcastVersion == 4:
            if toRipe != calculatedRipe:
                print("DEBUG: RIPE mismatch in v4 broadcast")
                return logger.info(
                    'The encryption key used to encrypt this message'
                    ' doesn\'t match the keys inbedded in the message'
                    ' itself. Ignoring message.'
                )
        elif broadcastVersion == 5:
            calculatedTag = highlevelcrypto.double_sha512(
                encodeVarint(sendersAddressVersion)
                + encodeVarint(sendersStream) + calculatedRipe
            )[32:]
            if calculatedTag != embeddedTag:
                print("DEBUG: Tag mismatch in v5 broadcast")
                return logger.debug(
                    'The tag and encryption key used to encrypt this'
                    ' message doesn\'t match the keys inbedded in the'
                    ' message itself. Ignoring message.'
                )
        messageEncodingType, messageEncodingTypeLength = decodeVarint(
            decryptedData[readPosition:readPosition + 9])
        if messageEncodingType == 0:
            print("DEBUG: Invisible message encoding")
            return
        readPosition += messageEncodingTypeLength
        messageLength, messageLengthLength = decodeVarint(
            decryptedData[readPosition:readPosition + 9])
        readPosition += messageLengthLength
        message = decryptedData[readPosition:readPosition + messageLength]
        readPosition += messageLength
        readPositionAtBottomOfMessage = readPosition
        signatureLength, signatureLengthLength = decodeVarint(
            decryptedData[readPosition:readPosition + 9])
        readPosition += signatureLengthLength
        signature = decryptedData[
            readPosition:readPosition + signatureLength]
        signedData += decryptedData[:readPositionAtBottomOfMessage]

        if not highlevelcrypto.verify(
                signedData, signature, hexlify(sendersPubSigningKey)):
            print("DEBUG: ECDSA verification failed")
            logger.debug('ECDSA verify failed')
            return
        logger.debug('ECDSA verify passed')
        print("DEBUG: ECDSA verification passed")
        # Used to detect and ignore duplicate messages in our inbox
        sigHash = highlevelcrypto.double_sha512(signature)[32:]
        print(f"DEBUG: Signature hash: {hexlify(sigHash)}")

        fromAddress = encodeAddress(
            sendersAddressVersion, sendersStream, calculatedRipe)
        logger.info('fromAddress: %s', fromAddress)
        print(f"DEBUG: Derived sender address: {fromAddress}")

        # Let's store the public key in case we want to reply to this person.
        sqlExecute('''INSERT INTO pubkeys VALUES (?,?,?,?,?)''',
                   dbstr(fromAddress),
                   dbstr(sendersAddressVersion),
                   sqlite3.Binary(decryptedData[:endOfPubkeyPosition]),
                   int(time.time()),
                   dbstr('yes'))
        print("DEBUG: Stored sender's pubkey in database")

        # Check to see whether we happen to be awaiting this
        # pubkey in order to send a message. If we are, it will do the POW
        # and send it.
        self.possibleNewPubkey(fromAddress)

        try:
            decodedMessage = helper_msgcoding.MsgDecode(
                messageEncodingType, message)
        except helper_msgcoding.MsgDecodeException:
            print("DEBUG: Message decode exception")
            return
        subject = decodedMessage.subject
        body = decodedMessage.body
        print(f"DEBUG: Broadcast subject: {subject}")

        toAddress = '[Broadcast subscribers]'
        if helper_inbox.isMessageAlreadyInInbox(sigHash):
            logger.info('This broadcast is already in our inbox. Ignoring it.')
            print("DEBUG: Duplicate broadcast detected")
            return
        t = (inventoryHash, toAddress, fromAddress, subject, int(
            time.time()), body, 'inbox', messageEncodingType, 0, sigHash)
        helper_inbox.insert(t)
        print("DEBUG: Inserted broadcast into inbox")

        queues.UISignalQueue.put(('displayNewInboxMessage', (
            inventoryHash, toAddress, fromAddress, subject, body)))

        # If we are behaving as an API then we might need to run an
        # outside command to let some program know that a new message
        # has arrived.
        if config.safeGetBoolean('bitmessagesettings', 'apienabled'):
            apiNotifyPath = config.safeGet(
                'bitmessagesettings', 'apinotifypath')
            if apiNotifyPath:
                print("DEBUG: Calling API notify path")
                subprocess.call([apiNotifyPath, "newBroadcast"])  # nosec B603

        # Display timing data
        processingTime = time.time() - messageProcessingStartTime
        logger.info(
            'Time spent processing this interesting broadcast: %s',
            processingTime)
        print(f"DEBUG: Broadcast processing time: {processingTime} seconds")

    def possibleNewPubkey(self, address):
        """
        We have inserted a pubkey into our pubkey table which we received
        from a pubkey, msg, or broadcast message. It might be one that we
        have been waiting for. Let's check.
        """
        print(f"DEBUG: Checking if pubkey for {address} is needed")

        # For address versions <= 3, we wait on a key with the correct
        # address version, stream number and RIPE hash.
        addressVersion, streamNumber, ripe = decodeAddress(address)[1:]
        if addressVersion <= 3:
            if address in state.neededPubkeys:
                print("DEBUG: Found needed pubkey (v3 or lower)")
                del state.neededPubkeys[address]
                self.sendMessages(address)
            else:
                logger.debug(
                    'We don\'t need this pub key. We didn\'t ask for it.'
                    ' For address: %s', address)
                print("DEBUG: Pubkey not needed (v3 or lower)")
        # For address versions >= 4, we wait on a pubkey with the correct tag.
        # Let us create the tag from the address and see if we were waiting
        # for it.
        elif addressVersion >= 4:
            tag = highlevelcrypto.double_sha512(
                encodeVarint(addressVersion) + encodeVarint(streamNumber)
                + ripe
            )[32:]
            tag_bytes = bytes(tag)
            if tag_bytes in state.neededPubkeys:
                print("DEBUG: Found needed pubkey (v4+)")
                del state.neededPubkeys[tag_bytes]
                self.sendMessages(address)
            else:
                print("DEBUG: Pubkey not needed (v4+)")

    @staticmethod
    def sendMessages(address):
        """
        This method is called by the `possibleNewPubkey` when it sees
        that we now have the necessary pubkey to send one or more messages.
        """
        logger.info('We have been awaiting the arrival of this pubkey.')
        print(f"DEBUG: Sending messages waiting for pubkey of {address}")
        sqlExecute(
            "UPDATE sent SET status='doingmsgpow', retrynumber=0"
            " WHERE toaddress=?"
            " AND (status='awaitingpubkey' OR status='doingpubkeypow')"
            " AND folder='sent'", dbstr(address))
        queues.workerQueue.put(('sendmessage', ''))

    @staticmethod
    def ackDataHasAValidHeader(ackData):
        """Checking ackData with valid Header, not sending ackData when false"""
        print("DEBUG: Validating ackdata header")
        if len(ackData) < protocol.Header.size:
            logger.info(
                'The length of ackData is unreasonably short. Not sending'
                ' ackData.')
            print("DEBUG: ackData too short")
            return False

        magic, command, payloadLength, checksum = protocol.Header.unpack(
            ackData[:protocol.Header.size])
        print(f"DEBUG: ackData header - magic: {hexlify(magic)}, command: {command}, length: {payloadLength}")
        if magic != protocol.magic:
            logger.info('Ackdata magic bytes were wrong. Not sending ackData.')
            print("DEBUG: Invalid magic bytes")
            return False
        payload = ackData[protocol.Header.size:]
        if len(payload) != payloadLength:
            logger.info(
                'ackData payload length doesn\'t match the payload length'
                ' specified in the header. Not sending ackdata.')
            print("DEBUG: Payload length mismatch")
            return False
        # ~1.6 MB which is the maximum possible size of an inv message.
        if payloadLength > 1600100:
            # The largest message should be either an inv or a getdata
            # message at 1.6 MB in size.
            # That doesn't mean that the object may be that big. The
            # shared.checkAndShareObjectWithPeers function will verify
            # that it is no larger than 2^18 bytes.
            print("DEBUG: Payload too large")
            return False
        # test the checksum in the message.
        if checksum != hashlib.sha512(payload).digest()[0:4]:
            logger.info('ackdata checksum wrong. Not sending ackdata.')
            print("DEBUG: Invalid checksum")
            return False
        command = command.rstrip(b'\x00')
        if command != b'object':
            print("DEBUG: Invalid command")
            return False
        print("DEBUG: ackData header valid")
        return True

    @staticmethod
    def addMailingListNameToSubject(subject, mailingListName):
        """Adding mailingListName to subject"""
        print(f"DEBUG: Adding mailing list name '{mailingListName}' to subject")
        subject = subject.strip()
        if subject[:3] == 'Re:' or subject[:3] == 'RE:':
            subject = subject[3:].strip()
        if '[' + mailingListName + ']' in subject:
            return subject
        return '[' + mailingListName + '] ' + subject
