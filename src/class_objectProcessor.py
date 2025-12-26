"""
The objectProcessor thread, of which there is only one,
processes the network objects
"""
# pylint: disable=too-many-locals,too-many-return-statements
# pylint: disable=too-many-branches,too-many-statements
import hashlib
import logging
import os
import random
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


def to_hex_string(data):
    """
    Konvertiere beliebige Daten zu einem hex-String für Python 2/3 Kompatibilität.
    Verwendet String als Standard für bidirektionale Kompatibilität.
    """
    if data is None:
        return ''
    
    # Wenn es bereits ein String ist
    if isinstance(data, str):
        # Prüfe, ob es bereits ein hex-String ist (nur hex-Zeichen)
        try:
            int(data, 16)
            return data  # Ist bereits hex
        except (ValueError, TypeError):
            # Ist kein hex-String, konvertiere zu hex
            return hexlify(data.encode('latin-1')).decode('utf-8')
    
    # Python 3: bytes, bytearray, memoryview
    if hasattr(data, 'tobytes'):  # memoryview
        data = data.tobytes()
    
    if isinstance(data, (bytes, bytearray)):
        return hexlify(data).decode('utf-8')
    
    # Fallback: zu String und dann zu hex
    try:
        return hexlify(str(data).encode('latin-1')).decode('utf-8')
    except:
        return str(data)


def from_hex_string(hex_str):
    """
    Konvertiere hex-String zurück zu bytes.
    """
    if not hex_str:
        return b''
    try:
        return bytes.fromhex(hex_str)
    except (ValueError, TypeError):
        # Falls es kein valider hex-String ist
        return hex_str.encode('latin-1')


class objectProcessor(threading.Thread):
    """
    The objectProcessor thread, of which there is only one, receives network
    objects (msg, broadcast, pubkey, getpubkey) from the receiveDataThreads.
    """
    def __init__(self):
        threading.Thread.__init__(self, name="objectProcessor")
        random.seed()
        if sql_ready.wait(sql_timeout) is False:
            logger.fatal('SQL thread is not started in %s sec', sql_timeout)
            os._exit(1)  # pylint: disable=protected-access
        shared.reloadMyAddressHashes()
        shared.reloadBroadcastSendersForWhichImWatching()
        # It may be the case that the last time Bitmessage was running,
        # the user closed it before it finished processing everything in the
        # objectProcessorQueue. Assuming that Bitmessage wasn't closed
        # forcefully, it should have saved the data in the queue into the
        # objectprocessorqueue table. Let's pull it out.
        try:
            queryreturn = sqlQuery('SELECT objecttype, data FROM objectprocessorqueue')
            for objectType, data in queryreturn:
                queues.objectProcessorQueue.put((objectType, data))
            
            logger.debug(
                'Loaded %s objects from disk into the objectProcessorQueue.',
                len(queryreturn))
            
            # Only delete if we successfully loaded something
            if queryreturn:
                sqlExecute('DELETE FROM objectprocessorqueue')
        except Exception as e:
            logger.debug("Could not load from objectprocessorqueue (table might not exist): %s", e)
            queryreturn = []
        self.successfullyDecryptMessageTimings = []

    def run(self):
        """Process the objects from `.queues.objectProcessorQueue`"""
        print(f"\n{'='*80}")
        print(f"[OBJECTPROCESSOR] Thread gestartet")
        print(f"[OBJECTPROCESSOR] Initial state.neededPubkeys: {len(state.neededPubkeys)} Einträge")
        if state.neededPubkeys:
            print(f"[OBJECTPROCESSOR] Keys in neededPubkeys:")
            for key, value in state.neededPubkeys.items():
                if isinstance(key, str) and len(key) > 10:
                    print(f"  - {key[:20]}...: {value}")
                elif isinstance(key, bytes):
                    print(f"  - bytes {hexlify(key[:10])}...: {value}")
                else:
                    print(f"  - {key}: {value}")
        print(f"[OBJECTPROCESSOR] Warte auf Objekte in der Queue...")
        print(f"{'='*80}")
        
        while True:
            objectType, data = queues.objectProcessorQueue.get()
            
            print(f"\n[OBJECTPROCESSOR] 📥 Neues Objekt erhalten:")
            print(f"  Typ: {objectType} ({protocol.OBJECT_GETPUBKEY=}, {protocol.OBJECT_PUBKEY=})")
            print(f"  Datenlänge: {len(data)} bytes")
            if len(data) > 50:
                print(f"  Erste 50 Bytes: {hexlify(data[:50])}...")

            self.checkackdata(data)

            try:
                if objectType == protocol.OBJECT_GETPUBKEY:
                    print(f"[OBJECTPROCESSOR] Verarbeite GETPUBKEY Objekt")
                    self.processgetpubkey(data)
                elif objectType == protocol.OBJECT_PUBKEY:
                    print(f"[OBJECTPROCESSOR] Verarbeite PUBKEY Objekt")
                    self.processpubkey(data)
                elif objectType == protocol.OBJECT_MSG:
                    print(f"[OBJECTPROCESSOR] Verarbeite MSG Objekt")
                    self.processmsg(data)
                elif objectType == protocol.OBJECT_BROADCAST:
                    print(f"[OBJECTPROCESSOR] Verarbeite BROADCAST Objekt")
                    self.processbroadcast(data)
                elif objectType == protocol.OBJECT_ONIONPEER:
                    print(f"[OBJECTPROCESSOR] Verarbeite ONIONPEER Objekt")
                    self.processonion(data)
                # is more of a command, not an object type. Is used to get
                # this thread past the queue.get() so that it will check
                # the shutdown variable.
                elif objectType == 'checkShutdownVariable':
                    print(f"[OBJECTPROCESSOR] Check Shutdown Variable")
                    pass
                else:
                    if isinstance(objectType, int):
                        print(f"[OBJECTPROCESSOR] Unbekannter Objekttyp: 0x{objectType:08X}")
                        logger.info(
                            'Don\'t know how to handle object type 0x%08X',
                            objectType)
                    else:
                        print(f"[OBJECTPROCESSOR] Unbekannter Objekttyp: {objectType}")
                        logger.info(
                            'Don\'t know how to handle object type %s',
                            objectType)
            except helper_msgcoding.DecompressionSizeException as e:
                logger.error(
                    'The object is too big after decompression (stopped'
                    ' decompressing at %ib, your configured limit %ib).'
                    ' Ignoring',
                    e.size, config.safeGetInt('zlib', 'maxsize'))
            except varintDecodeError as e:
                logger.debug(
                    'There was a problem with a varint while processing an'
                    ' object. Some details: %s', e)
            except Exception:
                logger.critical(
                    'Critical error within objectProcessorThread: \n',
                    exc_info=True)

            if state.shutdown:
                # Wait just a moment for most of the connections to close
                time.sleep(.5)
                numberOfObjectsThatWereInTheObjectProcessorQueue = 0
                with SqlBulkExecute() as sql:
                    while queues.objectProcessorQueue.curSize > 0:
                        objectType, data = queues.objectProcessorQueue.get()
                        sql.execute(
                            'INSERT INTO objectprocessorqueue VALUES (?,?)',
                            objectType, sqlite3.Binary(data))
                        numberOfObjectsThatWereInTheObjectProcessorQueue += 1
                logger.debug(
                    'Saved %s objects from the objectProcessorQueue to'
                    ' disk. objectProcessorThread exiting.',
                    numberOfObjectsThatWereInTheObjectProcessorQueue)
                state.shutdown = 2
                break

    @staticmethod
    def checkackdata(data):
        """Checking Acknowledgement of message received or not?"""
        # Let's check whether this is a message acknowledgement bound for us.
        if len(data) < 32:
            return

        # bypass nonce and time, retain object type/version/stream + body
        readPosition = 16

        data_bytes = bytes(data[readPosition:])
        # Konvertiere zu hex-String für Kompatibilität
        data_hex = to_hex_string(data_bytes)
        if data_hex in state.ackdataForWhichImWatching:
            logger.info('This object is an acknowledgement bound for me.')
            del state.ackdataForWhichImWatching[data_hex]
            rowcount = sqlExecute(
                "UPDATE sent SET status='ackreceived', lastactiontime=?"
                " WHERE ackdata=?", int(time.time()), sqlite3.Binary(data_bytes))
            if rowcount < 1:
                rowcount = sqlExecute(
                    "UPDATE sent SET status='ackreceived', lastactiontime=?"
                    " WHERE ackdata=CAST(? AS TEXT)", int(time.time()), data_bytes)
            queues.UISignalQueue.put((
                'updateSentItemStatusByAckdata', (
                    data_bytes, _translate(
                        "MainWindow",
                        "Acknowledgement of the message received {0}"
                    ).format(l10n.formatTimestamp()))
            ))
        else:
            logger.debug('This object is not an acknowledgement bound for me.')

    @staticmethod
    def processonion(data):
        """Process onionpeer object"""
        readPosition = 20  # bypass the nonce, time, and object type
        length = decodeVarint(data[readPosition:readPosition + 10])[1]
        readPosition += length
        stream, length = decodeVarint(data[readPosition:readPosition + 10])
        readPosition += length
        # it seems that stream is checked in network.bmproto
        port, length = decodeVarint(data[readPosition:readPosition + 10])
        readPosition += length
        host = protocol.checkIPAddress(data[readPosition + length:])

        if not host:
            return
        peer = Peer(host, port)
        with knownnodes.knownNodesLock:
            # FIXME: adjust expirestime
            knownnodes.addKnownNode(
                stream, peer, is_self=state.ownAddresses.get(peer))

    @staticmethod
    def processgetpubkey(data):
        """Process getpubkey object"""
        
        print(f"\n[GETPUBKEY] Starte Verarbeitung, Datenlänge: {len(data)}")
        
        if len(data) > 200:
            print(f"[GETPUBKEY] ❌ Zu lang ({len(data)} > 200), ignoriere")
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

        print(f"[GETPUBKEY] Version: {requestedAddressVersionNumber}, Stream: {streamNumber}")

        if requestedAddressVersionNumber == 0:
            print(f"[GETPUBKEY] ❌ Version 0, ignoriere")
            return logger.debug(
                'The requestedAddressVersionNumber of the pubkey request'
                ' is zero. That doesn\'t make any sense. Ignoring it.')
        if requestedAddressVersionNumber == 1:
            print(f"[GETPUBKEY] ❌ Version 1 nicht unterstützt, ignoriere")
            return logger.debug(
                'The requestedAddressVersionNumber of the pubkey request'
                ' is 1 which isn\'t supported anymore. Ignoring it.')
        if requestedAddressVersionNumber > 4:
            print(f"[GETPUBKEY] ❌ Version >4, ignoriere")
            return logger.debug(
                'The requestedAddressVersionNumber of the pubkey request'
                ' is too high. Can\'t understand. Ignoring it.')

        myAddress = ''
        requestedHash_hex = ''
        requestedTag_hex = ''
        
        if requestedAddressVersionNumber <= 3:
            requestedHash = data[readPosition:readPosition + 20]
            if len(requestedHash) != 20:
                print(f"[GETPUBKEY] ❌ Hash Länge falsch ({len(requestedHash)} != 20)")
                return logger.debug(
                    'The length of the requested hash is not 20 bytes.'
                    ' Something is wrong. Ignoring.')
            
            requestedHash_hex = to_hex_string(requestedHash)
            
            print(f"\n[GETPUBKEY] Version {requestedAddressVersionNumber}")
            print(f"[GETPUBKEY] Angefragter Hash: {hexlify(requestedHash)}")
            print(f"[GETPUBKEY] Meine Address Hashes ({len(shared.myAddressesByHash)}):")
            for i, (hash_hex, addr) in enumerate(list(shared.myAddressesByHash.items())[:5]):
                print(f"  {i+1}. {hash_hex}: {addr}")
            if len(shared.myAddressesByHash) > 5:
                print(f"  ... und {len(shared.myAddressesByHash) - 5} weitere")
            
            # if this address hash is one of mine
            if requestedHash_hex in shared.myAddressesByHash:
                myAddress = shared.myAddressesByHash[requestedHash_hex]
                print(f"[GETPUBKEY] ✅ Anfrage für MEINE Adresse: {myAddress}")
            else:
                print(f"[GETPUBKEY] ❌ Hash nicht in meinen Adressen")
                return
                
        elif requestedAddressVersionNumber >= 4:
            requestedTag = data[readPosition:readPosition + 32]
            if len(requestedTag) != 32:
                print(f"[GETPUBKEY] ❌ Tag Länge falsch ({len(requestedTag)} != 32)")
                return logger.debug(
                    'The length of the requested tag is not 32 bytes.'
                    ' Something is wrong. Ignoring.')
            
            requestedTag_hex = to_hex_string(requestedTag)
            
            print(f"\n[GETPUBKEY] Version {requestedAddressVersionNumber}")
            print(f"[GETPUBKEY] Angefragter Tag: {hexlify(requestedTag)}")
            print(f"[GETPUBKEY] Meine v4 Tags ({len(shared.myAddressesByTag)}):")
            for i, (tag_hex, addr) in enumerate(list(shared.myAddressesByTag.items())[:5]):
                print(f"  {i+1}. {tag_hex[:20]}...: {addr}")
            if len(shared.myAddressesByTag) > 5:
                print(f"  ... und {len(shared.myAddressesByTag) - 5} weitere")
            
            if requestedTag_hex in shared.myAddressesByTag:
                myAddress = shared.myAddressesByTag[requestedTag_hex]
                print(f"[GETPUBKEY] ✅ Anfrage für MEINE v4 Adresse: {myAddress}")
            else:
                print(f"[GETPUBKEY] ❌ Tag nicht in meinen v4 Adressen")
                return

        if myAddress == '':
            print(f"[GETPUBKEY] ❌ Keine Übereinstimmung gefunden, ignoriere")
            logger.info('This getpubkey request is not for any of my keys.')
            return

        
        # Decode the address to check version and stream
        decoded = decodeAddress(myAddress)
        myAddressVersion = decoded[1]
        myStreamNumber = decoded[2]
        myRipe = decoded[3]
        
        print(f"[GETPUBKEY] Decoded: Version={myAddressVersion}, Stream={myStreamNumber}, RIPE={hexlify(myRipe)}")

        if myAddressVersion != requestedAddressVersionNumber:
            print(f"[GETPUBKEY] ❌ Versionskonflikt: {myAddressVersion} != {requestedAddressVersionNumber}")
            return logger.warning(
                '(Within the processgetpubkey function) Someone requested'
                ' one of my pubkeys but the requestedAddressVersionNumber'
                ' doesn\'t match my actual address version number.'
                ' Ignoring.')
        
        if myStreamNumber != streamNumber:
            print(f"[GETPUBKEY] ❌ Stream mismatch: {myStreamNumber} != {streamNumber}")
            return logger.warning(
                '(Within the processgetpubkey function) Someone requested'
                ' one of my pubkeys but the stream number on which we'
                ' heard this getpubkey object doesn\'t match this'
                ' address\' stream number. Ignoring.')
        
        # Check if it's a chan address
        chan_status = config.safeGetBoolean(myAddress, 'chan')
        
        if chan_status:
            print(f"[GETPUBKEY] ℹ️ Chan-Adresse, ignoriere")
            return logger.info(
                'Ignoring getpubkey request because it is for one of my'
                ' chan addresses. The other party should already have'
                ' the pubkey.')
        
        # Check last pubkey send time
        lastPubkeySendTime = config.safeGetInt(myAddress, 'lastpubkeysendtime')
        current_time = time.time()
        twenty_eight_days = 2419200  # 28 days in seconds
        
        print(f"[GETPUBKEY] Last sent: {lastPubkeySendTime}, Current: {current_time}")
        print(f"[GETPUBKEY] Difference: {current_time - lastPubkeySendTime}s, Limit: {twenty_eight_days}s")
        
        # If the last time we sent our pubkey was more recent than 28 days ago...
        if lastPubkeySendTime > current_time - twenty_eight_days:
            print(f"[GETPUBKEY] ⏰ Zu früh (Cooldown), ignoriere")
            return logger.info(
                'Found getpubkey-requested-item in my list of EC hashes'
                ' BUT we already sent it recently. Ignoring request.'
                ' The lastPubkeySendTime is: %s', lastPubkeySendTime)
        
        print(f"[GETPUBKEY] ✅ Sende Public Key (Version {myAddressVersion})")
        logger.info(
            'Found getpubkey-requested-hash in my list of EC hashes.'
            ' Telling Worker thread to do the POW for a pubkey message'
            ' and send it out.')
        
        # Queue the appropriate task
        if requestedAddressVersionNumber == 2:
            print(f"[GETPUBKEY] Queue v2 Pubkey Task")
            queues.workerQueue.put(('doPOWForMyV2Pubkey', requestedHash))
        elif requestedAddressVersionNumber == 3:
            print(f"[GETPUBKEY] Queue v3 Pubkey Task")
            queues.workerQueue.put(('sendOutOrStoreMyV3Pubkey', requestedHash))
        elif requestedAddressVersionNumber == 4:
            print(f"[GETPUBKEY] Queue v4 Pubkey Task für {myAddress}")
            queues.workerQueue.put(('sendOutOrStoreMyV4Pubkey', myAddress))
        else:
            print(f"[GETPUBKEY] ERROR: Unknown address version {requestedAddressVersionNumber}")

            
    def processpubkey(self, data):
        """Process a pubkey object"""
        
        print(f"\n[PUBKEY] 📨 Starte Verarbeitung, Datenlänge: {len(data)}")
        pubkeyProcessingStartTime = time.time()
        state.numberOfPubkeysProcessed += 1
        queues.UISignalQueue.put((
            'updateNumberOfPubkeysProcessed', 'no data'))
        
        readPosition = 20  # bypass the nonce, time, and object type
        addressVersion, varintLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += varintLength
        streamNumber, varintLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += varintLength
        
        print(f"[PUBKEY] Adressversion: {addressVersion}, Stream: {streamNumber}")
        
        # SPEZIAL-DEBUG: Für Adresse aus dem Log
        target_address = "BM-2cXUVrDUeSGqWJDys1LPJDBuKHn9w2MdZP"
        target_tag = None
        if addressVersion >= 4:
            # Berechne den Tag für die Zieladresse
            try:
                decoded_target = decodeAddress(target_address)
                if decoded_target:
                    target_version, target_stream, target_ripe = decoded_target[1:]
                    target_tag = highlevelcrypto.double_sha512(
                        encodeVarint(target_version) + encodeVarint(target_stream) + target_ripe
                    )[32:]
                    target_tag_hex = to_hex_string(target_tag)
                    print(f"\n[PUBKEY-DEBUG] Gesuchter Tag für {target_address}:")
                    print(f"  Hex: {hexlify(target_tag)}")
                    print(f"  Hex-String: {target_tag_hex}")
                    
                    # Debug: Zeige alle neededPubkeys
                    print(f"[PUBKEY-DEBUG] Alle neededPubkeys ({len(state.neededPubkeys)}):")
                    for i, (key, value) in enumerate(list(state.neededPubkeys.items())[:10]):
                        if isinstance(key, str):
                            key_disp = f"str: {key[:20]}..." if len(key) > 20 else f"str: {key}"
                        elif isinstance(key, bytes):
                            key_disp = f"bytes: {hexlify(key[:10])}..."
                        else:
                            key_disp = f"{type(key)}: {key}"
                        
                        if isinstance(value, tuple) and len(value) >= 2:
                            print(f"  {i+1}. Key: {key_disp}")
                            print(f"     Value[0] (Adresse): {value[0]}")
                        else:
                            print(f"  {i+1}. Key: {key_disp}, Value: {value}")
            except Exception as e:
                print(f"[PUBKEY-DEBUG] Fehler beim Decodieren der Zieladresse: {e}")
        
        # DEBUG: Nur für bestimmte Versionen loggen
        if addressVersion == 0 or addressVersion == 1:
            print(f"[PUBKEY] ❌ Version 0/1, ignoriere")
            return logger.debug(
                '(Within processpubkey) addressVersion of 0/1 doesn\'t'
                ' make sense.')
        if addressVersion > 4:
            print(f"[PUBKEY] ❌ Version >4, ignoriere")
            return logger.info(
                'This version of Bitmessage cannot handle version %s'
                ' addresses.', addressVersion)
        
        if addressVersion == 2:
            # sanity check. This is the minimum possible length.
            if len(data) < 146:
                print(f"[PUBKEY] ❌ v2 Daten zu kurz ({len(data)} < 146)")
                return logger.debug(
                    '(within processpubkey) payloadLength less than 146.'
                    ' Sanity check failed.')
            readPosition += 4
            pubSigningKey = b'\x04' + data[readPosition:readPosition + 64]
            readPosition += 64
            pubEncryptionKey = b'\x04' + data[readPosition:readPosition + 64]
            if len(pubEncryptionKey) < 65:
                print(f"[PUBKEY] ❌ v2 Encryption key zu kurz")
                return logger.debug(
                    'publicEncryptionKey length less than 64. Sanity check'
                    ' failed.')
            readPosition += 64
            # The data we'll store in the pubkeys table.
            dataToStore = data[20:readPosition]
            ripe = highlevelcrypto.to_ripe(pubSigningKey, pubEncryptionKey)

            address = encodeAddress(addressVersion, streamNumber, ripe)
            
            print(f"\n[PUBKEY] ✅ v2 Pubkey erhalten für: {address}")
            print(f"[PUBKEY] RIPE: {hexlify(ripe)}")
            
            # Prüfen ob wir auf diesen Key warten
            print(f"[PUBKEY] Prüfe state.neededPubkeys...")
            print(f"[PUBKEY] Aktuelle neededPubkeys Keys: {list(state.neededPubkeys.keys())}")
            
            if address in state.neededPubkeys:
                print(f"🔥🔥🔥 [PUBKEY] WICHTIG: Wir warten auf diesen v2 Key!")
            else:
                print(f"[PUBKEY] ℹ️ Wir warten nicht auf diesen v2 Key")
            
            queryreturn = sqlQuery(
                "SELECT usedpersonally FROM pubkeys WHERE address=?"
                " AND usedpersonally='yes'", dbstr(address))
            # if this pubkey is already in our database and if we have
            # used it personally:
            if queryreturn != []:
                print(f"[PUBKEY] ℹ️ Key bereits bekannt, aktualisiere Zeit")
                logger.info(
                    'We HAVE used this pubkey personally. Updating time.')
                t = (dbstr(address), addressVersion, sqlite3.Binary(dataToStore),
                     int(time.time()), 'yes')
            else:
                print(f"[PUBKEY] 💾 Neuer Key, speichere in Datenbank")
                logger.info(
                    'We have NOT used this pubkey personally. Inserting'
                    ' in database.')
                t = (dbstr(address), addressVersion, sqlite3.Binary(dataToStore),
                     int(time.time()), 'no')
            
            sqlExecute('''INSERT INTO pubkeys VALUES (?,?,?,?,?)''', *t)
            self.possibleNewPubkey(address)
            
        elif addressVersion == 3:
            if len(data) < 170:  # sanity check.
                print(f"[PUBKEY] ❌ v3 Daten zu kurz ({len(data)} < 170)")
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
                print(f"[PUBKEY] ✅ v3 Key verifiziert")
                logger.debug('ECDSA verify passed (within processpubkey)')
            else:
                print(f"[PUBKEY] ❌ v3 Key Verifikation fehlgeschlagen")
                logger.warning('ECDSA verify failed (within processpubkey)')
                return

            ripe = highlevelcrypto.to_ripe(pubSigningKey, pubEncryptionKey)
            address = encodeAddress(addressVersion, streamNumber, ripe)
            
            print(f"\n[PUBKEY] ✅ v3 Pubkey erhalten für: {address}")
            print(f"[PUBKEY] RIPE: {hexlify(ripe)}")
            print(f"[PUBKEY] Prüfe state.neededPubkeys...")
            print(f"[PUBKEY] Aktuelle neededPubkeys: {list(state.neededPubkeys.keys())}")

            if address in state.neededPubkeys:
                print(f"🔥🔥🔥 [PUBKEY] WICHTIG: Wir warten auf diesen v3 Key!")
            
            queryreturn = sqlQuery(
                "SELECT usedpersonally FROM pubkeys WHERE address=?"
                " AND usedpersonally='yes'", dbstr(address))
            # if this pubkey is already in our database and if we have
            # used it personally:
            if queryreturn != []:
                print(f"[PUBKEY] ℹ️ v3 Key bereits bekannt, aktualisiere Zeit")
                logger.info(
                    'We HAVE used this pubkey personally. Updating time.')
                t = (dbstr(address), addressVersion, sqlite3.Binary(dataToStore),
                     int(time.time()), dbstr('yes'))
            else:
                print(f"[PUBKEY] 💾 Neuer v3 Key, speichere in Datenbank")
                logger.info(
                    'We have NOT used this pubkey personally. Inserting'
                    ' in database.')
                t = (dbstr(address), addressVersion, sqlite3.Binary(dataToStore),
                     int(time.time()), dbstr('no'))
            
            sqlExecute('''INSERT INTO pubkeys VALUES (?,?,?,?,?)''', *t)
            print(f"[PUBKEY] Rufe possibleNewPubkey auf...")
            self.possibleNewPubkey(address)
            
        elif addressVersion == 4:
            if len(data) < 350:  # sanity check.
                print(f"[PUBKEY] ❌ v4 Daten zu kurz ({len(data)} < 350)")
                return logger.debug(
                    '(within processpubkey) payloadLength less than 350.'
                    ' Sanity check failed.')

            tag = data[readPosition:readPosition + 32]
            # WICHTIG: Konvertiere zu hex-String für bidirektionale Kompatibilität
            tag_hex = to_hex_string(tag)
            
            print(f"\n[PUBKEY] 📨 v4 Pubkey erhalten")
            print(f"[PUBKEY] Tag: {hexlify(tag)}")
            print(f"[PUBKEY] Tag (hex string): {tag_hex}")
            print(f"[PUBKEY] Aktuelle neededPubkeys Keys ({len(state.neededPubkeys)}):")
            
            # Zeige alle neededPubkeys Keys mit ihren Typen
            for i, key in enumerate(list(state.neededPubkeys.keys())[:10]):
                if isinstance(key, str):
                    print(f"  {i+1}. str key: {key[:30]}... (Länge: {len(key)})")
                elif isinstance(key, bytes):
                    print(f"  {i+1}. bytes key: {hexlify(key[:10])}... (Länge: {len(key)})")
                else:
                    print(f"  {i+1}. {type(key)} key: {key}")
            
            # SPEZIAL: Check für die spezifische Adresse aus dem Log
            if target_tag:
                print(f"\n[PUBKEY-DEBUG] Vergleich mit gesuchtem Tag:")
                print(f"  Eingegangener Tag: {hexlify(tag)}")
                print(f"  Gesuchter Tag:     {hexlify(target_tag)}")
                print(f"  Gleich? {tag == target_tag}")
                print(f"  Tag hex strings gleich? {tag_hex == target_tag_hex}")
            
            # NUR LOGGEN wenn wir auf diesen Key warten
            if tag_hex in state.neededPubkeys:
                toAddress = state.neededPubkeys[tag_hex][0]
                print(f"\n🔥🔥🔥 [PUBKEY] ✅ WIR WARTEN AUF DIESEN v4 KEY!")
                print(f"[PUBKEY]   Für Adresse: {toAddress}")
                
                # Let us try to decrypt the pubkey
                result = protocol.decryptAndCheckPubkeyPayload(data, toAddress)
                
                if result == 'successful':
                    print(f"[PUBKEY] ✅ v4 Key erfolgreich entschlüsselt")
                    # At this point we know that we have been waiting on this
                    # pubkey. This function will command the workerThread
                    # to start work on the messages that require it.
                    print(f"[PUBKEY] Rufe possibleNewPubkey auf...")
                    self.possibleNewPubkey(toAddress)
                else:
                    print(f"[PUBKEY] ❌ v4 Key Entschlüsselung fehlgeschlagen: {result}")
            else:
                # Check if we're looking for it with bytes key instead of hex string
                if tag in state.neededPubkeys:
                    print(f"\n🔥🔥🔥 [PUBKEY] ✅ WIR WARTEN AUF DIESEN v4 KEY (bytes key)!")
                    toAddress = state.neededPubkeys[tag][0]
                    print(f"[PUBKEY]   Für Adresse: {toAddress}")
                    
                    result = protocol.decryptAndCheckPubkeyPayload(data, toAddress)
                    if result == 'successful':
                        print(f"[PUBKEY] ✅ v4 Key erfolgreich entschlüsselt")
                        self.possibleNewPubkey(toAddress)
                else:
                    print(f"\n[PUBKEY] ℹ️ Nicht benötigter v4 Key (nicht in neededPubkeys)")
                    if target_tag:
                        print(f"[PUBKEY]   Vergleich mit gesuchtem Tag: {tag == target_tag}")
                        if tag_hex != target_tag_hex:
                            print(f"[PUBKEY]   Hex strings unterschiedlich!")
                            print(f"    Eingegangen: {tag_hex[:20]}...")
                            print(f"    Gesucht:     {target_tag_hex[:20]}...")

        # Display timing data
        processing_time = time.time() - pubkeyProcessingStartTime
        if addressVersion >= 2 and addressVersion <= 4:
            print(f"[PUBKEY] Verarbeitungszeit: {processing_time:.3f}s")


    def processmsg(self, data):
        """Process a message object"""
        print(f"\n[MESSAGE] Starte Nachrichtenverarbeitung, Länge: {len(data)}")
        messageProcessingStartTime = time.time()
        state.numberOfMessagesProcessed += 1
        queues.UISignalQueue.put((
            'updateNumberOfMessagesProcessed', 'no data'))
        readPosition = 20  # bypass the nonce, time, and object type
        msgVersion, msgVersionLength = decodeVarint(
            data[readPosition:readPosition + 9])
        if msgVersion != 1:
            print(f"[MESSAGE] ❌ Ungültige Message Version: {msgVersion}")
            return logger.info(
                'Cannot understand message versions other than one.'
                ' Ignoring message.')
        readPosition += msgVersionLength

        streamNumberAsClaimedByMsg, streamNumberAsClaimedByMsgLength = \
            decodeVarint(data[readPosition:readPosition + 9])
        readPosition += streamNumberAsClaimedByMsgLength
        inventoryHash = highlevelcrypto.calculateInventoryHash(data)
        initialDecryptionSuccessful = False

        print(f"[MESSAGE] Versuche Entschlüsselung mit {len(shared.myECCryptorObjects)} meiner Keys...")

        # This is not an acknowledgement bound for me. See if it is a message
        # bound for me by trying to decrypt it with my private keys.

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
                    # Konvertiere key zu hex-String für Kompatibilität
                    toRipe = to_hex_string(key)
                    initialDecryptionSuccessful = True
                    print(f"\n[MESSAGE] ✅ Nachricht für mich entschlüsselt!")
                    print(f"[MESSAGE] Empfänger RIPE: {hexlify(key)}")
                    logger.info(
                        'EC decryption successful using key associated'
                        ' with ripe hash: %s.', hexlify(key))
            except Exception:  # nosec B110
                pass
        if not initialDecryptionSuccessful:
            # This is not a message bound for me.
            print(f"[MESSAGE] ❌ Nachricht nicht für mich entschlüsselbar")
            return logger.info(
                'Length of time program spent failing to decrypt this'
                ' message: %s seconds.',
                time.time() - messageProcessingStartTime)

        # This is a message bound for me.
        # Look up my address based on the RIPE hash.
        toAddress = shared.myAddressesByHash[toRipe]
        readPosition = 0
        sendersAddressVersionNumber, sendersAddressVersionNumberLength = \
            decodeVarint(decryptedData[readPosition:readPosition + 10])
        readPosition += sendersAddressVersionNumberLength
        if sendersAddressVersionNumber == 0:
            print(f"[MESSAGE] ❌ Sender Version 0, ignoriere")
            return logger.info(
                'Cannot understand sendersAddressVersionNumber = 0.'
                ' Ignoring message.')
        if sendersAddressVersionNumber > 4:
            print(f"[MESSAGE] ❌ Sender Version >4, ignoriere")
            return logger.info(
                'Sender\'s address version number %s not yet supported.'
                ' Ignoring message.', sendersAddressVersionNumber)
        if len(decryptedData) < 170:
            print(f"[MESSAGE] ❌ Daten zu kurz ({len(decryptedData)} < 170)")
            return logger.info(
                'Length of the unencrypted data is unreasonably short.'
                ' Sanity check failed. Ignoring message.')
        sendersStreamNumber, sendersStreamNumberLength = decodeVarint(
            decryptedData[readPosition:readPosition + 10])
        if sendersStreamNumber == 0:
            print(f"[MESSAGE] ❌ Sender Stream 0, ignoriere")
            logger.info('sender\'s stream number is 0. Ignoring message.')
            return
        readPosition += sendersStreamNumberLength
        readPosition += 4
        # PYTHON 2/3 KOMPATIBEL: Konvertiere zu bytes
        pubSigningKey_raw = decryptedData[readPosition:readPosition + 64]
        pubSigningKey = b'\x04' + (pubSigningKey_raw.tobytes() if hasattr(pubSigningKey_raw, 'tobytes') else pubSigningKey_raw)
        readPosition += 64
        pubEncryptionKey_raw = decryptedData[readPosition:readPosition + 64]
        pubEncryptionKey = b'\x04' + (pubEncryptionKey_raw.tobytes() if hasattr(pubEncryptionKey_raw, 'tobytes') else pubEncryptionKey_raw)
        readPosition += 64
        if sendersAddressVersionNumber >= 3:
            requiredAverageProofOfWorkNonceTrialsPerByte, varintLength = \
                decodeVarint(decryptedData[readPosition:readPosition + 10])
            readPosition += varintLength
            logger.info(
                'sender\'s requiredAverageProofOfWorkNonceTrialsPerByte is %s',
                requiredAverageProofOfWorkNonceTrialsPerByte)
            requiredPayloadLengthExtraBytes, varintLength = decodeVarint(
                decryptedData[readPosition:readPosition + 10])
            readPosition += varintLength
            logger.info(
                'sender\'s requiredPayloadLengthExtraBytes is %s',
                requiredPayloadLengthExtraBytes)
        # needed for when we store the pubkey in our database of pubkeys
        # for later use.
        endOfThePublicKeyPosition = readPosition
        # Konvertiere toRipe zurück zu bytes für Vergleich
        toRipe_bytes = from_hex_string(toRipe)
        if toRipe_bytes != decryptedData[readPosition:readPosition + 20]:
            print(f"[MESSAGE] ❌ RIPE mismatch - Surreptitious Forwarding Attack!")
            return logger.info(
                'The original sender of this message did not send it to'
                ' you. Someone is attempting a Surreptitious Forwarding'
                ' Attack.\nSee: '
                'http://world.std.com/~dtd/sign_encrypt/sign_encrypt7.html'
                '\nyour toRipe: %s\nembedded destination toRipe: %s',
                hexlify(toRipe_bytes),
                hexlify(decryptedData[readPosition:readPosition + 20])
            )
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
        # PYTHON 2/3 KOMPATIBEL: Konvertiere data[8:20] zu bytes
        data_slice = data[8:20]
        if hasattr(data_slice, 'tobytes'):
            data_slice = data_slice.tobytes()
        signedData = data_slice + encodeVarint(1) + encodeVarint(
            streamNumberAsClaimedByMsg
        ) + decryptedData[:positionOfBottomOfAckData]

        if not highlevelcrypto.verify(
                signedData, signature, hexlify(pubSigningKey)):
            print(f"[MESSAGE] ❌ Signature verification failed")
            return logger.debug('ECDSA verify failed')
        print(f"[MESSAGE] ✅ Signature verification passed")
        logger.debug('ECDSA verify passed')
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

        # calculate the fromRipe.
        ripe = highlevelcrypto.to_ripe(pubSigningKey, pubEncryptionKey)
        fromAddress = encodeAddress(
            sendersAddressVersionNumber, sendersStreamNumber, ripe)

        print(f"\n[MESSAGE] 📨 Nachrichtendetails:")
        print(f"[MESSAGE] Absender: {fromAddress}")
        print(f"[MESSAGE] Empfänger: {toAddress}")
        print(f"[MESSAGE] Absender RIPE: {hexlify(ripe)}")

        # Let's store the public key in case we want to reply to this
        # person.
        sqlExecute(
            '''INSERT INTO pubkeys VALUES (?,?,?,?,?)''',
            dbstr(fromAddress),
            sendersAddressVersionNumber,
            sqlite3.Binary(decryptedData[:endOfThePublicKeyPosition]),
            int(time.time()),
            dbstr('yes'))

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
                    print(f"[MESSAGE] ❌ Proof of Work unzureichend")
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
                print(f"[MESSAGE] ❌ Absender in Blacklist")
                logger.info('Message ignored because address is in blacklist.')

                blockMessage = True
        else:  # We're using a whitelist
            queryreturn = sqlQuery(
                "SELECT label FROM whitelist where address=? and enabled='1'",
                dbstr(fromAddress))
            if queryreturn == []:
                print(f"[MESSAGE] ❌ Absender nicht in Whitelist")
                logger.info(
                    'Message ignored because address not in whitelist.')
                blockMessage = True

        # toLabel = config.safeGet(toAddress, 'label', toAddress)
        try:
            decodedMessage = helper_msgcoding.MsgDecode(
                messageEncodingType, message)
        except helper_msgcoding.MsgDecodeException:
            print(f"[MESSAGE] ❌ Fehler beim Decodieren der Nachricht")
            return
        subject = decodedMessage.subject
        body = decodedMessage.body

        # Let us make sure that we haven't already received this message
        if helper_inbox.isMessageAlreadyInInbox(sigHash):
            print(f"[MESSAGE] ℹ️ Nachricht bereits im Posteingang")
            logger.info('This msg is already in our inbox. Ignoring it.')
            blockMessage = True
        if not blockMessage:
            if messageEncodingType != 0:
                t = (inventoryHash, toAddress, fromAddress, subject,
                     int(time.time()), body, 'inbox', messageEncodingType,
                     0, sigHash)
                helper_inbox.insert(t)

                queues.UISignalQueue.put(('displayNewInboxMessage', (
                    inventoryHash, toAddress, fromAddress, subject, body)))
                print(f"[MESSAGE] 📨 Nachricht gespeichert: '{subject[:50]}...'")

            # If we are behaving as an API then we might need to run an
            # outside command to let some program know that a new message
            # has arrived.
            if config.safeGetBoolean(
                    'bitmessagesettings', 'apienabled'):
                apiNotifyPath = config.safeGet(
                    'bitmessagesettings', 'apinotifypath')
                if apiNotifyPath:
                    subprocess.call([apiNotifyPath, "newMessage"])  # nosec B603

            # Let us now check and see whether our receiving address is
            # behaving as a mailing list
            if config.safeGetBoolean(toAddress, 'mailinglist') \
                    and messageEncodingType != 0:
                mailingListName = config.safeGet(
                    toAddress, 'mailinglistname', '')
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
            ackPayload = ackData[24:]
            objectType, toStreamNumber, expiresTime = \
                protocol.decodeObjectParameters(ackPayload)
            inventoryHash = highlevelcrypto.calculateInventoryHash(ackPayload)
            state.Inventory[inventoryHash] = (
                objectType, toStreamNumber, ackPayload, expiresTime, b'')
            invQueue.put((toStreamNumber, inventoryHash))

        # Display timing data
        timeRequiredToAttemptToDecryptMessage = time.time(
        ) - messageProcessingStartTime
        self.successfullyDecryptMessageTimings.append(
            timeRequiredToAttemptToDecryptMessage)
        timing_sum = 0
        for item in self.successfullyDecryptMessageTimings:
            timing_sum += item
        print(f"[MESSAGE] Verarbeitungszeit: {timeRequiredToAttemptToDecryptMessage:.3f}s")
        logger.debug(
            'Time to decrypt this message successfully: %s'
            '\nAverage time for all message decryption successes since'
            ' startup: %s.',
            timeRequiredToAttemptToDecryptMessage,
            timing_sum / len(self.successfullyDecryptMessageTimings)
        )

    def processbroadcast(self, data):
        """Process a broadcast object"""
        print(f"\n[BROADCAST] Starte Verarbeitung, Länge: {len(data)}")
        messageProcessingStartTime = time.time()
        state.numberOfBroadcastsProcessed += 1
        queues.UISignalQueue.put((
            'updateNumberOfBroadcastsProcessed', 'no data'))
        inventoryHash = highlevelcrypto.calculateInventoryHash(data)
        readPosition = 20  # bypass the nonce, time, and object type
        broadcastVersion, broadcastVersionLength = decodeVarint(
            data[readPosition:readPosition + 9])
        readPosition += broadcastVersionLength
        if broadcastVersion < 4 or broadcastVersion > 5:
            print(f"[BROADCAST] ❌ Ungültige Version: {broadcastVersion}")
            return logger.info(
                'Cannot decode incoming broadcast versions less than 4'
                ' or higher than 5. Assuming the sender isn\'t being silly,'
                ' You should upgrade Bitmessage because this message shall'
                ' be ignored.'
            )
        cleartextStreamNumber, cleartextStreamNumberLength = decodeVarint(
            data[readPosition:readPosition + 10])
        readPosition += cleartextStreamNumberLength
        if broadcastVersion == 4:
            # v4 broadcasts are encrypted the same way the msgs are
            # encrypted. To see if we are interested in a v4 broadcast,
            # we try to decrypt it. This was replaced with v5 broadcasts
            # which include a tag which we check instead, just like we do
            # with v4 pubkeys.
            signedData = data[8:readPosition]
            initialDecryptionSuccessful = False
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
                        # Konvertiere zu hex-String für Kompatibilität
                        toRipe = to_hex_string(key)
                        initialDecryptionSuccessful = True
                        logger.info(
                            'EC decryption successful using key associated'
                            ' with ripe hash: %s', hexlify(key))
                except Exception:
                    logger.debug(
                        'cryptorObject.decrypt Exception:', exc_info=True)
            if not initialDecryptionSuccessful:
                # This is not a broadcast I am interested in.
                print(f"[BROADCAST] ❌ Nicht für mich entschlüsselbar")
                return logger.debug(
                    'Length of time program spent failing to decrypt this'
                    ' v4 broadcast: %s seconds.',
                    time.time() - messageProcessingStartTime)
        elif broadcastVersion == 5:
            embeddedTag = data[readPosition:readPosition + 32]
            readPosition += 32
            # WICHTIG: Konvertiere zu hex-String für Kompatibilität
            embeddedTag_hex = to_hex_string(embeddedTag)
            if embeddedTag_hex not in shared.MyECSubscriptionCryptorObjects:
                print(f"[BROADCAST] ℹ️ Nicht interessiert an diesem Broadcast")
                logger.debug('We\'re not interested in this broadcast.')
                return
            # We are interested in this broadcast because of its tag.
            # We're going to add some more data which is signed further down.
            # PYTHON 2/3 KOMPATIBEL: Konvertiere zu bytes
            data_slice = data[8:readPosition]
            if hasattr(data_slice, 'tobytes'):
                data_slice = data_slice.tobytes()
            signedData = data_slice
            cryptorObject = shared.MyECSubscriptionCryptorObjects[embeddedTag_hex]
            try:
                decryptedData = cryptorObject.decrypt(data[readPosition:])
                logger.debug('EC decryption successful')
            except Exception:
                return logger.debug(
                    'Broadcast version %s decryption Unsuccessful.',
                    broadcastVersion)
        # At this point this is a broadcast I have decrypted and am
        # interested in.
        readPosition = 0
        sendersAddressVersion, sendersAddressVersionLength = decodeVarint(
            decryptedData[readPosition:readPosition + 9])
        if broadcastVersion == 4:
            if sendersAddressVersion < 2 or sendersAddressVersion > 3:
                return logger.warning(
                    'Cannot decode senderAddressVersion other than 2 or 3.'
                    ' Assuming the sender isn\'t being silly, you should'
                    ' upgrade Bitmessage because this message shall be'
                    ' ignored.'
                )
        elif broadcastVersion == 5:
            if sendersAddressVersion < 4:
                return logger.info(
                    'Cannot decode senderAddressVersion less than 4 for'
                    ' broadcast version number 5. Assuming the sender'
                    ' isn\'t being silly, you should upgrade Bitmessage'
                    ' because this message shall be ignored.'
                )
        readPosition += sendersAddressVersionLength
        sendersStream, sendersStreamLength = decodeVarint(
            decryptedData[readPosition:readPosition + 9])
        if sendersStream != cleartextStreamNumber:
            return logger.info(
                'The stream number outside of the encryption on which the'
                ' POW was completed doesn\'t match the stream number'
                ' inside the encryption. Ignoring broadcast.'
            )
        readPosition += sendersStreamLength
        readPosition += 4
        # PYTHON 2/3 KOMPATIBEL: Konvertiere zu bytes
        sendersPubSigningKey_raw = decryptedData[readPosition:readPosition + 64]
        sendersPubSigningKey = b'\x04' + (sendersPubSigningKey_raw.tobytes() if hasattr(sendersPubSigningKey_raw, 'tobytes') else sendersPubSigningKey_raw)
        readPosition += 64
        sendersPubEncryptionKey_raw = decryptedData[readPosition:readPosition + 64]
        sendersPubEncryptionKey = b'\x04' + (sendersPubEncryptionKey_raw.tobytes() if hasattr(sendersPubEncryptionKey_raw, 'tobytes') else sendersPubEncryptionKey_raw)
        readPosition += 64
        if sendersAddressVersion >= 3:
            requiredAverageProofOfWorkNonceTrialsPerByte, varintLength = \
                decodeVarint(decryptedData[readPosition:readPosition + 10])
            readPosition += varintLength
            logger.debug(
                'sender\'s requiredAverageProofOfWorkNonceTrialsPerByte'
                ' is %s', requiredAverageProofOfWorkNonceTrialsPerByte)
            requiredPayloadLengthExtraBytes, varintLength = decodeVarint(
                decryptedData[readPosition:readPosition + 10])
            readPosition += varintLength
            logger.debug(
                'sender\'s requiredPayloadLengthExtraBytes is %s',
                requiredPayloadLengthExtraBytes)
        endOfPubkeyPosition = readPosition

        calculatedRipe = highlevelcrypto.to_ripe(
            sendersPubSigningKey, sendersPubEncryptionKey)

        if broadcastVersion == 4:
            # Konvertiere toRipe zurück zu bytes für Vergleich
            toRipe_bytes = from_hex_string(toRipe)
            if toRipe_bytes != calculatedRipe:
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
            # Konvertiere embeddedTag zurück zu bytes für Vergleich
            embeddedTag_bytes = from_hex_string(embeddedTag_hex)
            if calculatedTag != embeddedTag_bytes:
                return logger.debug(
                    'The tag and encryption key used to encrypt this'
                    ' message doesn\'t match the keys inbedded in the'
                    ' message itself. Ignoring message.'
                )
        messageEncodingType, messageEncodingTypeLength = decodeVarint(
            decryptedData[readPosition:readPosition + 9])
        if messageEncodingType == 0:
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
            logger.debug('ECDSA verify failed')
            return
        logger.debug('ECDSA verify passed')
        # Used to detect and ignore duplicate messages in our inbox
        sigHash = highlevelcrypto.double_sha512(signature)[32:]

        fromAddress = encodeAddress(
            sendersAddressVersion, sendersStream, calculatedRipe)
        logger.info('fromAddress: %s', fromAddress)

        # Let's store the public key in case we want to reply to this person.
        sqlExecute('''INSERT INTO pubkeys VALUES (?,?,?,?,?)''',
                   dbstr(fromAddress),
                   dbstr(sendersAddressVersion),
                   sqlite3.Binary(decryptedData[:endOfPubkeyPosition]),
                   int(time.time()),
                   dbstr('yes'))

        # Check to see whether we happen to be awaiting this
        # pubkey in order to send a message. If we are, it will do the POW
        # and send it.
        self.possibleNewPubkey(fromAddress)

        try:
            decodedMessage = helper_msgcoding.MsgDecode(
                messageEncodingType, message)
        except helper_msgcoding.MsgDecodeException:
            return
        subject = decodedMessage.subject
        body = decodedMessage.body

        toAddress = '[Broadcast subscribers]'
        if helper_inbox.isMessageAlreadyInInbox(sigHash):
            logger.info('This broadcast is already in our inbox. Ignoring it.')
            return
        t = (inventoryHash, toAddress, fromAddress, subject, int(
            time.time()), body, 'inbox', messageEncodingType, 0, sigHash)
        helper_inbox.insert(t)

        queues.UISignalQueue.put(('displayNewInboxMessage', (
            inventoryHash, toAddress, fromAddress, subject, body)))

        # If we are behaving as an API then we might need to run an
        # outside command to let some program know that a new message
        # has arrived.
        if config.safeGetBoolean('bitmessagesettings', 'apienabled'):
            apiNotifyPath = config.safeGet(
                'bitmessagesettings', 'apinotifypath')
            if apiNotifyPath:
                subprocess.call([apiNotifyPath, "newBroadcast"])  # nosec B603

        # Display timing data
        logger.info(
            'Time spent processing this interesting broadcast: %s',
            time.time() - messageProcessingStartTime)

    def possibleNewPubkey(self, address):
        """
        We have inserted a pubkey into our pubkey table which we received
        from a pubkey, msg, or broadcast message. It might be one that we
        have been waiting for. Let's check.
        """
        print(f"\n{'='*80}")
        print(f"[POSSIBLE-NEW-PUBKEY] Prüfe ob wir auf diesen Key warten: {address}")
        
        # For address versions <= 3, we wait on a key with the correct
        # address version, stream number and RIPE hash.
        try:
            addressVersion, streamNumber, ripe = decodeAddress(address)[1:]
        except Exception as e:
            print(f"[POSSIBLE-NEW-PUBKEY] ❌ Fehler beim Decodieren: {e}")
            return
            
        print(f"[POSSIBLE-NEW-PUBKEY] Details:")
        print(f"  Version: {addressVersion}")
        print(f"  Stream: {streamNumber}")
        print(f"  RIPE: {hexlify(ripe)}")
        
        if addressVersion <= 3:
            print(f"[POSSIBLE-NEW-PUBKEY] Prüfe neededPubkeys für v{addressVersion}")
            print(f"[POSSIBLE-NEW-PUBKEY] Aktuelle neededPubkeys ({len(state.neededPubkeys)}):")
            
            # Debug: Zeige alle neededPubkeys
            for i, (key, value) in enumerate(list(state.neededPubkeys.items())[:10]):
                if isinstance(key, str):
                    key_disp = f"str: {key[:30]}..." if len(key) > 30 else f"str: {key}"
                elif isinstance(key, bytes):
                    key_disp = f"bytes: {hexlify(key[:10])}..."
                else:
                    key_disp = f"{type(key)}: {key}"
                print(f"  {i+1}. Key: {key_disp}")
            
            if address in state.neededPubkeys:
                print(f"\n🔥🔥🔥 [POSSIBLE-NEW-PUBKEY] ✅ WICHTIG: Wir warten auf diesen Key!")
                print(f"[POSSIBLE-NEW-PUBKEY]   Entferne aus neededPubkeys und sende wartende Nachrichten")
                del state.neededPubkeys[address]
                self.sendMessages(address)
            else:
                print(f"\n[POSSIBLE-NEW-PUBKEY] ℹ️ Wir warten nicht auf diesen Key")
                logger.debug(
                    'We don\'t need this pub key. We didn\'t ask for it.'
                    ' For address: %s', address)
        # For address versions >= 4, we wait on a pubkey with the correct tag.
        # Let us create the tag from the address and see if we were waiting
        # for it.
        elif addressVersion >= 4:
            tag = highlevelcrypto.double_sha512(
                encodeVarint(addressVersion) + encodeVarint(streamNumber)
                + ripe
            )[32:]
            # WICHTIG: Konvertiere zu hex-String für Kompatibilität
            tag_hex = to_hex_string(tag)
            tag_bytes = tag  # behalte auch bytes
            
            print(f"\n[POSSIBLE-NEW-PUBKEY] Berechneter Tag für v{addressVersion}:")
            print(f"  Bytes: {hexlify(tag)}")
            print(f"  Hex-String: {tag_hex}")
            
            print(f"[POSSIBLE-NEW-PUBKEY] Aktuelle neededPubkeys ({len(state.neededPubkeys)}):")
            # Debug: Zeige alle neededPubkeys
            for i, (key, value) in enumerate(list(state.neededPubkeys.items())[:10]):
                if isinstance(key, str):
                    key_disp = f"str: {key[:30]}..." if len(key) > 30 else f"str: {key}"
                elif isinstance(key, bytes):
                    key_disp = f"bytes: {hexlify(key[:10])}..."
                else:
                    key_disp = f"{type(key)}: {key}"
                print(f"  {i+1}. Key: {key_disp}")
            
            # Prüfe sowohl mit bytes als auch mit hex string
            found = False
            if tag_bytes in state.neededPubkeys:
                print(f"\n🔥🔥🔥 [POSSIBLE-NEW-PUBKEY] ✅ WICHTIG: Wir warten auf diesen v4 Key (bytes key)!")
                found = True
                del state.neededPubkeys[tag_bytes]
                self.sendMessages(address)
            elif tag_hex in state.neededPubkeys:
                print(f"\n🔥🔥🔥 [POSSIBLE-NEW-PUBKEY] ✅ WICHTIG: Wir warten auf diesen v4 Key (hex string key)!")
                found = True
                del state.neededPubkeys[tag_hex]
                self.sendMessages(address)
            
            if not found:
                print(f"\n[POSSIBLE-NEW-PUBKEY] ℹ️ Wir warten nicht auf diesen v4 Key")
                print(f"  Weder bytes noch hex string gefunden in neededPubkeys")
        
        print(f"{'='*80}")
        
    @staticmethod
    def sendMessages(address):
        """
        This method is called by the `possibleNewPubkey` when it sees
        that we now have the necessary pubkey to send one or more messages.
        """
        print(f"\n[SEND-MESSAGES] 🚀 Sende wartende Nachrichten für: {address}")
        logger.info('We have been awaiting the arrival of this pubkey.')
        
        # Aktualisiere Status der wartenden Nachrichten
        rowcount = sqlExecute(
            "UPDATE sent SET status='doingmsgpow', retrynumber=0"
            " WHERE toaddress=?"
            " AND (status='awaitingpubkey' OR status='doingpubkeypow')"
            " AND folder='sent'", dbstr(address))
        
        print(f"[SEND-MESSAGES] {rowcount} Nachrichten aktualisiert -> 'doingmsgpow'")
        
        # Starte Message-POW in Worker-Queue
        queues.workerQueue.put(('sendmessage', ''))
        print(f"[SEND-MESSAGES] Worker-Queue Task 'sendmessage' hinzugefügt")

    @staticmethod
    def ackDataHasAValidHeader(ackData):
        """Checking ackData with valid Header, not sending ackData when false"""
        if len(ackData) < protocol.Header.size:
            logger.info(
                'The length of ackData is unreasonably short. Not sending'
                ' ackData.')
            return False

        magic, command, payloadLength, checksum = protocol.Header.unpack(
            ackData[:protocol.Header.size])
        if magic != protocol.magic:
            logger.info('Ackdata magic bytes were wrong. Not sending ackData.')
            return False
        payload = ackData[protocol.Header.size:]
        if len(payload) != payloadLength:
            logger.info(
                'ackData payload length doesn\'t match the payload length'
                ' specified in the header. Not sending ackdata.')
            return False
        # ~1.6 MB which is the maximum possible size of an inv message.
        if payloadLength > 1600100:
            # The largest message should be either an inv or a getdata
            # message at 1.6 MB in size.
            # That doesn't mean that the object may be that big. The
            # shared.checkAndShareObjectWithPeers function will verify
            # that it is no larger than 2^18 bytes.
            return False
        # test the checksum in the message.
        if checksum != hashlib.sha512(payload).digest()[0:4]:
            logger.info('ackdata checksum wrong. Not sending ackdata.')
            return False
        command = command.rstrip(b'\x00')
        if command != b'object':
            return False
        return True

    @staticmethod
    def addMailingListNameToSubject(subject, mailingListName):
        """Adding mailingListName to subject"""
        subject = subject.strip()
        if subject[:3] == 'Re:' or subject[:3] == 'RE:':
            subject = subject[3:].strip()
        if '[' + mailingListName + ']' in subject:
            return subject
        return '[' + mailingListName + '] ' + subject
