"""
Thread for performing PoW
"""
# pylint: disable=protected-access,too-many-branches,too-many-statements
# pylint: disable=no-self-use,too-many-lines,too-many-locals

from __future__ import division

import hashlib
import time
import sqlite3
import os
import sys
import traceback
from binascii import hexlify, unhexlify
from struct import pack
from subprocess import call  # nosec

import six
from six.moves import configparser, queue
from six.moves.reprlib import repr

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
import tr
from addresses import decodeAddress, decodeVarint, encodeVarint
from bmconfigparser import config
from dbcompat import dbstr
from helper_sql import sqlExecute, sqlQuery
from network import StoppableThread, invQueue, knownnodes


def debug_print(msg, *args):
    """Debug-Ausgabe direkt auf stdout für zuverlässige Fehlerbehebung"""
    try:
        timestamp = time.strftime("%H:%M:%S")
        formatted_msg = f"[{timestamp}] DEBUG: {msg}" % args if args else f"[{timestamp}] DEBUG: {msg}"
        print(formatted_msg, file=sys.stderr)
        sys.stderr.flush()
    except:
        pass


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
        debug_print("singleWorker initialisiert")

    def _safe_extract(self, value, to_int=False, is_msgid=False):
        """Safely extract and convert values from database for Python 3"""
        debug_print("_safe_extract: Type des Werts: %s, to_int: %s, is_msgid: %s", 
                    type(value), to_int, is_msgid)
        
        if value is None:
            debug_print("_safe_extract: Wert ist None")
            return 0 if to_int else ""
        
        try:
            # SPEZIALBEHANDLUNG FÜR MSGID: Kein String-Konvertierungsversuch für bytes
            if is_msgid and isinstance(value, bytes):
                debug_print("_safe_extract: MSGID als bytes, Länge: %d - direkt zurückgeben", len(value))
                return value  # msgid als bytes zurückgeben für spätere Verwendung
            
            # Convert bytes to string if needed
            if isinstance(value, bytes):
                debug_print("_safe_extract: Wert ist bytes, Länge: %d", len(value))
                try:
                    if to_int:
                        try:
                            result = int(value)
                            debug_print("_safe_extract: Bytes zu int konvertiert: %d", result)
                            return result
                        except ValueError:
                            decoded = value.decode('utf-8')
                            result = int(decoded)
                            debug_print("_safe_extract: Bytes decoded zu int: %d", result)
                            return result
                    else:
                        result = value.decode('utf-8', 'replace')
                        debug_print("_safe_extract: Bytes zu string konvertiert: %s...", result[:50])
                        return result
                except Exception as e:
                    debug_print("_safe_extract: Fehler bei Konvertierung: %s", e)
                    if to_int:
                        return 0
                    else:
                        return str(value)[2:-1]  # bytes representation
            else:
                debug_print("_safe_extract: Wert ist nicht bytes: %s", type(value))
                # Already string or int
                if to_int:
                    try:
                        result = int(value)
                        debug_print("_safe_extract: Direkt zu int konvertiert: %d", result)
                        return result
                    except (ValueError, TypeError) as e:
                        debug_print("_safe_extract: Fehler bei int-Konvertierung: %s", e)
                        return 0
                else:
                    result = str(value)
                    debug_print("_safe_extract: Direkt zu string konvertiert: %s...", result[:50])
                    return result
        except Exception as e:
            debug_print("_safe_extract: Unerwarteter Fehler: %s", e)
            if to_int:
                return 0
            else:
                return ""

    def stopThread(self):
        """Signal through the queue that the thread should be stopped"""
        debug_print("stopThread aufgerufen")
        try:
            queues.workerQueue.put(("stopThread", "data"))
            debug_print("stopThread in queue platziert")
        except queue.Full:
            debug_print('workerQueue is Full')
        super(singleWorker, self).stopThread()

    def run(self):
        # pylint: disable=attribute-defined-outside-init
        debug_print("singleWorker.run() gestartet")
        debug_print("shutdown status: %d", state.shutdown)

        while not helper_sql.sql_ready.wait(1.0) and state.shutdown == 0:
            debug_print("Warte auf SQL ready...")
            self.stop.wait(1.0)
        
        if state.shutdown > 0:
            debug_print("Shutdown angefordert, beende singleWorker")
            return

        # PYTHON2-LOGIK: Initialize the neededPubkeys dictionary
        debug_print("PYTHON2 STYLE: Initialisiere neededPubkeys dictionary...")
        queryreturn = sqlQuery(
            '''SELECT DISTINCT toaddress FROM sent'''
            ''' WHERE (status='awaitingpubkey' AND folder='sent')''')
        
        debug_print("Gefundene Adressen für pubkey requests: %d", len(queryreturn))
        for row in queryreturn:
            toAddress = row[0]
            debug_print("Verarbeite Adresse für neededPubkeys: %s", type(toAddress))
            
            if isinstance(toAddress, bytes):
                toAddress = toAddress.decode('utf-8', 'replace')
                debug_print("Adresse decoded: %s...", toAddress[:30])
                
            try:
                toStatus, addressVersionNumber, streamNumber, ripe = decodeAddress(toAddress)
                if toStatus != 'success':
                    debug_print("  ✗ Kann Adresse nicht dekodieren: %s", toAddress[:30])
                    continue
                    
                debug_print("  Adresse decodiert: Version=%d, Stream=%d", 
                          addressVersionNumber, streamNumber)
                
                if addressVersionNumber <= 3:
                    state.neededPubkeys[toAddress] = 0
                    debug_print("  ✓ Added to neededPubkeys (v3): %s...", toAddress[:20])
                elif addressVersionNumber >= 4:
                    doubleHashOfAddressData = highlevelcrypto.double_sha512(
                        encodeVarint(addressVersionNumber)
                        + encodeVarint(streamNumber) + ripe
                    )
                    privEncryptionKey = doubleHashOfAddressData[:32]
                    tag = doubleHashOfAddressData[32:]
                    tag_bytes = bytes(tag)
                    state.neededPubkeys[tag_bytes] = (
                        toAddress,
                        highlevelcrypto.makeCryptor(hexlify(privEncryptionKey))
                    )
                    debug_print("  ✓ Added to neededPubkeys (v4) mit tag: %s...", 
                              hexlify(tag_bytes)[:20])
            except Exception as e:
                debug_print("  ✗ Fehler bei neededPubkeys init für %s: %s", 
                          toAddress[:20] if toAddress else "None", e)

        # Der Rest der run() Methode bleibt gleich...
        debug_print("Initialisiere ackdataForWhichImWatching...")
        queryreturn = sqlQuery(
            '''SELECT ackdata FROM sent WHERE status = 'msgsent' AND folder = 'sent' ''')
        debug_print("Gefundene ackdata Einträge: %d", len(queryreturn))
        
        for row in queryreturn:
            ackdata = row[0]
            debug_print("Verarbeite ackdata: Typ=%s", type(ackdata))
            
            if isinstance(ackdata, str):
                ackdata = ackdata.encode('latin-1')
                debug_print("ackdata string zu bytes konvertiert, Länge: %d", len(ackdata))
            elif not isinstance(ackdata, (bytes, bytearray)):
                try:
                    ackdata = bytes(ackdata)
                    debug_print("ackdata zu bytes konvertiert, Länge: %d", len(ackdata))
                except Exception as e:
                    debug_print("Cannot convert ackdata zu bytes: %s", e)
                    continue
            
            debug_print('Beobachte ackdata: %s...', hexlify(ackdata)[:32])
            state.ackdataForWhichImWatching[ackdata] = 0

        # Fix legacy (headerless) watched ackdata to include header
        debug_print("Fixe legacy ackdata entries...")
        for oldack in list(state.ackdataForWhichImWatching.keys()):
            debug_print("Prüfe legacy ackdata: Länge=%d", len(oldack))
            if len(oldack) == 32:
                newack = b'\x00\x00\x00\x02\x01\x01' + oldack
                state.ackdataForWhichImWatching[newack] = 0
                
                try:
                    rowcount = sqlExecute(
                        '''UPDATE sent SET ackdata=? WHERE ackdata=? AND folder = 'sent' ''',
                        newack, oldack
                    )
                    debug_print("Updated %d rows für legacy ackdata %s...", 
                              rowcount, hexlify(oldack)[:16])
                except Exception as e:
                    debug_print("Failed to update legacy ackdata: %s", e)
                    
                del state.ackdataForWhichImWatching[oldack]

        # For the case if user deleted knownnodes but still has onionpeer objects
        if not knownnodes.knownNodesActual:
            debug_print("Initialisiere onionpeer objects")
            for item in state.Inventory.by_type_and_tag(protocol.OBJECT_ONIONPEER):
                queues.objectProcessorQueue.put((
                    protocol.OBJECT_ONIONPEER, item.payload
                ))

        # give some time for the GUI to start before we start on existing POW tasks
        debug_print("Warte 10 Sekunden für GUI Start...")
        self.stop.wait(10)

        if state.shutdown:
            debug_print("Shutdown angefordert, beende singleWorker")
            return

        # just in case there are any pending tasks
        debug_print("Füge initial worker tasks zu queue hinzu...")
        queues.workerQueue.put(('sendmessage', ''))
        queues.workerQueue.put(('sendbroadcast', ''))
        queues.workerQueue.put(('sendOnionPeerObj', ''))

        debug_print("singleWorker main loop gestartet")
        
        while state.shutdown == 0:
            self.busy = 0
            debug_print("Warte auf nächsten Befehl von workerQueue...")
            command, data = queues.workerQueue.get()
            self.busy = 1
            debug_print("Verarbeite Befehl: %s", command)
            
            if command == 'sendmessage':
                try:
                    debug_print("START: sendMsg()")
                    self.sendMsg()
                    debug_print("ENDE: sendMsg()")
                except Exception as e:
                    debug_print("sendMsg failed: %s", e)
                    import traceback
                    traceback.print_exc()
            elif command == 'sendbroadcast':
                try:
                    debug_print("START: sendBroadcast()")
                    self.sendBroadcast()
                    debug_print("ENDE: sendBroadcast()")
                except Exception as e:
                    debug_print("sendBroadcast failed: %s", e)
                    import traceback
                    traceback.print_exc()
            elif command == 'doPOWForMyV2Pubkey':
                try:
                    debug_print("START: doPOWForMyV2Pubkey()")
                    self.doPOWForMyV2Pubkey(data)
                    debug_print("ENDE: doPOWForMyV2Pubkey()")
                except Exception as e:
                    debug_print("doPOWForMyV2Pubkey failed: %s", e)
                    import traceback
                    traceback.print_exc()
            elif command == 'sendOutOrStoreMyV3Pubkey':
                try:
                    debug_print("START: sendOutOrStoreMyV3Pubkey()")
                    self.sendOutOrStoreMyV3Pubkey(data)
                    debug_print("ENDE: sendOutOrStoreMyV3Pubkey()")
                except Exception as e:
                    debug_print("sendOutOrStoreMyV3Pubkey failed: %s", e)
                    import traceback
                    traceback.print_exc()
            elif command == 'sendOutOrStoreMyV4Pubkey':
                try:
                    debug_print("START: sendOutOrStoreMyV4Pubkey()")
                    self.sendOutOrStoreMyV4Pubkey(data)
                    debug_print("ENDE: sendOutOrStoreMyV4Pubkey()")
                except Exception as e:
                    debug_print("sendOutOrStoreMyV4Pubkey failed: %s", e)
                    import traceback
                    traceback.print_exc()
            elif command == 'sendOnionPeerObj':
                try:
                    debug_print("START: sendOnionPeerObj()")
                    self.sendOnionPeerObj(data)
                    debug_print("ENDE: sendOnionPeerObj()")
                except Exception as e:
                    debug_print("sendOnionPeerObj failed: %s", e)
                    import traceback
                    traceback.print_exc()
            elif command == 'resetPoW':
                try:
                    debug_print("START: resetPoW()")
                    proofofwork.resetPoW()
                    debug_print("ENDE: resetPoW()")
                except Exception as e:
                    debug_print("resetPoW failed: %s", e)
                    import traceback
                    traceback.print_exc()
            elif command == 'stopThread':
                self.busy = 0
                debug_print("StopThread Befehl erhalten, beende")
                return
            else:
                debug_print('Ungültiger Befehl an workerThread: %s', command)

            queues.workerQueue.task_done()
            debug_print("Queue task_done aufgerufen")
            
        debug_print("singleWorker beendet (shutdown)")

    def _sql_param(self, value):
        """Convert value to appropriate SQL parameter type"""
        debug_print("_sql_param: Typ=%s", type(value))
        if isinstance(value, bytes):
            debug_print("_sql_param: bytes zu sqlite3.Binary konvertiert")
            return sqlite3.Binary(value)
        elif isinstance(value, str):
            debug_print("_sql_param: string direkt zurückgegeben")
            return value
        elif value is None:
            debug_print("_sql_param: None zurückgegeben")
            return None
        else:
            debug_print("_sql_param: zu string konvertiert: %s", str(value)[:50])
            return str(value)

    def _getKeysForAddress(self, address):
        debug_print("_getKeysForAddress für %s...", address[:30])
        try:
            privSigningKeyBase58 = config.get(address, 'privsigningkey')
            privEncryptionKeyBase58 = config.get(address, 'privencryptionkey')
            debug_print("Schlüssel aus Config gelesen - Sign: %s..., Enc: %s...", 
                      privSigningKeyBase58[:20], privEncryptionKeyBase58[:20])
        except (configparser.NoSectionError, configparser.NoOptionError) as e:
            debug_print('Konnte privkey für Adresse %s nicht lesen: %s', address, e)
            raise ValueError

        # Python 3: Ensure strings are properly encoded
        if isinstance(privSigningKeyBase58, bytes):
            privSigningKeyBase58 = privSigningKeyBase58.decode('utf-8')
            debug_print("privSigningKeyBase58 von bytes zu string konvertiert")
        if isinstance(privEncryptionKeyBase58, bytes):
            privEncryptionKeyBase58 = privEncryptionKeyBase58.decode('utf-8')
            debug_print("privEncryptionKeyBase58 von bytes zu string konvertiert")
        
        debug_print("Decode Wallet Import Format für Signing Key...")
        privSigningKeyHex = hexlify(highlevelcrypto.decodeWalletImportFormat(
            privSigningKeyBase58.encode('utf-8')))
        debug_print("Decode Wallet Import Format für Encryption Key...")
        privEncryptionKeyHex = hexlify(
            highlevelcrypto.decodeWalletImportFormat(
                privEncryptionKeyBase58.encode('utf-8')))

        debug_print("Berechne Public Keys aus Private Keys...")
        pubSigningKey = unhexlify(highlevelcrypto.privToPub(privSigningKeyHex))[1:]
        pubEncryptionKey = unhexlify(highlevelcrypto.privToPub(privEncryptionKeyHex))[1:]
        
        debug_print("_getKeysForAddress erfolgreich - Signing Key Länge: %d, Encryption Key Länge: %d", 
                  len(pubSigningKey), len(pubEncryptionKey))

        return privSigningKeyHex, privEncryptionKeyHex, pubSigningKey, pubEncryptionKey

    @classmethod
    def _doPOWDefaults(
        cls, payload, TTL,
        nonceTrialsPerByte=None, payloadLengthExtraBytes=None,
        log_prefix='', log_time=False
    ):
        """Perform Proof of Work with Python 3 compatibility"""
        debug_print("_doPOWDefaults aufgerufen: log_prefix=%s, TTL=%d", log_prefix, TTL)
        debug_print("Payload Typ: %s, Länge: %d", type(payload), len(payload) if payload else 0)
        
        # Python 3: Ensure payload is bytes
        if isinstance(payload, str):
            debug_print("WARNUNG: Konvertiere string payload zu bytes")
            payload = payload.encode('latin-1')
        elif not isinstance(payload, (bytes, bytearray)):
            debug_print("FEHLER: Ungültiger payload Typ: %s", type(payload))
            try:
                payload = bytes(payload)
                debug_print("Payload zu bytes konvertiert, Länge: %d", len(payload))
            except Exception as e:
                debug_print("Kann payload nicht zu bytes konvertieren: %s", e)
                return None
        
        if not nonceTrialsPerByte:
            nonceTrialsPerByte = defaults.networkDefaultProofOfWorkNonceTrialsPerByte
        if not payloadLengthExtraBytes:
            payloadLengthExtraBytes = defaults.networkDefaultPayloadLengthExtraBytes
        
        debug_print('PoW Parameter: nonceTrialsPerByte=%d, payloadLengthExtraBytes=%d', 
                  nonceTrialsPerByte, payloadLengthExtraBytes)
        debug_print('%s Proof of Work gestartet... TTL: %d', log_prefix, TTL)
        
        if log_time:
            start_time = time.time()
        
        try:
            debug_print("Rufe proofofwork.calculate auf...")
            trialValue, nonce = proofofwork.calculate(
                payload, TTL, nonceTrialsPerByte, payloadLengthExtraBytes)
            debug_print(
                '%s Proof of Work gefunden %s Nonce: %s',
                log_prefix, trialValue, nonce
            )
            
            if log_time and start_time:
                delta = time.time() - start_time
                if delta > 0:
                    debug_print(
                        'PoW dauerte %.1f Sekunden, Geschwindigkeit %s.',
                        delta, sizeof_fmt(nonce / delta)
                    )
                else:
                    debug_print('PoW sehr schnell abgeschlossen')
                    
        except Exception as e:
            debug_print("Proof of Work Berechnung fehlgeschlagen: %s", e)
            raise
        
        # Python 3: Ensure we pack bytes correctly
        try:
            debug_print("Packe nonce mit struct.pack...")
            result = pack('>Q', nonce) + payload
            debug_print("PoW Ergebnis Länge: %d bytes", len(result))
            return result
        except Exception as e:
            debug_print("Fehler beim Packen des PoW Ergebnisses: %s", e)
            return None

    def doPOWForMyV2Pubkey(self, addressHash):
        """This function also broadcasts out the pubkey message once it is done with the POW"""
        debug_print("doPOWForMyV2Pubkey für hash: %s...", 
                  hexlify(addressHash)[:16] if isinstance(addressHash, bytes) else addressHash)
        
        # Python 3: Ensure addressHash is bytes
        if isinstance(addressHash, str):
            try:
                debug_print("Konvertiere addressHash string zu bytes")
                addressHash = unhexlify(addressHash)
            except Exception as e:
                debug_print("Kann addressHash nicht von string konvertieren: %s", e)
                return
        
        try:
            myAddress = shared.myAddressesByHash[addressHash]
            debug_print("Adresse gefunden: %s", myAddress)
        except KeyError:
            debug_print("Adresse hash nicht gefunden in myAddressesByHash: %s...", 
                      hexlify(addressHash)[:16] if isinstance(addressHash, bytes) else "N/A")
            return
        
        addressVersionNumber, streamNumber = decodeAddress(myAddress)[1:3]
        debug_print("Adresse Version: %d, Stream: %d", addressVersionNumber, streamNumber)

        # 28 days from now plus or minus five minutes
        TTL = int(28 * 24 * 60 * 60 + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)
        debug_print("TTL: %d, embeddedTime: %d", TTL, embeddedTime)
        
        # Python 3: Use bytes literals
        payload = pack('>Q', embeddedTime)
        payload += b'\x00\x00\x00\x01'  # object type: pubkey
        payload += encodeVarint(addressVersionNumber)  # Address version number
        payload += encodeVarint(streamNumber)
        
        bitfield = protocol.getBitfield(myAddress)
        debug_print("Bitfield Länge: %d", len(bitfield))
        payload += bitfield

        try:
            pubSigningKey, pubEncryptionKey = self._getKeysForAddress(myAddress)[2:]
            debug_print("Public Keys erhalten - Sign: %d bytes, Enc: %d bytes", 
                      len(pubSigningKey), len(pubEncryptionKey))
        except ValueError:
            debug_print("Fehler beim Holen der Schlüssel für Adresse")
            return
        except Exception as e:
            debug_print("Fehler beim Holen der Schlüssel: %s", e)
            return

        # Python 3: Ensure keys are bytes
        if isinstance(pubSigningKey, str):
            debug_print("Konvertiere pubSigningKey string zu bytes")
            pubSigningKey = pubSigningKey.encode('latin-1')
        if isinstance(pubEncryptionKey, str):
            debug_print("Konvertiere pubEncryptionKey string zu bytes")
            pubEncryptionKey = pubEncryptionKey.encode('latin-1')
        
        payload += pubSigningKey + pubEncryptionKey
        debug_print("Gesamt Payload Länge vor PoW: %d", len(payload))

        # Do the POW for this pubkey message
        debug_print("Starte PoW für V2 pubkey von %s...", myAddress[:20])
        payload = self._doPOWDefaults(payload, TTL, log_prefix='(For V2 pubkey message)')
        
        if payload is None:
            debug_print("PoW fehlgeschlagen für V2 pubkey")
            return

        inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
        objectType = 1
        state.Inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime, b''
        )
        debug_print("Inventory Hash: %s", hexlify(inventoryHash))

        debug_print('Sende inv mit hash: %s...', hexlify(inventoryHash)[:32])
        invQueue.put((streamNumber, inventoryHash))
        queues.UISignalQueue.put(('updateStatusBar', 'V2 Pubkey sent'))
        
        try:
            config.set(myAddress, 'lastpubkeysendtime', str(int(time.time())))
            config.save()
            debug_print("Updated lastpubkeysendtime für %s...", myAddress[:20])
        except configparser.NoSectionError:
            debug_print("Adresse Section nicht gefunden für %s...", myAddress[:20])
        except Exception as e:
            debug_print("Fehler beim Aktualisieren der Config: %s", e)

    def sendOutOrStoreMyV3Pubkey(self, adressHash):
        """
        If this isn't a chan address, this function assembles the pubkey data, 
        does the necessary POW and sends it out.
        """
        debug_print("sendOutOrStoreMyV3Pubkey für hash: %s...", 
                  hexlify(adressHash)[:16] if isinstance(adressHash, bytes) else adressHash)
        
        # Python 3: Ensure addressHash is bytes
        if isinstance(adressHash, str):
            try:
                debug_print("Konvertiere addressHash string zu bytes")
                adressHash = unhexlify(adressHash)
            except Exception as e:
                debug_print("Kann addressHash nicht von string konvertieren: %s", e)
                return
        
        try:
            myAddress = shared.myAddressesByHash[adressHash]
            debug_print("Adresse gefunden: %s", myAddress)
        except KeyError:
            debug_print("Kann %s nicht in myAddressByHash finden", 
                      hexlify(adressHash) if isinstance(adressHash, bytes) else adressHash)
            return
            
        if config.safeGetBoolean(myAddress, 'chan'):
            debug_print('Dies ist eine chan Adresse. Sende kein pubkey.')
            return
            
        _, addressVersionNumber, streamNumber, addressHash = decodeAddress(myAddress)
        debug_print("Adresse Version: %d, Stream: %d", addressVersionNumber, streamNumber)

        TTL = int(28 * 24 * 60 * 60 + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)
        debug_print("TTL: %d, embeddedTime: %d", TTL, embeddedTime)

        payload = pack('>Q', embeddedTime)
        payload += b'\x00\x00\x00\x01'
        payload += encodeVarint(addressVersionNumber)
        payload += encodeVarint(streamNumber)
        bitfield = protocol.getBitfield(myAddress)
        payload += bitfield
        debug_print("Payload nach Bitfield: %d bytes", len(payload))

        try:
            privSigningKeyHex, _, pubSigningKey, pubEncryptionKey = self._getKeysForAddress(myAddress)
            debug_print("Schlüssel erhalten - PrivSign Länge: %d", len(privSigningKeyHex))
        except ValueError:
            debug_print("ValueError bei _getKeysForAddress")
            return
        except Exception as e:
            debug_print('Fehler in sendOutOrStoreMyV3Pubkey: %s', e)
            traceback.print_exc()
            return

        # Python 3: Ensure keys are bytes
        if isinstance(pubSigningKey, str):
            debug_print("Konvertiere pubSigningKey string zu bytes")
            pubSigningKey = pubSigningKey.encode('latin-1')
        if isinstance(pubEncryptionKey, str):
            debug_print("Konvertiere pubEncryptionKey string zu bytes")
            pubEncryptionKey = pubEncryptionKey.encode('latin-1')
        
        payload += pubSigningKey + pubEncryptionKey
        
        try:
            noncetrials = config.getint(myAddress, 'noncetrialsperbyte')
            payloadlength = config.getint(myAddress, 'payloadlengthextrabytes')
            debug_print("PoW Parameter aus Config: noncetrials=%d, payloadlength=%d", 
                      noncetrials, payloadlength)
            payload += encodeVarint(noncetrials)
            payload += encodeVarint(payloadlength)
        except Exception as e:
            debug_print("Fehler beim Lesen von PoW Parametern: %s", e)
            payload += encodeVarint(defaults.networkDefaultProofOfWorkNonceTrialsPerByte)
            payload += encodeVarint(defaults.networkDefaultPayloadLengthExtraBytes)

        debug_print("Payload vor Signatur: %d bytes", len(payload))

        # Python 3: privSigningKeyHex is bytes from hexlify
        debug_print("Erstelle Signatur mit digestAlg: %s", self.digestAlg)
        signature = highlevelcrypto.sign(payload, privSigningKeyHex, self.digestAlg)
        debug_print("Signatur Länge: %d", len(signature))
        payload += encodeVarint(len(signature))
        payload += signature
        debug_print("Gesamt Payload vor PoW: %d bytes", len(payload))

        payload = self._doPOWDefaults(payload, TTL, log_prefix='(For pubkey message)')
        
        if payload is None:
            debug_print("PoW fehlgeschlagen für V3 pubkey")
            return

        inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
        objectType = 1
        state.Inventory[inventoryHash] = (objectType, streamNumber, payload, embeddedTime, b'')
        debug_print("Inventory Hash: %s", hexlify(inventoryHash))

        debug_print('Sende inv mit hash: %s', hexlify(inventoryHash))
        invQueue.put((streamNumber, inventoryHash))
        queues.UISignalQueue.put(('updateStatusBar', ''))
        
        try:
            config.set(myAddress, 'lastpubkeysendtime', str(int(time.time())))
            config.save()
            debug_print("Config gespeichert")
        except configparser.NoSectionError:
            debug_print("Adresse Section nicht gefunden")
        except Exception as e:
            debug_print("config.set nicht erfolgreich: %s", e)

    def sendOutOrStoreMyV4Pubkey(self, myAddress):
        debug_print("sendOutOrStoreMyV4Pubkey für Adresse: %s", myAddress)
        if not config.has_section(myAddress):
            debug_print("Keine Config Section für Adresse")
            return
        if config.safeGetBoolean(myAddress, 'chan'):
            debug_print('Dies ist eine chan Adresse. Sende kein pubkey.')
            return
            
        _, addressVersionNumber, streamNumber, addressHash = decodeAddress(myAddress)
        debug_print("Adresse Version: %d, Stream: %d", addressVersionNumber, streamNumber)

        TTL = int(28 * 24 * 60 * 60 + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)
        payload = pack('>Q', embeddedTime)
        payload += b'\x00\x00\x00\x01'
        payload += encodeVarint(addressVersionNumber)
        payload += encodeVarint(streamNumber)
        dataToEncrypt = protocol.getBitfield(myAddress)
        debug_print("Payload Basis: %d bytes", len(payload))
        debug_print("DataToEncrypt nach Bitfield: %d bytes", len(dataToEncrypt))

        try:
            privSigningKeyHex, _, pubSigningKey, pubEncryptionKey = self._getKeysForAddress(myAddress)
            debug_print("Schlüssel erhalten")
        except ValueError:
            debug_print("ValueError bei _getKeysForAddress")
            return
        except Exception:
            debug_print('Fehler in sendOutOrStoreMyV4Pubkey')
            traceback.print_exc()
            return

        dataToEncrypt += pubSigningKey + pubEncryptionKey
        dataToEncrypt += encodeVarint(config.getint(myAddress, 'noncetrialsperbyte'))
        dataToEncrypt += encodeVarint(config.getint(myAddress, 'payloadlengthextrabytes'))
        debug_print("DataToEncrypt nach PoW Parametern: %d bytes", len(dataToEncrypt))

        doubleHashOfAddressData = highlevelcrypto.double_sha512(
            encodeVarint(addressVersionNumber) + encodeVarint(streamNumber) + addressHash
        )
        debug_print("doubleHashOfAddressData berechnet, Länge: %d", len(doubleHashOfAddressData))
        payload += doubleHashOfAddressData[32:]  # the tag
        debug_print("Tag hinzugefügt: %s...", hexlify(doubleHashOfAddressData[32:])[:20])
        
        debug_print("Erstelle Signatur für Payload + dataToEncrypt")
        signature = highlevelcrypto.sign(payload + dataToEncrypt, privSigningKeyHex, self.digestAlg)
        dataToEncrypt += encodeVarint(len(signature))
        dataToEncrypt += signature
        debug_print("DataToEncrypt nach Signatur: %d bytes", len(dataToEncrypt))

        privEncryptionKey = doubleHashOfAddressData[:32]
        debug_print("PrivEncryptionKey aus doubleHash: %d bytes", len(privEncryptionKey))
        pubEncryptionKey = highlevelcrypto.pointMult(privEncryptionKey)
        debug_print("PubEncryptionKey berechnet: %d bytes", len(pubEncryptionKey))
        
        debug_print("Verschlüssele dataToEncrypt")
        encryptedData = highlevelcrypto.encrypt(dataToEncrypt, hexlify(pubEncryptionKey))
        payload += encryptedData
        debug_print("Payload nach Verschlüsselung: %d bytes", len(payload))

        payload = self._doPOWDefaults(payload, TTL, log_prefix='(For pubkey message)')
        if payload is None:
            debug_print("PoW fehlgeschlagen für V4 pubkey")
            return

        inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
        objectType = 1
        state.Inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime, doubleHashOfAddressData[32:]
        )
        debug_print("Inventory Hash: %s", hexlify(inventoryHash))

        debug_print('Sende inv mit hash: %s', hexlify(inventoryHash))
        invQueue.put((streamNumber, inventoryHash))
        queues.UISignalQueue.put(('updateStatusBar', ''))
        
        try:
            config.set(myAddress, 'lastpubkeysendtime', str(int(time.time())))
            config.save()
            debug_print("Config gespeichert")
        except Exception as err:
            debug_print("Fehler beim Hinzufügen von lastpubkeysendtime: %s", err)

    def sendOnionPeerObj(self, peer=None):
        """Send onionpeer object representing peer"""
        debug_print("sendOnionPeerObj aufgerufen")
        if not peer:
            debug_print("Kein spezifischer peer, suche eigene onion Adressen")
            for peer in state.ownAddresses:
                if peer.host.endswith('.onion'):
                    debug_print("Onion peer gefunden: %s:%d", peer.host, peer.port)
                    break
            else:
                debug_print("Keine onion Adresse gefunden")
                return
                
        TTL = int(7 * 24 * 60 * 60 + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)
        streamNumber = 1
        objectType = protocol.OBJECT_ONIONPEER
        objectPayload = encodeVarint(peer.port) + protocol.encodeHost(peer.host)
        tag = highlevelcrypto.calculateInventoryHash(objectPayload)
        debug_print("OnionPeer Object: Host=%s, Port=%d, Tag=%s...", 
                  peer.host, peer.port, hexlify(tag)[:20])

        if state.Inventory.by_type_and_tag(objectType, tag):
            debug_print("OnionPeer object bereits vorhanden")
            return

        payload = pack('>Q', embeddedTime)
        payload += pack('>I', objectType)
        payload += encodeVarint(2 if len(peer.host) == 22 else 3)
        payload += encodeVarint(streamNumber)
        payload += objectPayload
        debug_print("OnionPeer payload vor PoW: %d bytes", len(payload))

        payload = self._doPOWDefaults(payload, TTL, log_prefix='(For onionpeer object)')
        
        if payload is None:
            debug_print("PoW fehlgeschlagen für onionpeer object")
            return

        inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
        debug_print("Inventory Hash: %s", hexlify(inventoryHash))
        
        # Python 3: Use memoryview instead of buffer
        state.Inventory[inventoryHash] = (
            objectType, streamNumber, memoryview(payload), embeddedTime, memoryview(tag)
        )
        
        debug_print('Sende inv (innerhalb sendOnionPeerObj) für object: %s', hexlify(inventoryHash))
        invQueue.put((streamNumber, inventoryHash))

    def sendBroadcast(self):
        """Send a broadcast-type object"""
        debug_print("=" * 60)
        debug_print("SENDBROADCAST - Verarbeite gequeued broadcasts")
        debug_print("=" * 60)
        
        # Reset just in case
        try:
            reset_count = sqlExecute(
                '''UPDATE sent SET status='broadcastqueued' '''
                ''' WHERE status = 'doingbroadcastpow' AND folder = 'sent' ''')
            if reset_count > 0:
                debug_print("Reset %d broadcasts von doingbroadcastpow zu broadcastqueued", reset_count)
        except Exception as e:
            debug_print("Fehler beim Reset broadcast status: %s", e)
        
        # Get queued broadcasts with safe extraction
        try:
            queryreturn = sqlQuery(
                '''SELECT fromaddress, subject, message, ackdata, ttl, encodingtype '''
                '''FROM sent WHERE status=? and folder='sent' ''', 
                'broadcastqueued')
            debug_print("Gefundene broadcasts zum Senden: %d", len(queryreturn))
        except Exception as e:
            debug_print("Fehler beim Query broadcasts: %s", e)
            return
        
        if not queryreturn:
            debug_print("Keine broadcasts zu verarbeiten")
            return
        
        for i, row in enumerate(queryreturn):
            debug_print("--- Verarbeite broadcast %d/%d ---", i+1, len(queryreturn))
            
            try:
                if len(row) < 6:
                    debug_print("Broadcast row %d hat nur %d columns", i, len(row))
                    continue
                
                # Use safe extraction
                fromaddress = self._safe_extract(row[0])
                subject = self._safe_extract(row[1])
                body = self._safe_extract(row[2])
                ackdata_raw = row[3]
                TTL = self._safe_extract(row[4], to_int=True)
                encoding = self._safe_extract(row[5], to_int=True)
                
                debug_print("  Von: %s...", fromaddress[:30] if fromaddress else "None")
                debug_print("  Betreff: %s...", subject[:30] if subject else "None")
                debug_print("  Nachrichtenlänge: %d", len(body) if body else 0)
                debug_print("  TTL: %d, Encoding: %d", TTL, encoding)
                
                # Convert ackdata to bytes
                if isinstance(ackdata_raw, str):
                    ackdata = ackdata_raw.encode('latin-1')
                    debug_print("  Ackdata string zu bytes konvertiert")
                elif isinstance(ackdata_raw, bytes):
                    ackdata = ackdata_raw
                    debug_print("  Ackdata ist bereits bytes")
                else:
                    ackdata = bytes(ackdata_raw) if ackdata_raw else os.urandom(32)
                    debug_print("  Ackdata erzeugt/konvertiert")
                
                debug_print("  Ackdata: %s...", hexlify(ackdata)[:16] if ackdata else "None")
                
                # Decode address
                try:
                    _, addressVersionNumber, streamNumber, ripe = decodeAddress(fromaddress)
                    debug_print("  Adresse Version: %d, Stream: %d", addressVersionNumber, streamNumber)
                except Exception as e:
                    debug_print("Fehler beim Decodieren der Adresse: %s", e)
                    continue
                    
                if addressVersionNumber <= 1:
                    debug_print('sendBroadcast versteht Adresse Version %d nicht', addressVersionNumber)
                    continue

                try:
                    privSigningKeyHex, _, pubSigningKey, pubEncryptionKey = self._getKeysForAddress(fromaddress)
                    debug_print("  Schlüssel erfolgreich erhalten")
                except ValueError:
                    debug_print("FEHLER: Sender Adresse nicht in keys.dat gefunden")
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata,
                            tr._translate("MainWindow", "Error! Could not find sender address in keys.dat"))
                    ))
                    continue
                except Exception as err:
                    debug_print('Fehler beim Holen der Schlüssel: %s', err)
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata, tr._translate("MainWindow", "Error, can't send."))
                    ))
                    continue

                # Status auf 'doingbroadcastpow' setzen
                try:
                    rowcount = sqlExecute(
                        '''UPDATE sent SET status='doingbroadcastpow' '''
                        '''WHERE ackdata=? AND status='broadcastqueued' AND folder='sent' ''',
                        sqlite3.Binary(ackdata))
                    
                    if rowcount < 1:
                        # Versuche als Text
                        sqlExecute(
                            '''UPDATE sent SET status='doingbroadcastpow' '''
                            '''WHERE ackdata=CAST(? AS TEXT) AND status='broadcastqueued' AND folder='sent' ''',
                            ackdata if isinstance(ackdata, str) else ackdata.decode('utf-8', 'replace'))
                    debug_print("  Status auf doingbroadcastpow aktualisiert")
                except Exception as e:
                    debug_print("Fehler beim Aktualisieren des Status: %s", e)
                    continue

                # TTL validieren
                if not isinstance(TTL, (int, float)):
                    debug_print("WARNUNG: TTL ist keine Zahl: %s, verwende Default", TTL)
                    TTL = 3600
                    
                if TTL > 28 * 24 * 60 * 60:
                    TTL = 28 * 24 * 60 * 60
                if TTL < 60 * 60:
                    TTL = 60 * 60
                    
                # Zufällige Variation hinzufügen
                TTL = int(TTL + helper_random.randomrandrange(-300, 300))
                embeddedTime = int(time.time() + TTL)
                
                debug_print("  Finale TTL: %d, embeddedTime: %d", TTL, embeddedTime)
                
                # Payload zusammenbauen
                payload = pack('>Q', embeddedTime)
                payload += b'\x00\x00\x00\x03'  # object type: broadcast

                if addressVersionNumber <= 3:
                    payload += encodeVarint(4)  # broadcast version
                    debug_print("  Broadcast Version 4 (für Adresse Version <= 3)")
                else:
                    payload += encodeVarint(5)  # broadcast version
                    debug_print("  Broadcast Version 5 (für Adresse Version >= 4)")

                payload += encodeVarint(streamNumber)
                
                if addressVersionNumber >= 4:
                    doubleHashOfAddressData = highlevelcrypto.double_sha512(
                        encodeVarint(addressVersionNumber) + encodeVarint(streamNumber) + ripe
                    )
                    tag = doubleHashOfAddressData[32:]
                    payload += tag
                    debug_print("  Tag hinzugefügt für V4 Adresse")
                else:
                    tag = b''
                    debug_print("  Kein Tag für V3 oder früher")

                # Daten, die verschlüsselt werden sollen
                dataToEncrypt = encodeVarint(addressVersionNumber)
                dataToEncrypt += encodeVarint(streamNumber)
                dataToEncrypt += protocol.getBitfield(fromaddress)
                dataToEncrypt += pubSigningKey + pubEncryptionKey
                debug_print("  DataToEncrypt Basis: %d bytes", len(dataToEncrypt))
                
                if addressVersionNumber >= 3:
                    try:
                        noncetrials = config.getint(fromaddress, 'noncetrialsperbyte')
                        payloadlength = config.getint(fromaddress, 'payloadlengthextrabytes')
                        dataToEncrypt += encodeVarint(noncetrials)
                        dataToEncrypt += encodeVarint(payloadlength)
                        debug_print("  PoW Parameter hinzugefügt: %d, %d", noncetrials, payloadlength)
                    except Exception as e:
                        debug_print("  Konnte noncetrials/payloadlength für %s nicht lesen: %s", 
                                  fromaddress, e)
                        # Verwende Default-Werte
                        dataToEncrypt += encodeVarint(defaults.networkDefaultProofOfWorkNonceTrialsPerByte)
                        dataToEncrypt += encodeVarint(defaults.networkDefaultPayloadLengthExtraBytes)
                        debug_print("  Default PoW Parameter verwendet")
                
                # Encoding hinzufügen
                if not isinstance(encoding, int):
                    try:
                        encoding = int(encoding)
                    except:
                        encoding = 2  # Default
                        debug_print("  Encoding auf Default (2) gesetzt")
                        
                dataToEncrypt += encodeVarint(encoding)
                debug_print("  Encoding hinzugefügt: %d", encoding)
                
                # Nachricht encodieren
                try:
                    debug_print("  Encodiere Nachricht mit Encoding %d", encoding)
                    encodedMessage = helper_msgcoding.MsgEncode({"subject": subject, "body": body}, encoding)
                    dataToEncrypt += encodeVarint(encodedMessage.length)
                    dataToEncrypt += encodedMessage.data
                    debug_print("  Nachricht encodiert, Länge: %d", encodedMessage.length)
                except Exception as e:
                    debug_print("Fehler beim Encodieren der Nachricht: %s", e)
                    continue
                    
                dataToSign = payload + dataToEncrypt
                debug_print("  DataToSign Länge: %d bytes", len(dataToSign))

                # Signatur
                try:
                    debug_print("  Erstelle Signatur...")
                    signature = highlevelcrypto.sign(dataToSign, privSigningKeyHex, self.digestAlg)
                    dataToEncrypt += encodeVarint(len(signature))
                    dataToEncrypt += signature
                    debug_print("  Signatur hinzugefügt, Länge: %d", len(signature))
                except Exception as e:
                    debug_print("Fehler beim Signieren des broadcasts: %s", e)
                    continue

                # Verschlüsselung
                if addressVersionNumber <= 3:
                    privEncryptionKey = hashlib.sha512(
                        encodeVarint(addressVersionNumber) + encodeVarint(streamNumber) + ripe
                    ).digest()[:32]
                    debug_print("  PrivEncryptionKey für V3 berechnet")
                else:
                    privEncryptionKey = doubleHashOfAddressData[:32]
                    debug_print("  PrivEncryptionKey für V4 aus doubleHash")

                try:
                    pubEncryptionKey = highlevelcrypto.pointMult(privEncryptionKey)
                    debug_print("  Verschlüssele dataToEncrypt...")
                    payload += highlevelcrypto.encrypt(dataToEncrypt, hexlify(pubEncryptionKey))
                    debug_print("  Verschlüsselung erfolgreich")
                except Exception as e:
                    debug_print("Fehler beim Verschlüsseln des broadcasts: %s", e)
                    continue

                # UI aktualisieren
                debug_print("  Aktualisiere UI Status...")
                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata,
                        tr._translate("MainWindow", "Doing work necessary to send broadcast..."))
                ))
                
                # Proof of Work durchführen
                try:
                    debug_print("  Starte Proof of Work...")
                    payload = self._doPOWDefaults(payload, TTL, log_prefix='(For broadcast message)')
                    if payload is None:
                        debug_print("  PoW fehlgeschlagen für broadcast")
                        continue
                    debug_print("  PoW erfolgreich, finale Payload Länge: %d", len(payload))
                except Exception as e:
                    debug_print("  Fehler bei PoW für broadcast: %s", e)
                    continue

                # Größenprüfung
                if len(payload) > 2 ** 18:
                    debug_print('FEHLER: Broadcast object zu groß zum Senden: %d bytes', len(payload))
                    continue

                # Inventory-Hash berechnen
                try:
                    inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
                    objectType = 3
                    state.Inventory[inventoryHash] = (objectType, streamNumber, payload, embeddedTime, tag)
                    debug_print("  Inventory Hash berechnet: %s", hexlify(inventoryHash)[:32])
                    
                    debug_print('  Broadcast ready: %s...', hexlify(inventoryHash)[:32])
                    invQueue.put((streamNumber, inventoryHash))
                except Exception as e:
                    debug_print("Fehler beim Erstellen des Inventars: %s", e)
                    continue

                # UI aktualisieren
                queues.UISignalQueue.put((
                    'updateSentItemStatusByAckdata', (
                        ackdata,
                        tr._translate("MainWindow", "Broadcast sent on {0}").format(l10n.formatTimestamp()))
                ))

                # Datenbank aktualisieren
                try:
                    sqlExecute(
                        '''UPDATE sent SET msgid=?, status=?, lastactiontime=? WHERE ackdata=? AND folder='sent' ''',
                        sqlite3.Binary(inventoryHash), 'broadcastsent', int(time.time()), sqlite3.Binary(ackdata)
                    )
                    debug_print("  Broadcast %d erfolgreich gesendet", i+1)
                except Exception as e:
                    debug_print("Fehler beim Aktualisieren der Datenbank: %s", e)
                    
            except Exception as e:
                debug_print("Unerwarteter Fehler beim Verarbeiten von broadcast row %d: %s", i, e)
                traceback.print_exc()
                continue
        
        debug_print("Broadcast Verarbeitung abgeschlossen")
    def sendMsg(self):
        """Send a message-type object (assemble the object, perform PoW and put it to the inv announcement queue)"""
        # pylint: disable=too-many-nested-blocks
        print("\n" + "=" * 80)
        print("🚀 SENDMSG START - Verarbeite gequeued Nachrichten")
        print("=" * 80)
        
        debug_print("============================================================")
        debug_print("SENDMSG - Verarbeite gequeued Nachrichten")
        debug_print("============================================================")
        
        print("\n📋 PHASE 1: Reset doing* Nachrichten")
        # Reset just in case
        try:
            print("  SQL: UPDATE sent SET status='msgqueued' WHERE status IN ('doingpubkeypow', 'doingmsgpow') AND folder='sent'")
            reset_count = sqlExecute(
                '''UPDATE sent SET status='msgqueued' '''
                ''' WHERE status IN ('doingpubkeypow', 'doingmsgpow') '''
                ''' AND folder='sent' ''')
            print(f"  ✅ Reset {reset_count} Nachrichten von doing* zu msgqueued")
            debug_print("Reset %d Nachrichten von doing* zu msgqueued", reset_count)
        except Exception as e:
            print(f"  ❌ Fehler beim Reset Status: {e}")
            debug_print("Fehler beim Reset Status: %s", e)
        
        print("\n📋 PHASE 2: Status Übersicht in sent Tabelle")
        # DEBUG: Überprüfe alle Status in der Tabelle
        try:
            print("  SQL: SELECT status, COUNT(*) as count FROM sent WHERE folder='sent' GROUP BY status")
            status_overview = sqlQuery(
                '''SELECT status, COUNT(*) as count FROM sent WHERE folder='sent' GROUP BY status''')
            print(f"  Query Ergebnisse: {len(status_overview)} Status-Typen")
            
            debug_print("--- DEBUG: Status Übersicht in sent Tabelle ---")
            for j, status_row in enumerate(status_overview):
                if len(status_row) >= 2:
                    print(f"  Status '{status_row[0]}': {status_row[1]} Nachrichten")
                    debug_print("  Status '%s': %d Nachrichten", status_row[0], status_row[1])
                else:
                    print(f"  ⚠️  Ungültige Status-Zeile {j}: {status_row}")
        except Exception as e:
            print(f"  ❌ Fehler bei Status Überprüfung: {e}")
            debug_print("Fehler bei Status Überprüfung: %s", e)
        
        print("\n📋 PHASE 3: Haupt-Query für Nachrichten")
        print("  SQL: SELECT msgid, toaddress, fromaddress, subject, message, ackdata, status, ttl, retrynumber, encodingtype")
        print("       FROM sent WHERE (status='msgqueued' OR status='forcepow' OR status='awaitingpubkey')")
        print("       and folder='sent' ORDER BY lastactiontime ASC LIMIT 5")
        
        try:
            queryreturn = sqlQuery(
                '''SELECT msgid, toaddress, fromaddress, subject, message, '''
                ''' ackdata, status, ttl, retrynumber, encodingtype FROM '''
                ''' sent WHERE (status='msgqueued' OR status='forcepow' OR status='awaitingpubkey') '''
                ''' and folder='sent' ORDER BY lastactiontime ASC LIMIT 5''')
            
            print(f"  ✅ Query erfolgreich: {len(queryreturn)} Nachrichten gefunden (limit 5)")
            debug_print("Gefundene Nachrichten zum Verarbeiten: %d (limit 5)", len(queryreturn))
            
            # Debug: Zeige was zurückgegeben wurde
            if queryreturn:
                print(f"  Erste Zeile hat {len(queryreturn[0])} Spalten")
                for i, field in enumerate(queryreturn[0]):
                    field_type = type(field)
                    if isinstance(field, bytes):
                        print(f"    Spalte {i}: bytes, Länge={len(field)}, Hex: {hexlify(field)[:32]}...")
                    else:
                        print(f"    Spalte {i}: {field_type}, Wert: {str(field)[:50] if field else 'None'}")
            
        except Exception as e:
            print(f"  ❌ FEHLER bei Haupt-Query: {e}")
            import traceback
            traceback.print_exc()
            debug_print("Fehler bei Haupt-Query: %s", e)
            print("  Keine Nachrichten zu verarbeiten")
            return
        
        if not queryreturn:
            print("  ℹ️  Keine Nachrichten zu verarbeiten")
            debug_print("Keine Nachrichten zu verarbeiten")
            return
        
        print(f"\n📋 PHASE 4: Verarbeite {len(queryreturn)} Nachricht(en)")
        # while we have a msg that needs some work
        for i, row in enumerate(queryreturn):
            print(f"\n--- Verarbeite Nachricht {i+1}/{len(queryreturn)} ---")
            debug_print("--- Verarbeite Nachricht %d/%d ---", i+1, len(queryreturn))

            try:
                print(f"  Zeile Länge: {len(row)} Spalten")
                
                # Sicherstellen, dass die Zeile genug Spalten hat
                if len(row) < 10:
                    print(f"  ❌ FEHLER: Zeile hat nur {len(row)} Spalten (erwartet: 10)")
                    print(f"  Zeileninhalt: {row}")
                    debug_print("FEHLER: Zeile hat nur %d Spalten", len(row))
                    continue
                
                print("  Extrahiere Rohdaten...")
                msgid = row[0]
                toaddress = row[1]
                fromaddress = row[2]
                subject = row[3]
                message = row[4]
                ackdata_raw = row[5]
                status = row[6]
                TTL = row[7]
                retryNumber = row[8]
                encoding = row[9]
                
                print(f"  Raw-Daten:")
                print(f"    msgid Typ: {type(msgid)}")
                print(f"    toaddress: {str(toaddress)[:50] if toaddress else 'None'}...")
                print(f"    fromaddress: {str(fromaddress)[:50] if fromaddress else 'None'}...")
                print(f"    status: {status}")
                
                debug_print("  Raw-Daten: status=%s, toaddress=%s...", 
                          status, str(toaddress)[:30] if toaddress else "None")
                
                print("\n  Konvertiere Daten mit _safe_extract...")
                # Safe conversion - WICHTIG: msgid muss auch konvertiert werden!
                msgid = self._safe_extract(msgid, to_int=False, is_msgid=True)  # msgid ist ein Hash, keine Zahl!
                toaddress = self._safe_extract(toaddress)
                fromaddress = self._safe_extract(fromaddress)
                subject = self._safe_extract(subject)
                message = self._safe_extract(message)
                status = self._safe_extract(status)
                TTL = int(TTL) if TTL is not None else 0
                retryNumber = int(retryNumber) if retryNumber is not None else 0
                encoding = int(encoding) if encoding is not None else 0
                
                print(f"  Nach Konvertierung:")
                print(f"    msgid Typ: {type(msgid)}, Länge: {len(msgid) if isinstance(msgid, bytes) else 'N/A'}")
                if isinstance(msgid, bytes):
                    print(f"    msgid Hex: {hexlify(msgid)[:32]}...")
                print(f"    toaddress: {toaddress[:50] if toaddress else 'None'}...")
                print(f"    status: {status}")
                print(f"    TTL: {TTL}, Retry: {retryNumber}, Encoding: {encoding}")
                
                debug_print("  Nach Konvertierung: msgid=%s, status=%s, toaddress=%s...", 
                          msgid, status, toaddress[:30] if toaddress else "None")
                
                print("\n  Verarbeite ackdata...")
                if ackdata_raw is None:
                    ackdata = os.urandom(32)
                    print(f"    ⚠️  ackdata war None, generiere neuen: {hexlify(ackdata)[:32]}...")
                    debug_print("  WARNUNG: ackdata war None, generiere neuen")
                elif isinstance(ackdata_raw, str):
                    ackdata = ackdata_raw.encode('latin-1')
                    print(f"    ackdata war string, konvertiert zu bytes: {hexlify(ackdata)[:32]}...")
                elif isinstance(ackdata_raw, bytes):
                    ackdata = ackdata_raw
                    print(f"    ackdata ist bytes: {hexlify(ackdata)[:32]}...")
                else:
                    ackdata = bytes(ackdata_raw) if ackdata_raw else os.urandom(32)
                    print(f"    ackdata konvertiert zu bytes: {hexlify(ackdata)[:32]}...")
                
                print(f"\n  Nachrichten-Details:")
                print(f"    An: {toaddress[:50] if toaddress else 'None'}...")
                print(f"    Von: {fromaddress[:50] if fromaddress else 'None'}...")
                print(f"    Betreff: {subject[:30] if subject else 'None'}...")
                print(f"    Status: {status}, TTL: {TTL}, Retry: {retryNumber}")
                
                debug_print("  An: %s...", toaddress[:50] if toaddress else "None")
                debug_print("  Von: %s...", fromaddress[:50] if fromaddress else "None")
                debug_print("  Betreff: %s...", subject[:30] if subject else "None")
                debug_print("  Status: %s, TTL: %d, Retry: %d", status, TTL, retryNumber)
                
                # Check if addresses are valid
                if not toaddress or not fromaddress:
                    print(f"  ❌ FEHLER: Ungültige Adresse")
                    debug_print("  FEHLER: Ungültige Adresse")
                    continue
                
                print("\n  Dekodiere Adressen...")
                try:
                    # toStatus
                    _, toAddressVersionNumber, toStreamNumber, toRipe = \
                        decodeAddress(toaddress)
                    # fromStatus, , ,fromRipe
                    _, fromAddressVersionNumber, fromStreamNumber, _ = \
                        decodeAddress(fromaddress)
                        
                    print(f"  ✅ Adressen erfolgreich dekodiert:")
                    print(f"    An Version: {toAddressVersionNumber}, Stream: {toStreamNumber}")
                    print(f"    Von Version: {fromAddressVersionNumber}, Stream: {fromStreamNumber}")
                    print(f"    toRipe Länge: {len(toRipe)} bytes")
                    print(f"    toRipe Hex: {hexlify(toRipe)[:32]}...")
                    
                    debug_print("  An Version: %d, Stream: %d", toAddressVersionNumber, toStreamNumber)
                    debug_print("  Von Version: %d, Stream: %d", fromAddressVersionNumber, fromStreamNumber)
                except Exception as e:
                    print(f"  ❌ FEHLER beim Decodieren der Adressen: {e}")
                    debug_print("  FEHLER beim Decodieren der Adressen: %s", e)
                    continue

                print(f"\n📋 PHASE 5: Prüfe Status und Pubkey ({status})")
                
                # We may or may not already have the pubkey
                # for this toAddress. Let's check.
                if status == 'forcepow':
                    # if the status of this msg is 'forcepow'
                    # then clearly we have the pubkey already
                    # because the user could not have overridden the message
                    # about the POW being too difficult without knowing
                    # the required difficulty.
                    print("  Status ist 'forcepow' - fahre fort")
                    debug_print("  Status ist 'forcepow' - fahre fort")
                    pass
                elif status == 'doingmsgpow':
                    # We wouldn't have set the status to doingmsgpow
                    # if we didn't already have the pubkey so let's assume
                    # that we have it.
                    print("  Status ist 'doingmsgpow' - bereits in Arbeit")
                    debug_print("  Status ist 'doingmsgpow' - bereits in Arbeit")
                    pass
                # If we are sending a message to ourselves or a chan
                # then we won't need an entry in the pubkeys table;
                # we can calculate the needed pubkey using the private keys
                # in our keys.dat file.
                elif config.has_section(toaddress):
                    print(f"  Sende an sich selbst/chan: {toaddress}")
                    debug_print("  Sende an sich selbst/chan: %s", toaddress)
                    try:
                        print(f"  Setze Status auf 'doingmsgpow'...")
                        update_result = sqlExecute(
                            '''UPDATE sent SET status='doingmsgpow' '''
                            ''' WHERE toaddress=? AND status='msgqueued' AND folder='sent' ''',
                            toaddress)
                        print(f"  Update Result: {update_result} Zeilen aktualisiert")
                        debug_print("  Update Result: %d Zeilen aktualisiert", update_result)
                        if update_result <= 0:
                            print(f"  ⚠️  Konnte Status nicht aktualisieren, setze manuell")
                            debug_print("  Konnte Status nicht aktualisieren")
                            # Setze Status manuell für weitere Verarbeitung
                            status = 'doingmsgpow'
                        else:
                            status = 'doingmsgpow'
                        print(f"  ✅ Status auf 'doingmsgpow' aktualisiert")
                        debug_print("  Status auf 'doingmsgpow' aktualisiert")
                    except Exception as e:
                        print(f"  ❌ Fehler beim Aktualisieren: {e}")
                        debug_print("  Fehler beim Aktualisieren: %s", e)
                        status = 'doingmsgpow'  # Fortfahren trotz Fehler
                elif status == 'msgqueued':
                    print("  Status ist 'msgqueued' - prüfe auf existierenden pubkey...")
                    debug_print("  Prüfe auf existierenden pubkey...")
                    
                    queryreturn_pubkey = sqlQuery(
                        '''SELECT address FROM pubkeys WHERE address=?''',
                        toaddress)
                    
                    # If we have the needed pubkey in the pubkey table already,
                    if queryreturn_pubkey:
                        print(f"  ✅ Pubkey gefunden in Datenbank")
                        debug_print("  Pubkey gefunden in Datenbank")
                        # set the status of this msg to doingmsgpow
                        try:
                            print(f"  Setze Status auf 'doingmsgpow'...")
                            update_rows = sqlExecute(
                                '''UPDATE sent SET status='doingmsgpow' '''
                                ''' WHERE toaddress=? AND status='msgqueued' AND folder='sent' ''',
                                toaddress)
                            print(f"  Update Result: {update_rows} Zeilen aktualisiert")
                            debug_print("  Update Result: %d Zeilen aktualisiert", update_rows)
                            if update_rows <= 0:
                                print(f"  ⚠️  Konnte Status nicht aktualisieren, setze manuell")
                                debug_print("  Konnte Status nicht aktualisieren, setze manuell")
                                status = 'doingmsgpow'
                            else:
                                status = 'doingmsgpow'
                            print(f"  ✅ Status auf 'doingmsgpow' aktualisiert")
                            debug_print("  Status auf 'doingmsgpow' aktualisiert")
                            # mark the pubkey as 'usedpersonally' so that
                            # we don't delete it later.
                            sqlExecute(
                                '''UPDATE pubkeys SET usedpersonally='yes' '''
                                ''' WHERE address=?''',
                                toaddress)
                            print(f"  ✅ Pubkey als 'usedpersonally' markiert")
                        except Exception as e:
                            print(f"  ❌ Fehler beim Aktualisieren: {e}")
                            debug_print("  Fehler beim Aktualisieren: %s", e)
                            status = 'doingmsgpow'  # Fortfahren
                    # We don't have the needed pubkey in the pubkeys table already.
                    else:
                        print(f"  ❌ KEIN PUBKEY GEFUNDEN für {toaddress[:20]}...")
                        debug_print("  KEIN PUBKEY GEFUNDEN für %s...", toaddress[:20])
                        if toAddressVersionNumber <= 3:
                            toTag = b''
                        else:
                            toTag = highlevelcrypto.double_sha512(
                                encodeVarint(toAddressVersionNumber)
                                + encodeVarint(toStreamNumber) + toRipe
                            )[32:]
                        
                        # Python3: Konvertiere toTag zu bytes für Vergleich
                        toTag_bytes = toTag if isinstance(toTag, bytes) else str(toTag).encode('utf-8')
                        toaddress_str = toaddress if isinstance(toaddress, str) else toaddress.decode('utf-8')
                        
                        if toaddress_str in state.neededPubkeys or \
                                toTag_bytes in state.neededPubkeys:
                            # We already sent a request for the pubkey
                            print(f"  ℹ️  Pubkey wurde bereits angefordert")
                            debug_print("  Pubkey wurde bereits angefordert")
                            sqlExecute(
                                '''UPDATE sent SET status='awaitingpubkey', '''
                                ''' sleeptill=? WHERE toaddress=? '''
                                ''' AND status='msgqueued' ''',
                                int(time.time()) + 2.5 * 24 * 60 * 60,
                                toaddress
                            )
                            queues.UISignalQueue.put((
                                'updateSentItemStatusByToAddress', (
                                    toaddress,
                                    tr._translate(
                                        "MainWindow",
                                        "Encryption key was requested earlier."))
                            ))
                            print(f"  ✅ Status auf 'awaitingpubkey' gesetzt")
                            debug_print("  Status auf 'awaitingpubkey' gesetzt")
                            # on with the next msg on which we can do some work
                            continue
                        else:
                            # We have not yet sent a request for the pubkey
                            needToRequestPubkey = True
                            print(f"  ℹ️  Pubkey noch nicht angefordert")
                            debug_print("  Pubkey noch nicht angefordert")
                            
                            # If we are trying to send to address
                            # version >= 4 then the needed pubkey might be
                            # encrypted in the inventory.
                            if toAddressVersionNumber >= 4:
                                print(f"  V4+ Adresse, suche in Inventory...")
                                debug_print("  V4+ Adresse, suche in Inventory...")
                                doubleHashOfToAddressData = \
                                    highlevelcrypto.double_sha512(
                                        encodeVarint(toAddressVersionNumber)
                                        + encodeVarint(toStreamNumber) + toRipe
                                    )
                                # The first half of the sha512 hash.
                                privEncryptionKey = doubleHashOfToAddressData[:32]
                                # The second half of the sha512 hash.
                                tag = doubleHashOfToAddressData[32:]
                                state.neededPubkeys[tag] = (
                                    toaddress,
                                    highlevelcrypto.makeCryptor(
                                        hexlify(privEncryptionKey).decode('utf-8'))
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
                                            toaddress)
                                        del state.neededPubkeys[tag]
                                        print(f"  ✅ Pubkey aus Inventory dekodiert")
                                        debug_print("  Pubkey aus Inventory dekodiert")
                                        status = 'doingmsgpow'
                                        break
                                        
                            if needToRequestPubkey:
                                print(f"  Fordere Pubkey an für: {toaddress}")
                                debug_print("  Fordere Pubkey an für: %s", toaddress)
                                sqlExecute(
                                    '''UPDATE sent SET '''
                                    ''' status='doingpubkeypow' WHERE '''
                                    ''' toaddress=? AND status='msgqueued' AND folder='sent' ''',
                                    toaddress
                                )
                                queues.UISignalQueue.put((
                                    'updateSentItemStatusByToAddress', (
                                        toaddress,
                                        tr._translate(
                                            "MainWindow",
                                            "Sending a request for the"
                                            " recipient\'s encryption key."))
                                ))
                                print(f"  Starte requestPubKey...")
                                self.requestPubKey(toaddress)
                                print(f"  ⏭️  Weiter zur nächsten Nachricht")
                                # on with the next msg on which we can do some work
                                continue
                
                # NEU: Behandlung von 'awaitingpubkey' Status
                elif status == 'awaitingpubkey':
                    print(f"  Status ist 'awaitingpubkey' - prüfe ob Pubkey verfügbar")
                    debug_print("  Status ist 'awaitingpubkey' - prüfe ob Pubkey verfügbar")
                    
                    # Prüfe ob Pubkey jetzt in Datenbank ist
                    queryreturn_pubkey = sqlQuery(
                        '''SELECT address FROM pubkeys WHERE address=?''',
                        toaddress)
                    
                    if queryreturn_pubkey:
                        print(f"  ✅ Pubkey jetzt verfügbar! Aktualisiere Status zu 'doingmsgpow'")
                        debug_print("  Pubkey jetzt verfügbar! Aktualisiere Status zu 'doingmsgpow'")
                        try:
                            # VERBESSERT: Suche nach KOMBINATION aus msgid UND toaddress für Sicherheit
                            print(f"  Update mit msgid + toaddress...")
                            if isinstance(msgid, bytes):
                                update_result = sqlExecute(
                                    '''UPDATE sent SET status='doingmsgpow' '''
                                    ''' WHERE msgid=? AND toaddress=? AND status='awaitingpubkey' ''',
                                    sqlite3.Binary(msgid), toaddress)
                            else:
                                update_result = sqlExecute(
                                    '''UPDATE sent SET status='doingmsgpow' '''
                                    ''' WHERE msgid=? AND toaddress=? AND status='awaitingpubkey' ''',
                                    msgid, toaddress)
                            
                            print(f"  Update Result (mit msgid+toaddress): {update_result} Zeilen aktualisiert")
                            debug_print("  Update Result (mit msgid+toaddress): %d Zeilen aktualisiert", update_result)
                            
                            if update_result <= 0:
                                # Alternative 1: Nur mit toaddress
                                print(f"  ⚠️  Keine Zeilen mit msgid+toaddress, versuche nur mit toaddress...")
                                debug_print("  Keine Zeilen mit msgid+toaddress, versuche nur mit toaddress...")
                                update_result = sqlExecute(
                                    '''UPDATE sent SET status='doingmsgpow' '''
                                    ''' WHERE toaddress=? AND status='awaitingpubkey' ''',
                                    toaddress)
                                print(f"  Update nur mit toaddress: {update_result} Zeilen")
                                debug_print("  Update nur mit toaddress: %d Zeilen", update_result)
                                
                                # Alternative 2: Nur mit msgid
                                if update_result <= 0 and isinstance(msgid, bytes):
                                    print(f"  ⚠️  Versuche nur mit msgid...")
                                    debug_print("  Versuche nur mit msgid...")
                                    try:
                                        update_result = sqlExecute(
                                            '''UPDATE sent SET status='doingmsgpow' '''
                                            ''' WHERE msgid=? AND status='awaitingpubkey' ''',
                                            sqlite3.Binary(msgid))
                                        print(f"  Update nur mit msgid: {update_result} Zeilen")
                                        debug_print("  Update nur mit msgid: %d Zeilen", update_result)
                                    except Exception as e:
                                        print(f"  ❌ Fehler bei Update mit msgid: {e}")
                                        debug_print("  Fehler bei Update mit msgid: %s", e)
                            
                            if update_result <= 0:
                                print(f"  ⚠️  WARNUNG: Konnte keine Zeile updaten, setze Status manuell")
                                debug_print("  WARNUNG: Konnte keine Zeile updaten, setze Status manuell")
                                status = 'doingmsgpow'
                            else:
                                status = 'doingmsgpow'
                                print(f"  ✅ Status erfolgreich auf 'doingmsgpow' aktualisiert")
                                debug_print("  ✅ Status erfolgreich auf 'doingmsgpow' aktualisiert")
                            
                            # Mark pubkey as used
                            sqlExecute(
                                '''UPDATE pubkeys SET usedpersonally='yes' '''
                                ''' WHERE address=?''',
                                toaddress)
                            print(f"  ✅ Pubkey als 'usedpersonally' markiert")
                        except Exception as e:
                            print(f"  ❌ Fehler beim Aktualisieren: {e}")
                            debug_print("  Fehler beim Aktualisieren: %s", e)
                            status = 'doingmsgpow'  # Fortfahren trotz Fehler
                    else:
                        print(f"  ❌ KEIN PUBKEY GEFUNDEN - starte erneute Pubkey-Anfrage")
                        debug_print("  KEIN PUBKEY GEFUNDEN - starte erneute Pubkey-Anfrage")
                        print(f"  Setze Status auf 'doingpubkeypow' für erneute Anfrage")
                        debug_print("  Setze Status auf 'doingpubkeypow' für erneute Anfrage")
                        
                        try:
                            # Setze Status zurück zu 'doingpubkeypow' für erneute Anfrage
                            if isinstance(msgid, bytes):
                                update_result = sqlExecute(
                                    '''UPDATE sent SET status='doingpubkeypow', retrynumber=retrynumber+1 '''
                                    ''' WHERE msgid=? AND status='awaitingpubkey' ''',
                                    sqlite3.Binary(msgid))
                            else:
                                update_result = sqlExecute(
                                    '''UPDATE sent SET status='doingpubkeypow', retrynumber=retrynumber+1 '''
                                    ''' WHERE msgid=? AND status='awaitingpubkey' ''',
                                    msgid)
                            
                            print(f"  Update Result: {update_result} Zeilen aktualisiert für erneute Pubkey-Anfrage")
                            debug_print("  Update Result: %d Zeilen aktualisiert für erneute Pubkey-Anfrage", update_result)
                            
                            # Auch das letzte Aktualisierungsdatum zurücksetzen
                            sqlExecute(
                                '''UPDATE sent SET lastactiontime=? '''
                                ''' WHERE msgid=?''',
                                int(time.time()), msgid)
                            
                            print(f"  ✅ Status auf 'doingpubkeypow' zurückgesetzt - wird in nächster Runde verarbeitet")
                            debug_print("  Status auf 'doingpubkeypow' zurückgesetzt - wird in nächster Runde verarbeitet")
                        except Exception as e:
                            print(f"  ❌ Fehler beim Zurücksetzen des Status: {e}")
                            debug_print("  Fehler beim Zurücksetzen des Status: %s", e)
                        
                        print(f"  ⏭️  Weiter zur nächsten Nachricht")
                        continue

                print(f"\n📋 PHASE 6: Fortfahren mit Nachrichtenverarbeitung (Status: {status})")
                debug_print("  Fortfahren mit Nachrichtenverarbeitung...")
                
                # TTL Berechnung
                original_ttl = TTL
                TTL *= 2**retryNumber
                if TTL > 28 * 24 * 60 * 60:
                    TTL = 28 * 24 * 60 * 60
                
                # add some randomness to the TTL
                random_variation = helper_random.randomrandrange(-300, 300)
                TTL = int(TTL + random_variation)
                embeddedTime = int(time.time() + TTL)
                
                print(f"  TTL Berechnung:")
                print(f"    Original TTL: {original_ttl}")
                print(f"    Nach retryNumber ({retryNumber}): {TTL // (2**retryNumber) if retryNumber > 0 else TTL}")
                print(f"    Mit Zufalls-Variation ({random_variation}): {TTL}")
                print(f"    embeddedTime: {embeddedTime} (UTC: {time.ctime(embeddedTime)})")
                
                debug_print("  Original TTL: %d, Finale TTL: %d, embeddedTime: %d", 
                          original_ttl, TTL, embeddedTime)

                # if we aren't sending this to ourselves or a chan
                if not config.has_section(toaddress):
                    print(f"\n📋 PHASE 7: Sende Nachricht an andere")
                    state.ackdataForWhichImWatching[ackdata] = 0
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata,
                            tr._translate(
                                "MainWindow",
                                "Looking up the receiver\'s public key"))
                    ))
                    print('  Sending a message.')
                    print(f"  First 150 characters of message: {repr(message[:150])}")
                    debug_print('Sending a message.')
                    debug_print('First 150 characters of message: %s', repr(message[:150]))

                    # Let us fetch the recipient's public key out of
                    # our database.
                    print(f"  Hole Pubkey aus Datenbank für: {toaddress}")
                    queryreturn_pubkey = sqlQuery(
                        'SELECT transmitdata FROM pubkeys WHERE address=?',
                        toaddress)
                    
                    if not queryreturn_pubkey:
                        print(f"  ❌ FEHLER: Kein pubkey in Datenbank für %s", toaddress)
                        debug_print("  FEHLER: Kein pubkey in Datenbank für %s", toaddress)
                        continue
                    
                    print(f"  ✅ Pubkey gefunden, verarbeite...")
                    for row in queryreturn_pubkey:
                        pubkeyPayload_raw = row[0]
                        
                        # KRITISCHES DEBUGGING FÜR PUBKEYPAYLOAD
                        print(f"  pubkeyPayload_raw Typ: {type(pubkeyPayload_raw)}")
                        
                        # Konvertiere pubkeyPayload zu bytes
                        pubkeyPayload = None
                        if isinstance(pubkeyPayload_raw, bytes):
                            pubkeyPayload = pubkeyPayload_raw
                            print(f"  ✅ pubkeyPayload ist bytes, Länge: {len(pubkeyPayload)}")
                        elif isinstance(pubkeyPayload_raw, str):
                            print(f"  pubkeyPayload ist string, konvertiere zu bytes...")
                            try:
                                # Versuche hex decoding zuerst
                                pubkeyPayload = unhexlify(pubkeyPayload_raw)
                                print(f"  ✅ Als hex string decodiert, Länge: {len(pubkeyPayload)}")
                            except:
                                # Sonst normale string zu bytes
                                pubkeyPayload = pubkeyPayload_raw.encode('latin-1')
                                print(f"  ✅ Als latin-1 string konvertiert, Länge: {len(pubkeyPayload)}")
                        elif isinstance(pubkeyPayload_raw, int):
                            print(f"  ⚠️  WARNUNG: pubkeyPayload ist int! Wert: {pubkeyPayload_raw}")
                            try:
                                byte_length = (pubkeyPayload_raw.bit_length() + 7) // 8
                                pubkeyPayload = pubkeyPayload_raw.to_bytes(byte_length, 'big')
                                print(f"  ✅ Int zu bytes konvertiert, Länge: {len(pubkeyPayload)}")
                            except Exception as e:
                                print(f"  ❌ Konnte int nicht zu bytes konvertieren: {e}")
                                continue
                        else:
                            print(f"  ❌ UNBEKANNTER Typ für pubkeyPayload: {type(pubkeyPayload_raw)}")
                            continue
                        
                        if not pubkeyPayload:
                            print(f"  ❌ pubkeyPayload ist None oder leer!")
                            continue
                        
                        print(f"  Finales pubkeyPayload Länge: {len(pubkeyPayload)} bytes")
                        print(f"  Erste 32 bytes: {hexlify(pubkeyPayload[:32])[:64]}")
                        
                        # to bypass the address version whose length is definitely 1
                        readPosition = 1
                        
                        # Debug vor decodeVarint
                        print(f"  Vor decodeVarint: readPosition={readPosition}")
                        
                        try:
                            _, streamNumberLength = decodeVarint(
                                pubkeyPayload[readPosition:readPosition + 10])
                            readPosition += streamNumberLength
                            print(f"  Nach decodeVarint: readPosition={readPosition}, streamNumberLength={streamNumberLength}")
                        except Exception as e:
                            print(f"  ❌ Fehler bei decodeVarint: {e}")
                            continue
                        
                        behaviorBitfield = pubkeyPayload[readPosition:readPosition + 4]
                        print(f"  behaviorBitfield: {hexlify(behaviorBitfield)}")
                        
                        # if receiver is a mobile device who expects that their
                        # address RIPE is included unencrypted on the front of
                        # the message..
                        if protocol.isBitSetWithinBitfield(behaviorBitfield, 30):
                            # if we are Not willing to include the receiver's
                            # RIPE hash on the message..
                            if not config.safeGetBoolean(
                                    'bitmessagesettings', 'willinglysendtomobile'
                            ):
                                print(f'  ❌ The receiver is a mobile user but you are not willing to send to mobiles')
                                debug_print(
                                    'The receiver is a mobile user but the'
                                    ' sender (you) has not selected that you'
                                    ' are willing to send to mobiles. Aborting'
                                    ' send.'
                                )
                                queues.UISignalQueue.put((
                                    'updateSentItemStatusByAckdata', (
                                        ackdata,
                                        tr._translate(
                                            "MainWindow",
                                            "Problem: Destination is a mobile"
                                            " device who requests that the"
                                            " destination be included in the"
                                            " message but this is disallowed in"
                                            " your settings.  %1"
                                        ).arg(l10n.formatTimestamp()))
                                ))
                                continue
                        
                        readPosition += 4
                        readPosition += 64  # Skip signing key
                        pubEncryptionKeyBase256 = pubkeyPayload[
                            readPosition:readPosition + 64]
                        readPosition += 64
                        
                        print(f"  pubEncryptionKeyBase256 Länge: {len(pubEncryptionKeyBase256)}")
                        print(f"  pubEncryptionKeyBase256 Hex: {hexlify(pubEncryptionKeyBase256)[:64]}...")

                        # Let us fetch the amount of work required by the recipient.
                        if toAddressVersionNumber == 2:
                            requiredAverageProofOfWorkNonceTrialsPerByte = \
                                defaults.networkDefaultProofOfWorkNonceTrialsPerByte
                            requiredPayloadLengthExtraBytes = \
                                defaults.networkDefaultPayloadLengthExtraBytes
                            queues.UISignalQueue.put((
                                'updateSentItemStatusByAckdata', (
                                    ackdata,
                                    tr._translate(
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
                            if requiredAverageProofOfWorkNonceTrialsPerByte < \
                                    defaults.networkDefaultProofOfWorkNonceTrialsPerByte:
                                requiredAverageProofOfWorkNonceTrialsPerByte = \
                                    defaults.networkDefaultProofOfWorkNonceTrialsPerByte
                            if requiredPayloadLengthExtraBytes < \
                                    defaults.networkDefaultPayloadLengthExtraBytes:
                                requiredPayloadLengthExtraBytes = \
                                    defaults.networkDefaultPayloadLengthExtraBytes
                            
                            print(f"  PoW Anforderungen vom Empfänger:")
                            print(f"    requiredAverageProofOfWorkNonceTrialsPerByte: {requiredAverageProofOfWorkNonceTrialsPerByte}")
                            print(f"    requiredPayloadLengthExtraBytes: {requiredPayloadLengthExtraBytes}")
                            
                            debug_print(
                                'Using averageProofOfWorkNonceTrialsPerByte: %s'
                                ' and payloadLengthExtraBytes: %s.',
                                requiredAverageProofOfWorkNonceTrialsPerByte,
                                requiredPayloadLengthExtraBytes
                            )

                            queues.UISignalQueue.put(
                                (
                                    'updateSentItemStatusByAckdata',
                                    (
                                        ackdata,
                                        tr._translate(
                                            "MainWindow",
                                            "Doing work necessary to send message.\n"
                                            "Receiver\'s required difficulty: %1"
                                            " and %2"
                                        ).arg(
                                            str(
                                                float(requiredAverageProofOfWorkNonceTrialsPerByte)
                                                / defaults.networkDefaultProofOfWorkNonceTrialsPerByte
                                            )
                                        ).arg(
                                            str(
                                                float(requiredPayloadLengthExtraBytes)
                                                / defaults.networkDefaultPayloadLengthExtraBytes
                                            )
                                        )
                                    )
                                )
                            )

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
                                    print(f"  ❌ PoW zu schwierig, abgebrochen")
                                    sqlExecute(
                                        '''UPDATE sent SET status='toodifficult' '''
                                        ''' WHERE ackdata=? AND folder='sent' ''',
                                        sqlite3.Binary(ackdata))
                                    queues.UISignalQueue.put((
                                        'updateSentItemStatusByAckdata', (
                                            ackdata,
                                            tr._translate(
                                                "MainWindow",
                                                "Problem: The work demanded by"
                                                " the recipient (%1 and %2) is"
                                                " more difficult than you are"
                                                " willing to do. %3"
                                            ).arg(str(float(requiredAverageProofOfWorkNonceTrialsPerByte)
                                                  / defaults.networkDefaultProofOfWorkNonceTrialsPerByte)
                                                  ).arg(str(float(requiredPayloadLengthExtraBytes)
                                                        / defaults.networkDefaultPayloadLengthExtraBytes)
                                                        ).arg(l10n.formatTimestamp()))))
                                    debug_print("  PoW zu schwierig, abgebrochen")
                                    continue
                else:  # if we are sending a message to ourselves or a chan..
                    print(f"\n📋 PHASE 7: Sende Nachricht an sich selbst/chan")
                    debug_print('Sending a message to self/chan.')
                    debug_print('First 150 characters of message: %r', message[:150])
                    behaviorBitfield = protocol.getBitfield(fromaddress)

                    try:
                        privEncryptionKeyBase58 = config.get(
                            toaddress, 'privencryptionkey')
                    except (configparser.NoSectionError, configparser.NoOptionError) as err:
                        print(f"  ❌ Fehler: Konnte privEncryptionKey nicht lesen: {err}")
                        queues.UISignalQueue.put((
                            'updateSentItemStatusByAckdata', (
                                ackdata,
                                tr._translate(
                                    "MainWindow",
                                    "Problem: You are trying to send a"
                                    " message to yourself or a chan but your"
                                    " encryption key could not be found in"
                                    " the keys.dat file. Could not encrypt"
                                    " message. %1"
                                ).arg(l10n.formatTimestamp()))
                        ))
                        debug_print(
                            'Error within sendMsg. Could not read the keys'
                            ' from the keys.dat file for our own address. %s\n',
                            err)
                        continue
                    
                    # Python3 compatibility
                    if isinstance(privEncryptionKeyBase58, str):
                        privEncryptionKeyBase58_bytes = privEncryptionKeyBase58.encode('utf-8')
                    else:
                        privEncryptionKeyBase58_bytes = privEncryptionKeyBase58
                        
                    privEncryptionKeyHex = hexlify(
                        highlevelcrypto.decodeWalletImportFormat(
                            privEncryptionKeyBase58_bytes))
                    
                    # Python3: hexlify returns bytes, decode to string
                    if isinstance(privEncryptionKeyHex, bytes):
                        privEncryptionKeyHex_str = privEncryptionKeyHex.decode('utf-8')
                    else:
                        privEncryptionKeyHex_str = privEncryptionKeyHex
                    
                    pubEncryptionKeyBase256 = unhexlify(highlevelcrypto.privToPub(
                        privEncryptionKeyHex_str))[1:]
                    requiredAverageProofOfWorkNonceTrialsPerByte = \
                        defaults.networkDefaultProofOfWorkNonceTrialsPerByte
                    requiredPayloadLengthExtraBytes = \
                        defaults.networkDefaultPayloadLengthExtraBytes
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata,
                            tr._translate(
                                "MainWindow",
                                "Doing work necessary to send message."))
                    ))
                    print(f"  ✅ Für Selbst/Chan: Default PoW Parameter verwendet")

                print(f"\n📋 PHASE 8: Assembliere Nachricht")
                # Now we can start to assemble our message.
                payload = encodeVarint(fromAddressVersionNumber)
                payload += encodeVarint(fromStreamNumber)
                payload += protocol.getBitfield(fromaddress)

                # We need to convert our private keys to public keys in order
                # to include them.
                try:
                    privSigningKeyHex, privEncryptionKeyHex, \
                        pubSigningKey, pubEncryptionKey = self._getKeysForAddress(
                            fromaddress)
                    print(f"  ✅ Schlüssel für Absender geholt")
                except ValueError:
                    print(f"  ❌ Fehler: Absender Adresse nicht in keys.dat gefunden")
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata,
                            tr._translate(
                                "MainWindow",
                                "Error! Could not find sender address"
                                " (your address) in the keys.dat file."))
                    ))
                    continue
                except Exception as err:
                    print(f"  ❌ Fehler beim Holen der Schlüssel: {err}")
                    debug_print(
                        'Error within sendMsg. Could not read'
                        ' the keys from the keys.dat file for a requested'
                        ' address. %s\n', err
                    )
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata,
                            tr._translate(
                                "MainWindow",
                                "Error, can't send."))
                    ))
                    continue

                payload += pubSigningKey + pubEncryptionKey

                if fromAddressVersionNumber >= 3:
                    # If the receiver of our message is in our address book,
                    # subscriptions list, or whitelist then we will allow them to
                    # do the network-minimum proof of work.
                    if shared.isAddressInMyAddressBookSubscriptionsListOrWhitelist(
                            toaddress):
                        payload += encodeVarint(
                            defaults.networkDefaultProofOfWorkNonceTrialsPerByte)
                        payload += encodeVarint(
                            defaults.networkDefaultPayloadLengthExtraBytes)
                        print(f"  ✅ Empfänger in Adressbuch/Whitelist - verwende Default PoW")
                    else:
                        payload += encodeVarint(config.getint(
                            fromaddress, 'noncetrialsperbyte'))
                        payload += encodeVarint(config.getint(
                            fromaddress, 'payloadlengthextrabytes'))
                        print(f"  ✅ Verwende Absender PoW Parameter")

                # This hash will be checked by the receiver of the message
                # to verify that toRipe belongs to them.
                payload += toRipe
                payload += encodeVarint(encoding)  # message encoding type
                encodedMessage = helper_msgcoding.MsgEncode(
                    {"subject": subject, "body": message}, encoding
                )
                payload += encodeVarint(encodedMessage.length)
                payload += encodedMessage.data
                
                print(f"  Payload Basis zusammengebaut, Länge: {len(payload)} bytes")
                
                if config.has_section(toaddress):
                    debug_print(
                        'Not bothering to include ackdata because we are'
                        ' sending to ourselves or a chan.'
                    )
                    fullAckPayload = b''
                    print(f"  Kein ackdata für Selbst/Chan")
                elif not protocol.checkBitfield(
                        behaviorBitfield, protocol.BITFIELD_DOESACK):
                    debug_print(
                        'Not bothering to include ackdata because'
                        ' the receiver said that they won\'t relay it anyway.'
                    )
                    fullAckPayload = b''
                    print(f"  Kein ackdata (Empfänger will nicht relayen)")
                else:
                    # The fullAckPayload is a normal msg protocol message
                    # with the proof of work already completed
                    print(f"  Generiere fullAckPayload...")
                    fullAckPayload = self.generateFullAckMessage(
                        ackdata, toStreamNumber, TTL)
                    print(f"  fullAckPayload Länge: {len(fullAckPayload)}")
                
                payload += encodeVarint(len(fullAckPayload))
                payload += fullAckPayload
                
                # Python3: Ensure bytes for dataToSign
                dataToSign = pack('>Q', embeddedTime) + b'\x00\x00\x00\x02' + \
                    encodeVarint(1) + encodeVarint(toStreamNumber) + payload
                    
                print(f"  dataToSign Länge: {len(dataToSign)}")
                
                signature = highlevelcrypto.sign(
                    dataToSign, privSigningKeyHex, self.digestAlg)
                payload += encodeVarint(len(signature))
                payload += signature
                
                print(f"  Signatur hinzugefügt, Länge: {len(signature)}")
                print(f"  Finales Payload vor Verschlüsselung: {len(payload)} bytes")

                # We have assembled the data that will be encrypted.
                print(f"\n📋 PHASE 9: Verschlüssele Payload")
                try:
                    encrypted = highlevelcrypto.encrypt(
                        payload, "04" + hexlify(pubEncryptionKeyBase256).decode('utf-8')
                    )
                    print(f"  ✅ Verschlüsselung erfolgreich")
                    print(f"  Verschlüsselte Daten Länge: {len(encrypted)}")
                except Exception as e:
                    print(f"  ❌ highlevelcrypto.encrypt didn't work: {e}")
                    debug_print("highlevelcrypto.encrypt didn't work: %s", e)
                    sqlExecute(
                        '''UPDATE sent SET status='badkey' WHERE ackdata=? AND folder='sent' ''',
                        sqlite3.Binary(ackdata)
                    )
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata,
                            tr._translate(
                                "MainWindow",
                                "Problem: The recipient\'s encryption key is"
                                " no good. Could not encrypt message. %1"
                            ).arg(l10n.formatTimestamp()))
                    ))
                    continue

                encryptedPayload = pack('>Q', embeddedTime)
                encryptedPayload += b'\x00\x00\x00\x02'  # object type: msg
                encryptedPayload += encodeVarint(1)  # msg version
                encryptedPayload += encodeVarint(toStreamNumber) + encrypted

                print(f"\n📋 PHASE 10: Proof of Work")
                print(f"  Starte PoW für Nachricht...")
                print(f"  encryptedPayload Länge vor PoW: {len(encryptedPayload)}")
                
                encryptedPayload = self._doPOWDefaults(
                    encryptedPayload, TTL,
                    requiredAverageProofOfWorkNonceTrialsPerByte,
                    requiredPayloadLengthExtraBytes,
                    log_prefix='(For msg message)', log_time=True
                )

                if encryptedPayload is None:
                    print(f"  ❌ PoW fehlgeschlagen")
                    debug_print("  PoW fehlgeschlagen")
                    continue
                
                print(f"  ✅ PoW erfolgreich")
                print(f"  encryptedPayload Länge nach PoW: {len(encryptedPayload)}")

                # Sanity check
                if len(encryptedPayload) > 2 ** 18:
                    print(f"  ❌ This msg object is too large to send: {len(encryptedPayload)} bytes")
                    debug_print(
                        'This msg object is too large to send. This should'
                        ' never happen. Object size: %i',
                        len(encryptedPayload)
                    )
                    continue

                inventoryHash = highlevelcrypto.calculateInventoryHash(encryptedPayload)
                objectType = 2
                state.Inventory[inventoryHash] = (
                    objectType, toStreamNumber, encryptedPayload, embeddedTime, b'')
                    
                print(f"  ✅ Inventory Hash berechnet: {hexlify(inventoryHash)}")
                
                if config.has_section(toaddress) or \
                   not protocol.checkBitfield(behaviorBitfield, protocol.BITFIELD_DOESACK):
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata,
                            tr._translate(
                                "MainWindow",
                                "Message sent. Sent at %1"
                            ).arg(l10n.formatTimestamp()))))
                    print(f"  ✅ Nachricht gesendet (kein ACK erwartet)")
                else:
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata,
                            tr._translate(
                                "MainWindow",
                                "Message sent. Waiting for acknowledgement."
                                " Sent on %1"
                            ).arg(l10n.formatTimestamp()))
                    ))
                    print(f"  ✅ Nachricht gesendet, warte auf ACK")
                    
                print(f"  Broadcasting inv for my msg: {hexlify(inventoryHash)[:64]}...")
                debug_print(
                    'Broadcasting inv for my msg(within sendmsg function): %s',
                    hexlify(inventoryHash).decode('utf-8')
                )
                invQueue.put((toStreamNumber, inventoryHash))

                print(f"\n📋 PHASE 11: Datenbank aktualisieren")
                # Update the sent message in the sent table
                if config.has_section(toaddress) or \
                   not protocol.checkBitfield(behaviorBitfield, protocol.BITFIELD_DOESACK):
                    newStatus = 'msgsentnoackexpected'
                else:
                    newStatus = 'msgsent'
                
                # wait 10% past expiration
                sleepTill = int(time.time() + TTL * 1.1)
                print(f"  sleepTill: {sleepTill} (UTC: {time.ctime(sleeptill)})")
                
                sqlExecute(
                    '''UPDATE sent SET msgid=?, status=?, retrynumber=?, '''
                    ''' sleeptill=?, lastactiontime=? WHERE ackdata=? AND folder='sent' ''',
                    sqlite3.Binary(inventoryHash), newStatus, retryNumber + 1,
                    sleepTill, int(time.time()), sqlite3.Binary(ackdata)
                )
                
                print(f"  ✅ Datenbank aktualisiert: Status={newStatus}")

                # If we are sending to ourselves or a chan, put in inbox
                if config.has_section(toaddress):
                    sigHash = highlevelcrypto.double_sha512(signature)[32:]
                    t = (inventoryHash, toaddress, fromaddress, subject, int(
                        time.time()), message, 'inbox', encoding, 0, sigHash)
                    helper_inbox.insert(t)

                    queues.UISignalQueue.put(('displayNewInboxMessage', (
                        inventoryHash, toaddress, fromaddress, subject, message)))
                    
                    print(f"  ✅ Nachricht in inbox eingefügt (Selbst/Chan)")

                print(f"\n✅ Nachricht {i+1} erfolgreich gesendet!")
                debug_print("  Nachricht %d erfolgreich gesendet", i+1)
                
            except Exception as e:
                print(f"\n❌ FEHLER beim Verarbeiten von Nachricht row {i}: {e}")
                import traceback
                traceback.print_exc()
                debug_print("Fehler beim Verarbeiten von Nachricht row %d: %s", i, e)
                continue
        
        print(f"\n" + "=" * 80)
        print(f"✅ SENDMSG ABGESCHLOSSEN")
        print(f"   Verarbeitete Nachrichten: {len(queryreturn)}")
        print("=" * 80)
        
        debug_print("Nachrichten Verarbeitung abgeschlossen")
    def requestPubKey(self, toAddress):
        """Send a getpubkey object - PROFESSIONAL FIX BASED ON PYTHON2"""
        print("=" * 80)
        print("🚀 REQUESTPUBKEY START für Adresse:", toAddress[:50] + "..." if len(toAddress) > 50 else toAddress)
        print("=" * 80)
        
        # 1. EXAKT wie Python2: Adresse dekodieren
        print("\n📋 PHASE 1: Adresse dekodieren")
        print("  toAddress:", repr(toAddress))
        
        try:
            toStatus, addressVersionNumber, streamNumber, ripe = decodeAddress(toAddress)
            print(f"  ✅ Dekodierung erfolgreich:")
            print(f"    Status: {toStatus}")
            print(f"    Version: {addressVersionNumber}")
            print(f"    Stream: {streamNumber}")
            print(f"    RIPE Länge: {len(ripe)} bytes")
            print(f"    RIPE Hex: {hexlify(ripe)[:32]}...")
        except Exception as e:
            print(f"  ❌ FEHLER bei decodeAddress: {e}")
            debug_print('Ungültige Adresse: %s', toAddress)
            return

        if toStatus != 'success':
            print(f"  ❌ Ungültige Adresse, Status: {toStatus}")
            debug_print('Ungültige Adresse: %s', toAddress)
            return

        # 2. PROFESSIONELLER ANSATZ: Mehrere Abfrage-Strategien
        print("\n📋 PHASE 2: Finde Nachricht in Datenbank")
        print("  PROFI-FIX: Verwende mehrere Query-Strategien...")
        
        retryNumber = 0
        found = False
        
        # Strategie 1: Exakt wie Python2 (mit dbstr)
        print("\n  🔍 Strategie 1: Original Python2 Query (mit dbstr)")
        print(f"    SQL: SELECT retrynumber FROM sent WHERE toaddress=? AND (status='doingpubkeypow' OR status='awaitingpubkey') AND folder='sent' LIMIT 1")
        print(f"    Parameter: dbstr(toAddress) = {repr(dbstr(toAddress))}")
        
        try:
            queryReturn = sqlQuery(
                '''SELECT retrynumber FROM sent WHERE toaddress=? '''
                ''' AND (status='doingpubkeypow' OR status='awaitingpubkey') '''
                ''' AND folder='sent' LIMIT 1''',
                dbstr(toAddress))
            
            print(f"    Query Ergebnis: {len(queryReturn)} Zeilen")
            
            if queryReturn:
                retryNumber = queryReturn[0][0]
                found = True
                print(f"    ✅ Strategie 1 erfolgreich")
                print(f"    retryNumber: {retryNumber} (Typ: {type(retryNumber)})")
            else:
                print("    ℹ️  Keine Ergebnisse mit Strategie 1")
        except Exception as e:
            print(f"    ❌ Fehler bei Strategie 1 Query: {e}")
        
        # Strategie 2: Ohne Status-Bedingung (falls Status noch msgqueued ist)
        if not found:
            print("\n  🔍 Strategie 2: Query OHNE Status-Bedingung")
            print(f"    SQL: SELECT retrynumber FROM sent WHERE toaddress=? AND folder='sent' LIMIT 1")
            
            try:
                queryReturn = sqlQuery(
                    '''SELECT retrynumber FROM sent WHERE toaddress=? '''
                    ''' AND folder='sent' LIMIT 1''',
                    dbstr(toAddress))
                
                print(f"    Query Ergebnis: {len(queryReturn)} Zeilen")
                
                if queryReturn:
                    retryNumber = queryReturn[0][0]
                    found = True
                    print(f"    ✅ Strategie 2 erfolgreich")
                    print(f"    retryNumber: {retryNumber}")
                    
                    # Status prüfen und korrigieren falls nötig
                    print("    📊 Prüfe aktuellen Status...")
                    status_query = sqlQuery(
                        '''SELECT status FROM sent WHERE toaddress=? AND folder='sent' LIMIT 1''',
                        dbstr(toAddress))
                    
                    if status_query:
                        current_status = status_query[0][0]
                        print(f"    Aktueller Status: '{current_status}'")
                        
                        if current_status == 'msgqueued':
                            print("    ⚠️  Status ist 'msgqueued', korrigiere zu 'doingpubkeypow'...")
                            try:
                                rows_updated = sqlExecute(
                                    '''UPDATE sent SET status='doingpubkeypow' '''
                                    ''' WHERE toaddress=? AND folder='sent' ''',
                                    dbstr(toAddress))
                                print(f"    ✅ {rows_updated} Zeilen aktualisiert")
                            except Exception as e:
                                print(f"    ❌ Fehler beim Update: {e}")
                    else:
                        print("    ℹ️  Kein Status gefunden")
                else:
                    print("    ℹ️  Keine Ergebnisse mit Strategie 2")
            except Exception as e:
                print(f"    ❌ Fehler bei Strategie 2 Query: {e}")
        
        # Strategie 3: Direkte Suche in allen sent Einträgen
        if not found:
            print("\n  🔍 Strategie 3: Manuelle Suche in allen sent Einträgen")
            
            try:
                all_entries = sqlQuery('''SELECT toaddress, retrynumber, status FROM sent WHERE folder='sent' ''')
                print(f"    Durchsuche {len(all_entries)} Einträge...")
                
                match_count = 0
                for addr_in_db, retry, status in all_entries:
                    # Konvertiere bytes zu string falls nötig
                    original_addr = addr_in_db
                    if isinstance(addr_in_db, bytes):
                        try:
                            addr_in_db = addr_in_db.decode('utf-8', 'replace')
                        except:
                            addr_in_db = str(addr_in_db)
                    
                    # Debug Ausgabe für ersten Eintrag
                    if match_count == 0:
                        print(f"    Beispiel-Eintrag: addr='{addr_in_db[:50]}...' (Original: {type(original_addr)}), retry={retry}, status='{status}'")
                    
                    if addr_in_db.strip() == toAddress.strip():
                        retryNumber = retry if retry is not None else 0
                        found = True
                        match_count += 1
                        print(f"    ✅ Treffer {match_count}:")
                        print(f"      addr='{addr_in_db[:50]}...'")
                        print(f"      retry={retryNumber}")
                        print(f"      status='{status}'")
                        
                        # Status korrigieren falls nötig
                        if status == 'msgqueued':
                            print("      ⚠️  Korrigiere Status von 'msgqueued' zu 'doingpubkeypow'...")
                            try:
                                rows_updated = sqlExecute(
                                    '''UPDATE sent SET status='doingpubkeypow' '''
                                    ''' WHERE toaddress=? AND folder='sent' ''',
                                    dbstr(toAddress))
                                print(f"      ✅ {rows_updated} Zeilen aktualisiert")
                            except Exception as e:
                                print(f"      ❌ Fehler beim Update: {e}")
                
                if match_count > 0:
                    print(f"    ✅ {match_count} Treffer gefunden")
                else:
                    print("    ℹ️  Keine Treffer gefunden")
                    
            except Exception as e:
                print(f"    ❌ Fehler bei Strategie 3: {e}")
        
        if not found:
            print("\n❌ KRITISCHER FEHLER: Kein Eintrag für diese Adresse gefunden!")
            print(f"  Adresse: {toAddress}")
            print("  Mögliche Ursachen:")
            print("  1. Nachricht wurde noch nicht in 'sent' Tabelle gespeichert")
            print("  2. Adresse ist falsch geschrieben")
            print("  3. Datenbank ist korrupt")
            debug_print("✗ KRITISCHER FEHLER: Kein Eintrag für %s gefunden!", toAddress)
            return
        
        print(f"\n✅ Nachricht gefunden: retryNumber = {retryNumber}")

        # 3. Ab hier EXAKTE Python2-Logik (angepasst für Debug)
        print("\n📋 PHASE 3: Verarbeite Adresse")
        print(f"  addressVersionNumber: {addressVersionNumber}")
        print(f"  streamNumber: {streamNumber}")
        print(f"  retryNumber: {retryNumber}")
        
        if addressVersionNumber <= 3:
            print(f"  ✅ V3 oder früher - füge zu neededPubkeys hinzu")
            state.neededPubkeys[toAddress] = 0
            print(f"    neededPubkeys Größe: {len(state.neededPubkeys)}")
        elif addressVersionNumber >= 4:
            print(f"  ✅ V4 Adresse - generiere Tag für neededPubkeys")
            
            # Python2-Logik: Tag generieren und zu neededPubkeys hinzufügen
            try:
                doubleHashOfAddressData = highlevelcrypto.double_sha512(
                    encodeVarint(addressVersionNumber)
                    + encodeVarint(streamNumber) + ripe
                )
                privEncryptionKey = doubleHashOfAddressData[:32]
                tag = doubleHashOfAddressData[32:]
                tag_bytes = bytes(tag)
                
                print(f"    doubleHashOfAddressData Länge: {len(doubleHashOfAddressData)}")
                print(f"    privEncryptionKey Länge: {len(privEncryptionKey)}")
                print(f"    tag Länge: {len(tag)}")
                print(f"    tag Hex: {hexlify(tag_bytes)[:32]}...")
                
                if tag_bytes not in state.neededPubkeys:
                    state.neededPubkeys[tag_bytes] = (
                        toAddress,
                        highlevelcrypto.makeCryptor(hexlify(privEncryptionKey))
                    )
                    print(f"    ✅ Tag zu neededPubkeys hinzugefügt")
                    print(f"    neededPubkeys Größe: {len(state.neededPubkeys)}")
                else:
                    print(f"    ℹ️  Tag bereits in neededPubkeys vorhanden")
            except Exception as e:
                print(f"    ❌ Fehler bei Tag-Generierung: {e}")
        
        print("\n📋 PHASE 4: TTL Berechnung")
        TTL = 2.5 * 24 * 60 * 60  # 2.5 Tage in Sekunden
        print(f"  Basis TTL: {TTL} Sekunden ({TTL/86400:.1f} Tage)")
        
        TTL *= 2 ** retryNumber
        print(f"  Nach retryNumber ({retryNumber}): {TTL} Sekunden")
        
        if TTL > 28 * 24 * 60 * 60:
            TTL = 28 * 24 * 60 * 60
            print(f"  Auf Maximum gekappt: {TTL} Sekunden (28 Tage)")
        
        # Zufällige Variation
        random_variation = helper_random.randomrandrange(-300, 300)
        TTL = TTL + random_variation
        print(f"  Mit Zufalls-Variation ({random_variation}): {TTL} Sekunden")
        
        embeddedTime = int(time.time() + TTL)
        print(f"  embeddedTime: {embeddedTime} (UTC: {time.ctime(embeddedTime)})")
        print(f"  Aktuelle Zeit: {int(time.time())} (UTC: {time.ctime()})")
        
        print("\n📋 PHASE 5: Payload erstellen")
        payload = pack('>Q', embeddedTime)
        print(f"  embeddedTime (8 bytes): {hexlify(payload)}")
        
        payload += b'\x00\x00\x00\x00'  # object type: getpubkey
        print(f"  + object type getpubkey (4 bytes): {hexlify(payload[-4:])}")
        
        payload += encodeVarint(addressVersionNumber)
        print(f"  + addressVersionNumber (varint): {hexlify(encodeVarint(addressVersionNumber))}")
        
        payload += encodeVarint(streamNumber)
        print(f"  + streamNumber (varint): {hexlify(encodeVarint(streamNumber))}")
        
        if addressVersionNumber <= 3:
            payload += ripe
            print(f"  + ripe ({len(ripe)} bytes): {hexlify(ripe)[:32]}...")
            print(f"  ✅ Fordere pubkey an mit ripe")
        else:
            payload += tag
            print(f"  + tag ({len(tag)} bytes): {hexlify(tag)[:32]}...")
            print(f"  ✅ Fordere v4 pubkey an mit tag")
        
        print(f"  Gesamt Payload Länge: {len(payload)} bytes")
        
        print("\n📋 PHASE 6: UI Updates")
        try:
            queues.UISignalQueue.put(('updateStatusBar', 
                'Doing the computations necessary to request the recipient\'s public key.'))
            queues.UISignalQueue.put((
                'updateSentItemStatusByToAddress', (
                    toAddress, tr._translate(
                        "MainWindow",
                        "Doing work necessary to request encryption key."))
            ))
            print("  ✅ UI Updates in Queue gesetzt")
        except Exception as e:
            print(f"  ⚠️  Fehler bei UI Updates: {e}")
        
        print("\n📋 PHASE 7: Proof of Work durchführen")
        print(f"  Starte PoW für getpubkey request...")
        print(f"  TTL: {TTL} Sekunden")
        print(f"  Payload Länge vor PoW: {len(payload)} bytes")
        
        try:
            payload = self._doPOWDefaults(payload, TTL, log_prefix='(For getpubkey)')
            if payload is None:
                print("  ❌ PoW fehlgeschlagen!")
                debug_print("PoW fehlgeschlagen für getpubkey request")
                return
            print(f"  ✅ PoW erfolgreich")
            print(f"  Payload Länge nach PoW: {len(payload)} bytes")
        except Exception as e:
            print(f"  ❌ Fehler bei PoW: {e}")
            return
        
        print("\n📋 PHASE 8: Inventory erstellen")
        try:
            inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
            objectType = 1
            state.Inventory[inventoryHash] = (
                objectType, streamNumber, payload, embeddedTime, b'')
            print(f"  ✅ Inventory Hash berechnet: {hexlify(inventoryHash)}")
            print(f"  ✅ Inventory gespeichert")
        except Exception as e:
            print(f"  ❌ Fehler bei Inventory Erstellung: {e}")
            return
        
        print("\n📋 PHASE 9: Sende getpubkey request")
        print(f"  Sende inv mit hash: {hexlify(inventoryHash)[:64]}...")
        
        try:
            invQueue.put((streamNumber, inventoryHash))
            print(f"  ✅ inv in Queue gestellt (Stream: {streamNumber})")
        except Exception as e:
            print(f"  ❌ Fehler beim Senden: {e}")
        
        print("\n📋 PHASE 10: Datenbank aktualisieren")
        sleeptill = int(time.time() + TTL * 1.1)
        print(f"  sleeptill: {sleeptill} (UTC: {time.ctime(sleeptill)})")
        print(f"  retryNumber neu: {retryNumber + 1}")
        
        try:
            rows_updated = sqlExecute(
                '''UPDATE sent SET lastactiontime=?, '''
                ''' status='awaitingpubkey', retrynumber=?, sleeptill=? '''
                ''' WHERE toaddress=? AND (status='doingpubkeypow' OR '''
                ''' status='awaitingpubkey') AND folder='sent' ''',
                int(time.time()), retryNumber + 1, sleeptill, dbstr(toAddress))
            
            print(f"  ✅ Datenbank aktualisiert: {rows_updated} Zeilen geändert")
            if rows_updated <= 0:
                print(f"  ⚠️  WARNUNG: Keine Zeilen aktualisiert!")
                print(f"    Mögliche Ursachen:")
                print(f"    1. Status war nicht 'doingpubkeypow' oder 'awaitingpubkey'")
                print(f"    2. Adresse nicht gefunden")
                print(f"    3. WHERE-Bedingung zu strikt")
        except Exception as e:
            print(f"  ❌ Fehler bei Datenbank Update: {e}")
        
        print("\n📋 PHASE 11: Finale UI Updates")
        try:
            queues.UISignalQueue.put((
                'updateStatusBar', tr._translate(
                    "MainWindow",
                    "Broadcasting the public key request. This program will auto-retry if they are offline.")
            ))
            queues.UISignalQueue.put((
                'updateSentItemStatusByToAddress', (
                    toAddress, tr._translate(
                        "MainWindow",
                        "Sending public key request. Waiting for reply."
                        " Requested at {0}"
                    ).format(l10n.formatTimestamp()))
            ))
            print("  ✅ Finale UI Updates gesendet")
        except Exception as e:
            print(f"  ⚠️  Fehler bei finalen UI Updates: {e}")
        
        print("\n" + "=" * 80)
        print("✅ REQUESTPUBKEY ERFOLGREICH ABGESCHLOSSEN")
        print(f"📨 Getpubkey request gesendet für: {toAddress[:50]}...")
        print(f"🔑 Adresse Version: {addressVersionNumber}")
        print(f"🔄 Stream: {streamNumber}")
        print(f"🔄 Retry Nummer: {retryNumber + 1}")
        print(f"⏰ Gültig bis: {time.ctime(sleeptill)}")
        print("=" * 80)
        
        # Auch debug_print für Datei-Log
        debug_print("REQUESTPUBKEY (Professional Fix) ERFOLGREICH für %s", toAddress)
    def generateFullAckMessage(self, ackdata, TTL):
        """Create ACK packet"""
        debug_print("generateFullAckMessage aufgerufen, TTL: %d", TTL)
        
        # Bucket TTL
        if TTL < 24 * 60 * 60:
            TTL = 24 * 60 * 60
            debug_print("TTL auf 24h gesetzt")
        elif TTL < 7 * 24 * 60 * 60:
            TTL = 7 * 24 * 60 * 60
            debug_print("TTL auf 7 Tage gesetzt")
        else:
            TTL = 28 * 24 * 60 * 60
            debug_print("TTL auf 28 Tage gesetzt")
        
        TTL = int(TTL + helper_random.randomrandrange(-300, 300))
        embeddedTime = int(time.time() + TTL)
        debug_print("Finale TTL: %d, embeddedTime: %d", TTL, embeddedTime)

        payload = pack('>Q', embeddedTime) + ackdata
        debug_print("ACK Payload vor PoW: %d bytes", len(payload))
        
        payload = self._doPOWDefaults(
            payload, TTL, log_prefix='(For ack message)', log_time=True)
        
        if payload is None:
            debug_print("ACK PoW fehlgeschlagen")
            return b''
        
        debug_print("ACK Payload nach PoW: %d bytes", len(payload))
        result = protocol.CreatePacket(b'object', payload)
        debug_print("ACK Packet Länge: %d bytes", len(result))
        return result
