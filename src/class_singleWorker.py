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

    def _safe_extract(self, value, to_int=False):
        """Safely extract and convert values from database for Python 3"""
        debug_print("_safe_extract: Type des Werts: %s, to_int: %s", type(value), to_int)
        
        if value is None:
            debug_print("_safe_extract: Wert ist None")
            return 0 if to_int else ""
        
        try:
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
        debug_print("============================================================")
        debug_print("SENDMSG - Verarbeite gequeued Nachrichten")
        debug_print("============================================================")
        
        # Reset just in case
        try:
            debug_print("Reset: Setze doing* Nachrichten zurück zu msgqueued")
            reset_count = sqlExecute(
                '''UPDATE sent SET status='msgqueued' '''
                ''' WHERE status IN ('doingpubkeypow', 'doingmsgpow') '''
                ''' AND folder='sent' ''')
            debug_print("Reset %d Nachrichten von doing* zu msgqueued", reset_count)
        except Exception as e:
            debug_print("Fehler beim Reset Status: %s", e)
        
        # DEBUG: Überprüfe alle Status in der Tabelle
        try:
            debug_print("--- DEBUG: Status Übersicht in sent Tabelle ---")
            status_overview = sqlQuery(
                '''SELECT status, COUNT(*) as count FROM sent WHERE folder='sent' GROUP BY status''')
            for status_row in status_overview:
                debug_print("  Status '%s': %d Nachrichten", status_row[0], status_row[1])
        except Exception as e:
            debug_print("Fehler bei Status Überprüfung: %s", e)
        
        queryreturn = sqlQuery(
            '''SELECT toaddress, fromaddress, subject, message, '''
            ''' ackdata, status, ttl, retrynumber, encodingtype FROM '''
            ''' sent WHERE (status='msgqueued' OR status='forcepow' OR status='awaitingpubkey') '''
            ''' and folder='sent' ORDER BY lastactiontime ASC LIMIT 5''')
        
        debug_print("Gefundene Nachrichten zum Verarbeiten: %d (limit 5)", len(queryreturn))
        
        if not queryreturn:
            debug_print("Keine Nachrichten zu verarbeiten")
            return
        
        # while we have a msg that needs some work
        for i, row in enumerate(queryreturn):
            debug_print("--- Verarbeite Nachricht %d/%d ---", i+1, len(queryreturn))
            
            try:
                toaddress, fromaddress, subject, message, \
                    ackdata_raw, status, TTL, retryNumber, encoding = row
                
                debug_print("  Raw-Daten: status=%s, toaddress=%s...", 
                          status, str(toaddress)[:30] if toaddress else "None")
                
                # Safe conversion
                toaddress = self._safe_extract(toaddress)
                fromaddress = self._safe_extract(fromaddress)
                subject = self._safe_extract(subject)
                message = self._safe_extract(message)
                status = self._safe_extract(status)
                TTL = int(TTL) if TTL is not None else 0
                retryNumber = int(retryNumber) if retryNumber is not None else 0
                encoding = int(encoding) if encoding is not None else 0
                
                # Convert ackdata to bytes if needed
                if ackdata_raw is None:
                    ackdata = os.urandom(32)
                    debug_print("  WARNUNG: ackdata war None, generiere neuen")
                elif isinstance(ackdata_raw, str):
                    ackdata = ackdata_raw.encode('latin-1')
                elif isinstance(ackdata_raw, bytes):
                    ackdata = ackdata_raw
                else:
                    ackdata = bytes(ackdata_raw) if ackdata_raw else os.urandom(32)
                
                debug_print("  An: %s...", toaddress[:50] if toaddress else "None")
                debug_print("  Von: %s...", fromaddress[:50] if fromaddress else "None")
                debug_print("  Betreff: %s...", subject[:30] if subject else "None")
                debug_print("  Status: %s, TTL: %d, Retry: %d", status, TTL, retryNumber)
                
                # Check if addresses are valid
                if not toaddress or not fromaddress:
                    debug_print("  FEHLER: Ungültige Adresse")
                    continue
                    
                try:
                    # toStatus
                    _, toAddressVersionNumber, toStreamNumber, toRipe = \
                        decodeAddress(toaddress)
                    # fromStatus, , ,fromRipe
                    _, fromAddressVersionNumber, fromStreamNumber, _ = \
                        decodeAddress(fromaddress)
                        
                    debug_print("  An Version: %d, Stream: %d", toAddressVersionNumber, toStreamNumber)
                    debug_print("  Von Version: %d, Stream: %d", fromAddressVersionNumber, fromStreamNumber)
                except Exception as e:
                    debug_print("  FEHLER beim Decodieren der Adressen: %s", e)
                    continue

                # We may or may not already have the pubkey
                # for this toAddress. Let's check.
                if status == 'forcepow':
                    # if the status of this msg is 'forcepow'
                    # then clearly we have the pubkey already
                    # because the user could not have overridden the message
                    # about the POW being too difficult without knowing
                    # the required difficulty.
                    debug_print("  Status ist 'forcepow' - fahre fort")
                    pass
                elif status == 'doingmsgpow':
                    # We wouldn't have set the status to doingmsgpow
                    # if we didn't already have the pubkey so let's assume
                    # that we have it.
                    debug_print("  Status ist 'doingmsgpow' - bereits in Arbeit")
                    pass
                # If we are sending a message to ourselves or a chan
                # then we won't need an entry in the pubkeys table;
                # we can calculate the needed pubkey using the private keys
                # in our keys.dat file.
                elif config.has_section(toaddress):
                    debug_print("  Sende an sich selbst/chan: %s", toaddress)
                    try:
                        update_result = sqlExecute(
                            '''UPDATE sent SET status='doingmsgpow' '''
                            ''' WHERE toaddress=? AND status='msgqueued' AND folder='sent' ''',
                            toaddress)
                        debug_print("  Update Result: %d Zeilen aktualisiert", update_result)
                        if update_result <= 0:
                            debug_print("  Konnte Status nicht aktualisieren")
                            # Setze Status manuell für weitere Verarbeitung
                            status = 'doingmsgpow'
                        else:
                            status = 'doingmsgpow'
                        debug_print("  Status auf 'doingmsgpow' aktualisiert")
                    except Exception as e:
                        debug_print("  Fehler beim Aktualisieren: %s", e)
                        status = 'doingmsgpow'  # Fortfahren trotz Fehler
                elif status == 'msgqueued':
                    # Let's see if we already have the pubkey in our pubkeys table
                    debug_print("  Prüfe auf existierenden pubkey...")
                    queryreturn_pubkey = sqlQuery(
                        '''SELECT address FROM pubkeys WHERE address=?''',
                        toaddress)
                    
                    # If we have the needed pubkey in the pubkey table already,
                    if queryreturn_pubkey:
                        debug_print("  Pubkey gefunden in Datenbank")
                        # set the status of this msg to doingmsgpow
                        try:
                            update_rows = sqlExecute(
                                '''UPDATE sent SET status='doingmsgpow' '''
                                ''' WHERE toaddress=? AND status='msgqueued' AND folder='sent' ''',
                                toaddress)
                            debug_print("  Update Result: %d Zeilen aktualisiert", update_rows)
                            if update_rows <= 0:
                                debug_print("  Konnte Status nicht aktualisieren, setze manuell")
                                status = 'doingmsgpow'
                            else:
                                status = 'doingmsgpow'
                            debug_print("  Status auf 'doingmsgpow' aktualisiert")
                            # mark the pubkey as 'usedpersonally' so that
                            # we don't delete it later.
                            sqlExecute(
                                '''UPDATE pubkeys SET usedpersonally='yes' '''
                                ''' WHERE address=?''',
                                toaddress)
                        except Exception as e:
                            debug_print("  Fehler beim Aktualisieren: %s", e)
                            status = 'doingmsgpow'  # Fortfahren
                    # We don't have the needed pubkey in the pubkeys table already.
                    else:
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
                            debug_print("  Status auf 'awaitingpubkey' gesetzt")
                            # on with the next msg on which we can do some work
                            continue
                        else:
                            # We have not yet sent a request for the pubkey
                            needToRequestPubkey = True
                            debug_print("  Pubkey noch nicht angefordert")
                            
                            # If we are trying to send to address
                            # version >= 4 then the needed pubkey might be
                            # encrypted in the inventory.
                            if toAddressVersionNumber >= 4:
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
                                        debug_print("  Pubkey aus Inventory dekodiert")
                                        status = 'doingmsgpow'
                                        break
                                        
                            if needToRequestPubkey:
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
                                self.requestPubKey(toaddress)
                                # on with the next msg on which we can do some work
                                continue
                
                # NEU: Behandlung von 'awaitingpubkey' Status
                elif status == 'awaitingpubkey':
                    debug_print("  Status ist 'awaitingpubkey' - prüfe ob Pubkey verfügbar")
                    
                    # Prüfe ob Pubkey jetzt in Datenbank ist
                    queryreturn_pubkey = sqlQuery(
                        '''SELECT address FROM pubkeys WHERE address=?''',
                        toaddress)
                    
                    if queryreturn_pubkey:
                        debug_print("  Pubkey jetzt verfügbar! Aktualisiere Status zu 'doingmsgpow'")
                        try:
                            update_result = sqlExecute(
                                '''UPDATE sent SET status='doingmsgpow' '''
                                ''' WHERE toaddress=? AND status='awaitingpubkey' AND folder='sent' ''',
                                toaddress)
                            debug_print("  Update Result: %d Zeilen aktualisiert", update_result)
                            status = 'doingmsgpow'
                            debug_print("  Status auf 'doingmsgpow' aktualisiert")
                            
                            # Mark pubkey as used
                            sqlExecute(
                                '''UPDATE pubkeys SET usedpersonally='yes' '''
                                ''' WHERE address=?''',
                                toaddress)
                        except Exception as e:
                            debug_print("  Fehler beim Aktualisieren: %s", e)
                            status = 'doingmsgpow'  # Fortfahren
                    else:
                        debug_print("  Pubkey noch nicht verfügbar, überspringe Nachricht")
                        continue

                # At this point we know that we have the necessary pubkey
                # in the pubkeys table.
                debug_print("  Fortfahren mit Nachrichtenverarbeitung...")
                
                # Rest of the code remains exactly as you had it...
                # [Hier kommt der REST deines Codes - unverändert!]
                
                TTL *= 2**retryNumber
                if TTL > 28 * 24 * 60 * 60:
                    TTL = 28 * 24 * 60 * 60
                # add some randomness to the TTL
                TTL = int(TTL + helper_random.randomrandrange(-300, 300))
                embeddedTime = int(time.time() + TTL)
                debug_print("  Original TTL: %d, Finale TTL: %d, embeddedTime: %d", 
                          TTL // (2**retryNumber) if retryNumber > 0 else TTL, TTL, embeddedTime)

                # if we aren't sending this to ourselves or a chan
                if not config.has_section(toaddress):
                    state.ackdataForWhichImWatching[ackdata] = 0
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata,
                            tr._translate(
                                "MainWindow",
                                "Looking up the receiver\'s public key"))
                    ))
                    debug_print('Sending a message.')
                    debug_print(
                        'First 150 characters of message: %s',
                        repr(message[:150])
                    )

                    # Let us fetch the recipient's public key out of
                    # our database.
                    queryreturn_pubkey = sqlQuery(
                        'SELECT transmitdata FROM pubkeys WHERE address=?',
                        toaddress)
                    
                    if not queryreturn_pubkey:
                        debug_print("  FEHLER: Kein pubkey in Datenbank für %s", toaddress)
                        continue
                    
                    for row in queryreturn_pubkey:
                        pubkeyPayload, = row

                    # to bypass the address version whose length is definitely 1
                    readPosition = 1
                    _, streamNumberLength = decodeVarint(
                        pubkeyPayload[readPosition:readPosition + 10])
                    readPosition += streamNumberLength
                    behaviorBitfield = pubkeyPayload[readPosition:readPosition + 4]
                    
                    # if receiver is a mobile device who expects that their
                    # address RIPE is included unencrypted on the front of
                    # the message..
                    if protocol.isBitSetWithinBitfield(behaviorBitfield, 30):
                        # if we are Not willing to include the receiver's
                        # RIPE hash on the message..
                        if not config.safeGetBoolean(
                                'bitmessagesettings', 'willinglysendtomobile'
                        ):
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
                    debug_print('Sending a message to self/chan.')
                    debug_print(
                        'First 150 characters of message: %r', message[:150])
                    behaviorBitfield = protocol.getBitfield(fromaddress)

                    try:
                        privEncryptionKeyBase58 = config.get(
                            toaddress, 'privencryptionkey')
                    except (configparser.NoSectionError, configparser.NoOptionError) as err:
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
                except ValueError:
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
                    else:
                        payload += encodeVarint(config.getint(
                            fromaddress, 'noncetrialsperbyte'))
                        payload += encodeVarint(config.getint(
                            fromaddress, 'payloadlengthextrabytes'))

                # This hash will be checked by the receiver of the message
                # to verify that toRipe belongs to them.
                payload += toRipe
                payload += encodeVarint(encoding)  # message encoding type
                encodedMessage = helper_msgcoding.MsgEncode(
                    {"subject": subject, "body": message}, encoding
                )
                payload += encodeVarint(encodedMessage.length)
                payload += encodedMessage.data
                if config.has_section(toaddress):
                    debug_print(
                        'Not bothering to include ackdata because we are'
                        ' sending to ourselves or a chan.'
                    )
                    fullAckPayload = b''
                elif not protocol.checkBitfield(
                        behaviorBitfield, protocol.BITFIELD_DOESACK):
                    debug_print(
                        'Not bothering to include ackdata because'
                        ' the receiver said that they won\'t relay it anyway.'
                    )
                    fullAckPayload = b''
                else:
                    # The fullAckPayload is a normal msg protocol message
                    # with the proof of work already completed
                    fullAckPayload = self.generateFullAckMessage(
                        ackdata, toStreamNumber, TTL)
                payload += encodeVarint(len(fullAckPayload))
                payload += fullAckPayload
                
                # Python3: Ensure bytes for dataToSign
                dataToSign = pack('>Q', embeddedTime) + b'\x00\x00\x00\x02' + \
                    encodeVarint(1) + encodeVarint(toStreamNumber) + payload
                    
                signature = highlevelcrypto.sign(
                    dataToSign, privSigningKeyHex, self.digestAlg)
                payload += encodeVarint(len(signature))
                payload += signature

                # We have assembled the data that will be encrypted.
                try:
                    encrypted = highlevelcrypto.encrypt(
                        payload, "04" + hexlify(pubEncryptionKeyBase256).decode('utf-8')
                    )
                except Exception as e:
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

                encryptedPayload = self._doPOWDefaults(
                    encryptedPayload, TTL,
                    requiredAverageProofOfWorkNonceTrialsPerByte,
                    requiredPayloadLengthExtraBytes,
                    log_prefix='(For msg message)', log_time=True
                )

                if encryptedPayload is None:
                    debug_print("  PoW fehlgeschlagen")
                    continue

                # Sanity check
                if len(encryptedPayload) > 2 ** 18:
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
                    
                if config.has_section(toaddress) or \
                   not protocol.checkBitfield(behaviorBitfield, protocol.BITFIELD_DOESACK):
                    queues.UISignalQueue.put((
                        'updateSentItemStatusByAckdata', (
                            ackdata,
                            tr._translate(
                                "MainWindow",
                                "Message sent. Sent at %1"
                            ).arg(l10n.formatTimestamp()))))
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
                    
                debug_print(
                    'Broadcasting inv for my msg(within sendmsg function): %s',
                    hexlify(inventoryHash).decode('utf-8')
                )
                invQueue.put((toStreamNumber, inventoryHash))

                # Update the sent message in the sent table
                if config.has_section(toaddress) or \
                   not protocol.checkBitfield(behaviorBitfield, protocol.BITFIELD_DOESACK):
                    newStatus = 'msgsentnoackexpected'
                else:
                    newStatus = 'msgsent'
                # wait 10% past expiration
                sleepTill = int(time.time() + TTL * 1.1)
                sqlExecute(
                    '''UPDATE sent SET msgid=?, status=?, retrynumber=?, '''
                    ''' sleeptill=?, lastactiontime=? WHERE ackdata=? AND folder='sent' ''',
                    sqlite3.Binary(inventoryHash), newStatus, retryNumber + 1,
                    sleepTill, int(time.time()), sqlite3.Binary(ackdata)
                )

                # If we are sending to ourselves or a chan, put in inbox
                if config.has_section(toaddress):
                    sigHash = highlevelcrypto.double_sha512(signature)[32:]
                    t = (inventoryHash, toaddress, fromaddress, subject, int(
                        time.time()), message, 'inbox', encoding, 0, sigHash)
                    helper_inbox.insert(t)

                    queues.UISignalQueue.put(('displayNewInboxMessage', (
                        inventoryHash, toaddress, fromaddress, subject, message)))

                debug_print("  Nachricht %d erfolgreich gesendet", i+1)
                
            except Exception as e:
                debug_print("Fehler beim Verarbeiten von Nachricht row %d: %s", i, e)
                import traceback
                traceback.print_exc()
                continue
        
        debug_print("Nachrichten Verarbeitung abgeschlossen")
    def requestPubKey(self, toAddress):
        """Send a getpubkey object - PROFESSIONAL FIX BASED ON PYTHON2"""
        debug_print("=" * 60)
        debug_print("REQUESTPUBKEY (PROFESSIONAL FIX) - Start für: %s", toAddress)
        debug_print("=" * 60)
        
        # 1. EXAKT wie Python2: Adresse dekodieren
        toStatus, addressVersionNumber, streamNumber, ripe = decodeAddress(toAddress)
        if toStatus != 'success':
            debug_print('Ungültige Adresse: %s', toAddress)
            return

        # 2. PROFESSIONELLER ANSATZ: Mehrere Abfrage-Strategien
        debug_print("PROFESSIONAL FIX: Verwende mehrere Query-Strategien...")
        
        retryNumber = 0
        found = False
        
        # Strategie 1: Exakt wie Python2 (mit dbstr)
        debug_print("Strategie 1: Original Python2 Query (mit dbstr)...")
        queryReturn = sqlQuery(
            '''SELECT retrynumber FROM sent WHERE toaddress=? '''
            ''' AND (status='doingpubkeypow' OR status='awaitingpubkey') '''
            ''' AND folder='sent' LIMIT 1''',
            dbstr(toAddress))  # ← WICHTIG: dbstr() wie in Python2!
        
        if queryReturn:
            retryNumber = queryReturn[0][0]
            found = True
            debug_print("  ✓ Strategie 1 erfolgreich, retryNumber: %d", retryNumber)
        
        # Strategie 2: Ohne Status-Bedingung (falls Status noch msgqueued ist)
        if not found:
            debug_print("Strategie 2: Query OHNE Status-Bedingung...")
            queryReturn = sqlQuery(
                '''SELECT retrynumber FROM sent WHERE toaddress=? '''
                ''' AND folder='sent' LIMIT 1''',
                dbstr(toAddress))
            
            if queryReturn:
                retryNumber = queryReturn[0][0]
                found = True
                debug_print("  ✓ Strategie 2 erfolgreich, retryNumber: %d", retryNumber)
                
                # Status prüfen und korrigieren falls nötig
                status_query = sqlQuery(
                    '''SELECT status FROM sent WHERE toaddress=? AND folder='sent' LIMIT 1''',
                    dbstr(toAddress))
                if status_query:
                    current_status = status_query[0][0]
                    debug_print("  Aktueller Status: '%s'", current_status)
                    
                    if current_status == 'msgqueued':
                        debug_print("  Status ist 'msgqueued', korrigiere zu 'doingpubkeypow'...")
                        sqlExecute(
                            '''UPDATE sent SET status='doingpubkeypow' '''
                            ''' WHERE toaddress=? AND folder='sent' ''',
                            dbstr(toAddress))
        
        # Strategie 3: Direkte Suche in allen sent Einträgen
        if not found:
            debug_print("Strategie 3: Manuelle Suche in allen sent Einträgen...")
            all_entries = sqlQuery('''SELECT toaddress, retrynumber, status FROM sent WHERE folder='sent' ''')
            
            debug_print("  Durchsuche %d Einträge...", len(all_entries))
            
            for addr_in_db, retry, status in all_entries:
                # Konvertiere bytes zu string falls nötig
                if isinstance(addr_in_db, bytes):
                    addr_in_db = addr_in_db.decode('utf-8', 'replace')
                
                if addr_in_db.strip() == toAddress.strip():
                    retryNumber = retry if retry is not None else 0
                    found = True
                    debug_print("  ✓ Manuell gefunden: addr='%s', retry=%d, status='%s'", 
                              addr_in_db[:30], retryNumber, status)
                    
                    # Status korrigieren falls nötig
                    if status == 'msgqueued':
                        debug_print("  Korrigiere Status von 'msgqueued' zu 'doingpubkeypow'...")
                        sqlExecute(
                            '''UPDATE sent SET status='doingpubkeypow' '''
                            ''' WHERE toaddress=? AND folder='sent' ''',
                            dbstr(toAddress))
                    break
        
        if not found:
            debug_print("✗ KRITISCHER FEHLER: Kein Eintrag für %s gefunden!", toAddress)
            debug_print("  Nachricht scheint nicht in der Datenbank zu existieren!")
            debug_print("  sendMsg() muss die Nachricht zuerst in 'sent' Tabelle speichern!")
            return

        # 3. Ab hier EXAKTE Python2-Logik (angepasst für Debug)
        debug_print("Phase 2: Verarbeite Adresse mit retryNumber=%d...", retryNumber)
        
        if addressVersionNumber <= 3:
            state.neededPubkeys[toAddress] = 0
            debug_print("V3 oder früher, füge zu neededPubkeys hinzu")
        elif addressVersionNumber >= 4:
            # Python2-Logik: Tag generieren und zu neededPubkeys hinzufügen
            doubleHashOfAddressData = highlevelcrypto.double_sha512(
                encodeVarint(addressVersionNumber)
                + encodeVarint(streamNumber) + ripe
            )
            privEncryptionKey = doubleHashOfAddressData[:32]
            # Note that this is the second half of the sha512 hash.
            tag = doubleHashOfAddressData[32:]
            tag_bytes = bytes(tag)
            
            if tag_bytes not in state.neededPubkeys:
                state.neededPubkeys[tag_bytes] = (
                    toAddress,
                    highlevelcrypto.makeCryptor(hexlify(privEncryptionKey))
                )
                debug_print("V4, füge tag zu neededPubkeys hinzu: %s...", hexlify(tag_bytes)[:20])
            else:
                debug_print("Tag bereits in neededPubkeys vorhanden")

        # 4. TTL Berechnung (exakt wie Python2)
        TTL = 2.5 * 24 * 60 * 60
        TTL *= 2 ** retryNumber
        if TTL > 28 * 24 * 60 * 60:
            TTL = 28 * 24 * 60 * 60
        TTL = TTL + helper_random.randomrandrange(-300, 300)
        embeddedTime = int(time.time() + TTL)
        debug_print("TTL: %d, embeddedTime: %d", TTL, embeddedTime)
        
        # 5. Payload erstellen (exakt wie Python2)
        payload = pack('>Q', embeddedTime)
        payload += b'\x00\x00\x00\x00'  # object type: getpubkey
        payload += encodeVarint(addressVersionNumber)
        payload += encodeVarint(streamNumber)
        
        if addressVersionNumber <= 3:
            payload += ripe
            debug_print('Fordere pubkey an mit ripe: %s', hexlify(ripe)[:20])
        else:
            payload += tag
            debug_print('Fordere v4 pubkey an mit tag: %s', hexlify(tag)[:20])

        # 6. UI Updates (angepasst mit Debug)
        queues.UISignalQueue.put(('updateStatusBar', 
            'Doing the computations necessary to request the recipient\'s public key.'))
        queues.UISignalQueue.put((
            'updateSentItemStatusByToAddress', (
                toAddress, tr._translate(
                    "MainWindow",
                    "Doing work necessary to request encryption key."))
        ))
        debug_print("UI aktualisiert")

        # 7. PoW durchführen (wie Python2)
        debug_print("Starte PoW für getpubkey request...")
        payload = self._doPOWDefaults(payload, TTL, log_prefix='(For getpubkey)')
        if payload is None:
            debug_print("PoW fehlgeschlagen für getpubkey request")
            return

        # 8. Inventory erstellen (wie Python2)
        inventoryHash = highlevelcrypto.calculateInventoryHash(payload)
        objectType = 1
        state.Inventory[inventoryHash] = (
            objectType, streamNumber, payload, embeddedTime, b'')
        debug_print("Inventory Hash: %s", hexlify(inventoryHash))
        
        debug_print('Sende getpubkey request: %s...', hexlify(inventoryHash)[:32])
        invQueue.put((streamNumber, inventoryHash))

        # 9. Datenbank aktualisieren (EXAKT wie Python2)
        sleeptill = int(time.time() + TTL * 1.1)
        sqlExecute(
            '''UPDATE sent SET lastactiontime=?, '''
            ''' status='awaitingpubkey', retrynumber=?, sleeptill=? '''
            ''' WHERE toaddress=? AND (status='doingpubkeypow' OR '''
            ''' status='awaitingpubkey') AND folder='sent' ''',
            int(time.time()), retryNumber + 1, sleeptill, dbstr(toAddress))  # ← dbstr()!
        
        debug_print("Datenbank aktualisiert (awaitingpubkey)")

        # 10. Finale UI Updates (wie Python2)
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
        
        debug_print("REQUESTPUBKEY (Professional Fix) ERFOLGREICH für %s", toAddress)
        debug_print("=" * 60)
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
