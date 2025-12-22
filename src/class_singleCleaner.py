"""
The `singleCleaner` class is a timer-driven thread that cleans data structures
to free memory, resends messages when a remote node doesn't respond, and
sends pong messages to keep connections alive if the network isn't busy.

It cleans these data structures in memory:
  - inventory (moves data to the on-disk sql database)
  - inventorySets (clears then reloads data out of sql database)

It cleans these tables on the disk:
  - inventory (clears expired objects)
  - pubkeys (clears pubkeys older than 4 weeks old which we have not used
    personally)
  - knownNodes (clears addresses which have not been online for over 3 days)

It resends messages when there has been no response:
  - resends getpubkey messages in 5 days (then 10 days, then 20 days, etc...)
  - resends msg messages in 5 days (then 10 days, then 20 days, etc...)

"""

import gc
import os
import time
import sqlite3
import traceback

import queues
import state
from bmconfigparser import config
from helper_sql import sqlExecute, sqlQuery
from network import connectionpool, knownnodes, StoppableThread
from tr import _translate
from dbcompat import dbstr
from helper_sql import safe_decode


#: Equals 4 weeks. You could make this longer if you want
#: but making it shorter would not be advisable because
#: there is a very small possibility that it could keep you
#: from obtaining a needed pubkey for a period of time.
lengthOfTimeToHoldOnToAllPubkeys = 2419200


class singleCleaner(StoppableThread):
    """The singleCleaner thread class"""
    name = "singleCleaner"
    cycleLength = 300
    expireDiscoveredPeers = 300

    def run(self):  # pylint: disable=too-many-branches
        gc.disable()
        timeWeLastClearedInventoryAndPubkeysTables = 0
        try:
            print("DEBUG: singleCleaner thread started")
            print("DEBUG: Loading maximumLengthOfTimeToBotherResendingMessages from config")
            state.maximumLengthOfTimeToBotherResendingMessages = (
                config.getfloat(
                    'bitmessagesettings', 'stopresendingafterxdays')
                * 24 * 60 * 60
            ) + (
                config.getfloat(
                    'bitmessagesettings', 'stopresendingafterxmonths')
                * (60 * 60 * 24 * 365) / 12)
            print(f"DEBUG: maximumLengthOfTimeToBotherResendingMessages set to {state.maximumLengthOfTimeToBotherResendingMessages}")
        except Exception as e:  # noqa:E722
            print(f"DEBUG: Error loading resend timing config: {str(e)}")
            print("DEBUG: Using default infinite value for maximumLengthOfTimeToBotherResendingMessages")
            # Either the user hasn't set stopresendingafterxdays and
            # stopresendingafterxmonths yet or the options are missing
            # from the config file.
            state.maximumLengthOfTimeToBotherResendingMessages = float('inf')

        while state.shutdown == 0:
            print("DEBUG: singleCleaner cycle starting")
            self.stop.wait(self.cycleLength)
            print("DEBUG: Flushing inventory to disk")
            queues.UISignalQueue.put((
                'updateStatusBar',
                'Doing housekeeping (Flushing inventory in memory to disk...)'
            ))
            state.Inventory.flush()
            queues.UISignalQueue.put(('updateStatusBar', ''))

            # If we are running as a daemon then we are going to fill up the UI
            # queue which will never be handled by a UI. We should clear it to
            # save memory.
            # FIXME redundant?
            if state.thisapp.daemon or not state.enableGUI:
                print("DEBUG: Clearing UISignalQueue as running in daemon mode or GUI disabled")
                queues.UISignalQueue.queue.clear()

            tick = int(time.time())
            if timeWeLastClearedInventoryAndPubkeysTables < tick - 7380:
                print("DEBUG: Cleaning inventory and pubkeys tables")
                timeWeLastClearedInventoryAndPubkeysTables = tick
                state.Inventory.clean()
                queues.workerQueue.put(('sendOnionPeerObj', ''))
                # pubkeys
                sqlExecute(
                    "DELETE FROM pubkeys WHERE time<? AND usedpersonally='no'",
                    tick - lengthOfTimeToHoldOnToAllPubkeys)

                # Let us resend getpubkey objects if we have not yet heard
                # a pubkey, and also msg objects if we have not yet heard
                # an acknowledgement
                queryreturn = sqlQuery(
                    "SELECT toaddress, ackdata, status FROM sent"
                    " WHERE ((status='awaitingpubkey' OR status='msgsent')"
                    " AND folder='sent' AND sleeptill<? AND senttime>?)",
                    tick,
                    tick - state.maximumLengthOfTimeToBotherResendingMessages
                )
                print(f"DEBUG: Found {len(queryreturn)} messages to potentially resend")
                for toAddress, ackData, status in queryreturn:
                    toAddress = safe_decode(toAddress, "utf-8", "replace")
                    status = safe_decode(status, "utf-8", "replace")
                    print(f"DEBUG: Processing message - toAddress: {toAddress}, status: {status}")
                    if status == 'awaitingpubkey':
                        print("DEBUG: Resending pubkey request")
                        self.resendPubkeyRequest(toAddress)
                    elif status == 'msgsent':
                        print("DEBUG: Resending message")
                        self.resendMsg(ackData)

            try:
                # Cleanup knownnodes and handle possible severe exception
                # while writing it to disk
                if state.enableNetwork:
                    print("DEBUG: Cleaning up known nodes")
                    knownnodes.cleanupKnownNodes(connectionpool.pool)
            except Exception as err:
                print(f"DEBUG: Error in knownnodes cleanup: {str(err)}")
                if "Errno 28" in str(err):
                    print("DEBUG: Disk full error detected")
                    self.logger.fatal(
                        '(while writing knownnodes to disk)'
                        ' Alert: Your disk or data storage volume is full.'
                    )
                    queues.UISignalQueue.put((
                        'alert',
                        (_translate("MainWindow", "Disk full"),
                         _translate(
                             "MainWindow",
                             'Alert: Your disk or data storage volume'
                             ' is full. Bitmessage will now exit.'),
                         True)
                    ))
                    # FIXME redundant?
                    if state.thisapp.daemon or not state.enableGUI:
                        print("DEBUG: Exiting due to disk full")
                        os._exit(1)  # pylint: disable=protected-access

            # inv/object tracking
            print("DEBUG: Cleaning connections")
            for connection in connectionpool.pool.connections():
                connection.clean()

            # discovery tracking - KORREKTUR: Dictionary changed size during iteration
            print("DEBUG: Cleaning discovered peers")
            self.cleanDiscoveredPeers()
            
            # ..todo:: cleanup pending upload / download

            print("DEBUG: Running garbage collection")
            gc.collect()
            print("DEBUG: singleCleaner cycle completed")

    def cleanDiscoveredPeers(self):
        """Clean up discovered peers"""
        try:
            exp = int(time.time()) - 2 * 60 * 60  # 2 hours
            # PYTHON 3 KOMPATIBILITÄT: Erstelle zuerst eine Liste, dann filtere
            peers_to_remove = []
            for k, v in list(state.discoveredPeers.items()):  # list() macht Kopie
                if v < exp:
                    peers_to_remove.append(k)
            
            # Jetzt entfernen
            for k in peers_to_remove:
                try:
                    del state.discoveredPeers[k]
                except KeyError:
                    pass
                    
            print(f"DEBUG: Cleaned up {len(peers_to_remove)} discovered peer(s)")
        except Exception as e:
            print(f"DEBUG: Error cleaning discovered peers: {str(e)}")

    def resendPubkeyRequest(self, address):
        """Resend pubkey request for address"""
        print(f"DEBUG: Resending pubkey request for address: {address}")
        self.logger.debug(
            'It has been a long time and we haven\'t heard a response to our'
            ' getpubkey request. Sending again.'
        )
        try:
            print(f"DEBUG: Removing address {address} from neededPubkeys")
            # We need to take this entry out of the neededPubkeys structure
            # because the queues.workerQueue checks to see whether the entry
            # is already present and will not do the POW and send the message
            # because it assumes that it has already done it recently.
            del state.neededPubkeys[address]
        except KeyError:
            print(f"DEBUG: Address {address} not found in neededPubkeys")
            pass
        except RuntimeError:
            print(f"DEBUG: RuntimeError while removing {address} from neededPubkeys")
            self.logger.warning(
                "Can't remove %s from neededPubkeys, requesting pubkey will be delayed", address, exc_info=True)

        queues.UISignalQueue.put((
            'updateStatusBar',
            'Doing work necessary to again attempt to request a public key...'
        ))
        print(f"DEBUG: Updating sent table for address {address}")
        sqlExecute(
            "UPDATE sent SET status = 'msgqueued'"
            " WHERE toaddress = ? AND folder = 'sent'", dbstr(address))
        queues.workerQueue.put(('sendmessage', ''))
        print("DEBUG: Pubkey request resent successfully")

    def resendMsg(self, ackdata):
        """Resend message by ackdata"""
        print(f"DEBUG: Resending message with ackdata: {ackdata}")
        self.logger.debug(
            'It has been a long time and we haven\'t heard an acknowledgement'
            ' to our msg. Sending again.'
        )
        print("DEBUG: Updating sent table with binary ackdata")
        rowcount = sqlExecute(
            "UPDATE sent SET status = 'msgqueued'"
            " WHERE ackdata = ? AND folder = 'sent'", sqlite3.Binary(ackdata))
        if rowcount < 1:
            print("DEBUG: Trying with text ackdata as binary didn't match")
            sqlExecute(
                "UPDATE sent SET status = 'msgqueued'"
                " WHERE ackdata = CAST(? AS TEXT) AND folder = 'sent'", ackdata)
        queues.workerQueue.put(('sendmessage', ''))
        queues.UISignalQueue.put((
            'updateStatusBar',
            'Doing work necessary to again attempt to deliver a message...'
        ))
        print("DEBUG: Message resent successfully")
