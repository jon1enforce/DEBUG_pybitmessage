import sys
import logging
from qtpy import QtCore
import queues
from network.node import Peer
from binascii import hexlify  # Wichtig für sendOutOrStoreMyV4Pubkey
from helper_sql import safe_decode

logger = logging.getLogger(__name__)

class UISignaler(QtCore.QThread):
    _instance = None

    # 1:1 Signal definitions from original
    writeNewAddressToTable = QtCore.Signal(str, str, str)
    updateStatusBar = QtCore.Signal(object)
    updateSentItemStatusByToAddress = QtCore.Signal(object, str)
    updateSentItemStatusByAckdata = QtCore.Signal(object, str)
    displayNewInboxMessage = QtCore.Signal(object, str, object, object, str)
    displayNewSentMessage = QtCore.Signal(object, str, str, object, object, str)
    updateNetworkStatusTab = QtCore.Signal(bool, bool, Peer)
    updateNumberOfMessagesProcessed = QtCore.Signal()
    updateNumberOfPubkeysProcessed = QtCore.Signal()
    updateNumberOfBroadcastsProcessed = QtCore.Signal()
    setStatusIcon = QtCore.Signal(str)
    changedInboxUnread = QtCore.Signal(str)
    rerenderMessagelistFromLabels = QtCore.Signal()
    rerenderMessagelistToLabels = QtCore.Signal()
    rerenderAddressBook = QtCore.Signal()
    rerenderSubscriptions = QtCore.Signal()
    rerenderBlackWhiteList = QtCore.Signal()
    removeInboxRowByMsgid = QtCore.Signal(str)
    newVersionAvailable = QtCore.Signal(str)
    displayAlert = QtCore.Signal(str, str, bool)

    @classmethod
    def get(cls):
        if not cls._instance:
            cls._instance = UISignaler()
        return cls._instance

    def run(self):
        logger.debug("UISignaler thread started")
        while True:
            try:
                item = queues.UISignalQueue.get()
                
                # Behalte die originale strikte 2-Wert Erwartung bei
                if not isinstance(item, tuple) or len(item) != 2:
                    logger.error("Invalid queue item format - expected (command, data) tuple")
                    continue
                    
                command, data = item
                logger.debug("Processing command: %s", command)

                # Originale Befehlsverarbeitung 1:1
                if command == 'writeNewAddressToTable':
                    label, address, streamNumber = data
                    self.writeNewAddressToTable.emit(label, address, str(streamNumber))
                elif command == 'updateStatusBar':
                    self.updateStatusBar.emit(data)
                elif command == 'updateSentItemStatusByToAddress':
                    toAddress, message = data
                    self.updateSentItemStatusByToAddress.emit(toAddress, message)
                elif command == 'updateSentItemStatusByAckdata':
                    ackData, message = data
                    self.updateSentItemStatusByAckdata.emit(ackData, message)
                elif command == 'displayNewInboxMessage':
                    inventoryHash, toAddress, fromAddress, subject, body = data
                    self.displayNewInboxMessage.emit(inventoryHash, toAddress, fromAddress, subject, body)
                elif command == 'displayNewSentMessage':
                    toAddress, fromLabel, fromAddress, subject, message, ackdata = data
                    self.displayNewSentMessage.emit(
                        toAddress, fromLabel, fromAddress,
                        safe_decode(subject, "utf-8"), message, ackdata)
                elif command == 'updateNetworkStatusTab':
                    outbound, add, destination = data
                    self.updateNetworkStatusTab.emit(outbound, add, destination)
                elif command == 'updateNumberOfMessagesProcessed':
                    self.updateNumberOfMessagesProcessed.emit()
                elif command == 'updateNumberOfPubkeysProcessed':
                    self.updateNumberOfPubkeysProcessed.emit()
                elif command == 'updateNumberOfBroadcastsProcessed':
                    self.updateNumberOfBroadcastsProcessed.emit()
                elif command == 'setStatusIcon':
                    self.setStatusIcon.emit(data)
                elif command == 'changedInboxUnread':
                    self.changedInboxUnread.emit(data)
                elif command == 'rerenderMessagelistFromLabels':
                    self.rerenderMessagelistFromLabels.emit()
                elif command == 'rerenderMessagelistToLabels':
                    self.rerenderMessagelistToLabels.emit()
                elif command == 'rerenderAddressBook':
                    self.rerenderAddressBook.emit()
                elif command == 'rerenderSubscriptions':
                    self.rerenderSubscriptions.emit()
                elif command == 'rerenderBlackWhiteList':
                    self.rerenderBlackWhiteList.emit()
                elif command == 'removeInboxRowByMsgid':
                    self.removeInboxRowByMsgid.emit(data)
                elif command == 'newVersionAvailable':
                    self.newVersionAvailable.emit(data)
                elif command == 'alert':
                    title, text, exitAfterUserClicksOk = data
                    self.displayAlert.emit(title, text, exitAfterUserClicksOk)
                else:
                    logger.error("Unknown command: %s", command)
                    sys.stderr.write('Command sent to UISignaler not recognized: %s\n' % command)

            except Exception as e:
                logger.critical("UISignaler error: %s", traceback.format_exc())
                # Originales Verhalten beibehalten (kein sleep)
                continue
