import sys
import logging

from qtpy import QtCore

import queues
from network.node import Peer

# Debugging setup
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class UISignaler(QtCore.QThread):
    """
    Singleton class that handles UI signal dispatching from background threads.
    Receives commands from UISignalQueue and emits corresponding Qt signals.
    """
    _instance = None

    # Define all Qt signals
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
        """
        Singleton access method.
        
        Returns:
            UISignaler: The singleton instance
        """
        if not cls._instance:
            logger.debug("DEBUG: Creating new UISignaler instance")
            cls._instance = UISignaler()
        else:
            logger.debug("DEBUG: Returning existing UISignaler instance")
        return cls._instance

    def run(self):
        """
        Main thread loop that processes commands from UISignalQueue.
        """
        logger.debug("DEBUG: UISignaler thread started")
        while True:
            try:
                command, data = queues.UISignalQueue.get()
                logger.debug(f"DEBUG: Processing command: {command} with data: {data}")
                
                if command == 'writeNewAddressToTable':
                    label, address, streamNumber = data
                    logger.debug(f"DEBUG: Emitting writeNewAddressToTable: {label}, {address}, {streamNumber}")
                    self.writeNewAddressToTable.emit(label, address, str(streamNumber))
                    
                elif command == 'updateStatusBar':
                    logger.debug("DEBUG: Emitting updateStatusBar")
                    self.updateStatusBar.emit(data)
                    
                elif command == 'updateSentItemStatusByToAddress':
                    toAddress, message = data
                    logger.debug(f"DEBUG: Emitting updateSentItemStatusByToAddress: {toAddress}")
                    self.updateSentItemStatusByToAddress.emit(toAddress, message)
                    
                elif command == 'updateSentItemStatusByAckdata':
                    ackData, message = data
                    logger.debug(f"DEBUG: Emitting updateSentItemStatusByAckdata: {ackData}")
                    self.updateSentItemStatusByAckdata.emit(ackData, message)
                    
                elif command == 'displayNewInboxMessage':
                    inventoryHash, toAddress, fromAddress, subject, body = data
                    logger.debug(f"DEBUG: Emitting displayNewInboxMessage: {inventoryHash}")
                    self.displayNewInboxMessage.emit(
                        inventoryHash, toAddress, fromAddress, subject, body)
                    
                elif command == 'displayNewSentMessage':
                    toAddress, fromLabel, fromAddress, subject, message, ackdata = data
                    logger.debug(f"DEBUG: Emitting displayNewSentMessage: {toAddress}")
                    self.displayNewSentMessage.emit(
                        toAddress, fromLabel, fromAddress,
                        subject.decode('utf-8'), message, ackdata)
                    
                elif command == 'updateNetworkStatusTab':
                    outbound, add, destination = data
                    logger.debug(f"DEBUG: Emitting updateNetworkStatusTab: {outbound}, {add}, {destination}")
                    self.updateNetworkStatusTab.emit(outbound, add, destination)
                    
                elif command == 'updateNumberOfMessagesProcessed':
                    logger.debug("DEBUG: Emitting updateNumberOfMessagesProcessed")
                    self.updateNumberOfMessagesProcessed.emit()
                    
                elif command == 'updateNumberOfPubkeysProcessed':
                    logger.debug("DEBUG: Emitting updateNumberOfPubkeysProcessed")
                    self.updateNumberOfPubkeysProcessed.emit()
                    
                elif command == 'updateNumberOfBroadcastsProcessed':
                    logger.debug("DEBUG: Emitting updateNumberOfBroadcastsProcessed")
                    self.updateNumberOfBroadcastsProcessed.emit()
                    
                elif command == 'setStatusIcon':
                    logger.debug(f"DEBUG: Emitting setStatusIcon: {data}")
                    self.setStatusIcon.emit(data)
                    
                elif command == 'changedInboxUnread':
                    logger.debug(f"DEBUG: Emitting changedInboxUnread: {data}")
                    self.changedInboxUnread.emit(data)
                    
                elif command == 'rerenderMessagelistFromLabels':
                    logger.debug("DEBUG: Emitting rerenderMessagelistFromLabels")
                    self.rerenderMessagelistFromLabels.emit()
                    
                elif command == 'rerenderMessagelistToLabels':
                    logger.debug("DEBUG: Emitting rerenderMessagelistToLabels")
                    self.rerenderMessagelistToLabels.emit()
                    
                elif command == 'rerenderAddressBook':
                    logger.debug("DEBUG: Emitting rerenderAddressBook")
                    self.rerenderAddressBook.emit()
                    
                elif command == 'rerenderSubscriptions':
                    logger.debug("DEBUG: Emitting rerenderSubscriptions")
                    self.rerenderSubscriptions.emit()
                    
                elif command == 'rerenderBlackWhiteList':
                    logger.debug("DEBUG: Emitting rerenderBlackWhiteList")
                    self.rerenderBlackWhiteList.emit()
                    
                elif command == 'removeInboxRowByMsgid':
                    logger.debug(f"DEBUG: Emitting removeInboxRowByMsgid: {data}")
                    self.removeInboxRowByMsgid.emit(data)
                    
                elif command == 'newVersionAvailable':
                    logger.debug(f"DEBUG: Emitting newVersionAvailable: {data}")
                    self.newVersionAvailable.emit(data)
                    
                elif command == 'alert':
                    title, text, exitAfterUserClicksOk = data
                    logger.debug(f"DEBUG: Emitting displayAlert: {title}")
                    self.displayAlert.emit(title, text, exitAfterUserClicksOk)
                    
                else:
                    error_msg = f'Command sent to UISignaler not recognized: {command}\n'
                    logger.error(f"DEBUG: {error_msg.strip()}")
                    sys.stderr.write(error_msg)
                    
            except Exception as e:
                logger.error(f"DEBUG: Error processing UI signal: {str(e)}")
                raise
