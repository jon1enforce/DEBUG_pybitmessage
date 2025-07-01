"""
NewChanDialog class definition
"""

from unqstr import ustr, unic
from qtpy import QtCore, QtWidgets

from bitmessageqt import widgets
from addresses import addBMIfNotPresent
from .addressvalidator import AddressValidator, PassPhraseValidator
from queues import (
    addressGeneratorQueue, apiAddressGeneratorReturnQueue, UISignalQueue)
from tr import _translate
from .utils import str_chan


class NewChanDialog(QtWidgets.QDialog):
    """The "New Chan" dialog"""
    def __init__(self, parent=None):
        print("DEBUG: [NewChanDialog.__init__] Initializing NewChanDialog")
        super(NewChanDialog, self).__init__(parent)
        
        try:
            print("DEBUG: [NewChanDialog.__init__] Loading UI file")
            widgets.load('newchandialog.ui', self)
            self.parent = parent
            
            print("DEBUG: [NewChanDialog.__init__] Setting up validators")
            self.chanAddress.setValidator(AddressValidator(
                self.chanAddress, self.chanPassPhrase, self.validatorFeedback,
                self.buttonBox.button(QtWidgets.QDialogButtonBox.Ok), False))
            self.chanPassPhrase.setValidator(PassPhraseValidator(
                self.chanPassPhrase, self.chanAddress, self.validatorFeedback,
                self.buttonBox.button(QtWidgets.QDialogButtonBox.Ok), False))

            print("DEBUG: [NewChanDialog.__init__] Setting up timer")
            self.timer = QtCore.QTimer()
            self.timer.timeout.connect(self.delayedUpdateStatus)
            self.timer.start(500)  # milliseconds
            
            self.setAttribute(QtCore.Qt.WA_DeleteOnClose)
            print("DEBUG: [NewChanDialog.__init__] Showing dialog")
            self.show()
            
        except Exception as e:
            print(f"DEBUG: [NewChanDialog.__init__] Error during initialization: {e}")
            raise

    def delayedUpdateStatus(self):
        """Related to updating the UI for the chan passphrase validity"""
        print("DEBUG: [NewChanDialog.delayedUpdateStatus] Checking passphrase queue")
        try:
            self.chanPassPhrase.validator().checkQueue()
        except Exception as e:
            print(f"DEBUG: [NewChanDialog.delayedUpdateStatus] Error checking queue: {e}")

    def accept(self):
        """Proceed in joining the chan"""
        print("DEBUG: [NewChanDialog.accept] Accept triggered")
        self.timer.stop()
        self.hide()
        
        try:
            apiAddressGeneratorReturnQueue.queue.clear()
            chan_address = ustr(self.chanAddress.text())
            chan_passphrase = ustr(self.chanPassPhrase.text())
            
            if chan_address == "":
                print("DEBUG: [NewChanDialog.accept] Creating new chan")
                addressGeneratorQueue.put(
                    ('createChan', 4, 1, str_chan + ' ' + chan_passphrase,
                     chan_passphrase.encode("utf-8", "replace"),
                     True))
            else:
                print(f"DEBUG: [NewChanDialog.accept] Joining existing chan: {chan_address}")
                addressGeneratorQueue.put(
                    ('joinChan', addBMIfNotPresent(chan_address),
                    str_chan + ' ' + chan_passphrase,
                    chan_passphrase.encode("utf-8", "replace"),
                    True))
            
            print("DEBUG: [NewChanDialog.accept] Waiting for address generation response")
            addressGeneratorReturnValue = apiAddressGeneratorReturnQueue.get(True)
            
            if len(addressGeneratorReturnValue) > 0 and addressGeneratorReturnValue[0] != 'chan name does not match address':
                success_msg = _translate(
                    "newchandialog", 
                    "Successfully created / joined chan {0}"
                ).format(unic(chan_passphrase))
                print(f"DEBUG: [NewChanDialog.accept] Success: {success_msg}")
                UISignalQueue.put(('updateStatusBar', success_msg))
                self.parent.ui.tabWidget.setCurrentIndex(
                    self.parent.ui.tabWidget.indexOf(self.parent.ui.chans)
                )
                self.done(QtWidgets.QDialog.Accepted)
            else:
                error_msg = _translate("newchandialog", "Chan creation / joining failed")
                print(f"DEBUG: [NewChanDialog.accept] Failure: {error_msg}")
                UISignalQueue.put(('updateStatusBar', error_msg))
                self.done(QtWidgets.QDialog.Rejected)
                
        except Exception as e:
            print(f"DEBUG: [NewChanDialog.accept] Error during accept: {e}")
            UISignalQueue.put((
                'updateStatusBar',
                _translate("newchandialog", "Error during chan operation")
            ))
            self.done(QtWidgets.QDialog.Rejected)
            raise

    def reject(self):
        """Cancel joining the chan"""
        print("DEBUG: [NewChanDialog.reject] Reject triggered")
        self.timer.stop()
        self.hide()
        try:
            cancel_msg = _translate("newchandialog", "Chan creation / joining cancelled")
            print(f"DEBUG: [NewChanDialog.reject] {cancel_msg}")
            UISignalQueue.put(('updateStatusBar', cancel_msg))
            self.done(QtWidgets.QDialog.Rejected)
        except Exception as e:
            print(f"DEBUG: [NewChanDialog.reject] Error during reject: {e}")
            raise
