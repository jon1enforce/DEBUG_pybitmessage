"""
Dialogs that work with BM address.
"""
# pylint: disable=too-few-public-methods
# https://github.com/PyCQA/pylint/issues/471

import hashlib
import logging

from unqstr import ustr, unic
from qtpy import QtGui, QtWidgets

import queues
from bitmessageqt import widgets
import state
from .account import (
    GatewayAccount, MailchuckAccount, AccountMixin, accountClass
)
from addresses import addBMIfNotPresent, decodeAddress, encodeVarint
from bmconfigparser import config as global_config
from tr import _translate

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class AddressCheckMixin(object):
    """Base address validation class for Qt UI"""

    def _setup(self):
        """Initialize the address validation setup"""
        logger.debug("DEBUG: Setting up AddressCheckMixin")
        self.valid = False
        self.lineEditAddress.textChanged.connect(self.addressChanged)
        logger.debug("DEBUG: Connected addressChanged signal")

    def _onSuccess(self, addressVersion, streamNumber, ripe):
        """Callback for successful address validation"""
        logger.debug(
            f"DEBUG: Address validation success - Version: {addressVersion}, "
            f"Stream: {streamNumber}, RIPE: {ripe[:8]}..."
        )
        pass

    def addressChanged(self, address):
        """
        Address validation callback, performs validation and gives feedback
        """
        logger.debug(f"DEBUG: Address changed: {address}")
        status, addressVersion, streamNumber, ripe = decodeAddress(ustr(address))
        logger.debug(f"DEBUG: Decode result - Status: {status}")
        
        self.valid = status == 'success'
        if self.valid:
            logger.debug("DEBUG: Address is valid")
            self.labelAddressCheck.setText(
                _translate("MainWindow", "Address is valid."))
            self._onSuccess(addressVersion, streamNumber, ripe)
        elif status == 'missingbm':
            logger.debug("DEBUG: Address missing BM- prefix")
            self.labelAddressCheck.setText(_translate(
                "MainWindow",  # dialog name should be here
                "The address should start with ''BM-''"
            ))
        elif status == 'checksumfailed':
            logger.debug("DEBUG: Address checksum failed")
            self.labelAddressCheck.setText(_translate(
                "MainWindow",
                "The address is not typed or copied correctly"
                " (the checksum failed)."
            ))
        elif status == 'versiontoohigh':
            logger.debug("DEBUG: Address version too high")
            self.labelAddressCheck.setText(_translate(
                "MainWindow",
                "The version number of this address is higher than this"
                " software can support. Please upgrade Bitmessage."
            ))
        elif status == 'invalidcharacters':
            logger.debug("DEBUG: Address contains invalid characters")
            self.labelAddressCheck.setText(_translate(
                "MainWindow",
                "The address contains invalid characters."
            ))
        elif status == 'ripetooshort':
            logger.debug("DEBUG: RIPE data too short")
            self.labelAddressCheck.setText(_translate(
                "MainWindow",
                "Some data encoded in the address is too short."
            ))
        elif status == 'ripetoolong':
            logger.debug("DEBUG: RIPE data too long")
            self.labelAddressCheck.setText(_translate(
                "MainWindow",
                "Some data encoded in the address is too long."
            ))
        elif status == 'varintmalformed':
            logger.debug("DEBUG: Varint malformed in address")
            self.labelAddressCheck.setText(_translate(
                "MainWindow",
                "Some data encoded in the address is malformed."
            ))


class AddressDataDialog(QtWidgets.QDialog, AddressCheckMixin):
    """
    Base class for a dialog getting BM-address data.
    Corresponding ui-file should define two fields:
    lineEditAddress - for the address
    lineEditLabel - for it's label
    After address validation the values of that fields are put into
    the data field of the dialog.
    """

    def __init__(self, parent):
        logger.debug("DEBUG: Initializing AddressDataDialog")
        super(AddressDataDialog, self).__init__(parent)
        self.parent = parent
        self.data = None

    def accept(self):
        """Callback for QDialog accepting value"""
        logger.debug("DEBUG: AddressDataDialog accept called")
        if self.valid:
            logger.debug("DEBUG: Address is valid, storing data")
            self.data = (
                addBMIfNotPresent(ustr(self.lineEditAddress.text())),
                ustr(self.lineEditLabel.text())
            )
            logger.debug(f"DEBUG: Stored data - Address: {self.data[0]}, Label: {self.data[1]}")
        else:
            logger.debug("DEBUG: Address is invalid, showing error")
            queues.UISignalQueue.put(('updateStatusBar', _translate(
                "MainWindow",
                "The address you entered was invalid. Ignoring it."
            )))
        super(AddressDataDialog, self).accept()
        logger.debug("DEBUG: AddressDataDialog accept completed")


class AddAddressDialog(AddressDataDialog):
    """QDialog for adding a new address"""

    def __init__(self, parent=None, address=None):
        logger.debug("DEBUG: Initializing AddAddressDialog")
        super(AddAddressDialog, self).__init__(parent)
        widgets.load('addaddressdialog.ui', self)
        self._setup()
        if address:
            logger.debug(f"DEBUG: Pre-filling address: {address}")
            self.lineEditAddress.setText(address)


class NewAddressDialog(QtWidgets.QDialog):
    """QDialog for generating a new address"""

    def __init__(self, parent=None):
        logger.debug("DEBUG: Initializing NewAddressDialog")
        super(NewAddressDialog, self).__init__(parent)
        widgets.load('newaddressdialog.ui', self)

        # Let's fill out the 'existing address' combo box with addresses
        # from the 'Your Identities' tab.
        addresses = global_config.addresses(True)
        logger.debug(f"DEBUG: Found {len(addresses)} existing addresses")
        for address in addresses:
            self.radioButtonExisting.click()
            self.comboBoxExisting.addItem(address)
        
        self.groupBoxDeterministic.setHidden(True)
        QtWidgets.QWidget.resize(self, QtWidgets.QWidget.sizeHint(self))
        self.show()
        logger.debug("DEBUG: NewAddressDialog setup complete")

    def accept(self):
        """accept callback"""
        logger.debug("DEBUG: NewAddressDialog accept called")
        self.hide()
        
        if self.radioButtonRandomAddress.isChecked():
            logger.debug("DEBUG: Creating random address")
            if self.radioButtonMostAvailable.isChecked():
                streamNumberForAddress = 1
                logger.debug("DEBUG: Using most available stream (1)")
            else:
                # User selected 'Use the same stream as an existing address.'
                existing_address = self.comboBoxExisting.currentText()
                _, _, streamNumberForAddress = decodeAddress(existing_address)
                logger.debug(f"DEBUG: Using stream from existing address: {streamNumberForAddress}")
            
            queues.addressGeneratorQueue.put((
                'createRandomAddress', 4, streamNumberForAddress,
                ustr(self.newaddresslabel.text()), 1, "",
                self.checkBoxEighteenByteRipe.isChecked()
            ))
            logger.debug("DEBUG: Added random address creation to queue")
        else:
            logger.debug("DEBUG: Creating deterministic address")
            passphrase = ustr(self.lineEditPassphrase.text())
            passphrase_again = ustr(self.lineEditPassphraseAgain.text())
            
            if passphrase != passphrase_again:
                logger.debug("DEBUG: Passphrase mismatch")
                QtWidgets.QMessageBox.about(
                    self, _translate("MainWindow", "Passphrase mismatch"),
                    _translate(
                        "MainWindow",
                        "The passphrase you entered twice doesn\'t"
                        " match. Try again.")
                )
            elif passphrase == "":
                logger.debug("DEBUG: Empty passphrase")
                QtWidgets.QMessageBox.about(
                    self, _translate("MainWindow", "Choose a passphrase"),
                    _translate(
                        "MainWindow", "You really do need a passphrase.")
                )
            else:
                logger.debug("DEBUG: Creating deterministic addresses")
                # this will eventually have to be replaced by logic
                # to determine the most available stream number.
                streamNumberForAddress = 1
                num_addresses = self.spinBoxNumberOfAddressesToMake.value()
                logger.debug(f"DEBUG: Creating {num_addresses} deterministic addresses")
                
                queues.addressGeneratorQueue.put((
                    'createDeterministicAddresses', 4, streamNumberForAddress,
                    "unused deterministic address",
                    num_addresses,
                    passphrase,
                    self.checkBoxEighteenByteRipe.isChecked()
                ))
                logger.debug("DEBUG: Added deterministic address creation to queue")


class NewSubscriptionDialog(AddressDataDialog):
    """QDialog for subscribing to an address"""

    def __init__(self, parent=None):
        logger.debug("DEBUG: Initializing NewSubscriptionDialog")
        super(NewSubscriptionDialog, self).__init__(parent)
        widgets.load('newsubscriptiondialog.ui', self)
        self.recent = []
        self._setup()
        logger.debug("DEBUG: NewSubscriptionDialog setup complete")

    def _onSuccess(self, addressVersion, streamNumber, ripe):
        """Override for additional subscription-specific validation"""
        logger.debug("DEBUG: NewSubscriptionDialog validation success")
        if addressVersion <= 3:
            logger.debug("DEBUG: Old address type detected (v3 or lower)")
            self.checkBoxDisplayMessagesAlreadyInInventory.setText(_translate(
                "MainWindow",
                "Address is an old type. We cannot display its past"
                " broadcasts."
            ))
        else:
            logger.debug("DEBUG: Checking for recent broadcasts")
            state.Inventory.flush()
            doubleHashOfAddressData = hashlib.sha512(hashlib.sha512(
                encodeVarint(addressVersion)
                + encodeVarint(streamNumber) + ripe
            ).digest()).digest()
            tag = doubleHashOfAddressData[32:]
            self.recent = state.Inventory.by_type_and_tag(3, tag)
            count = len(self.recent)
            logger.debug(f"DEBUG: Found {count} recent broadcasts")
            
            if count == 0:
                self.checkBoxDisplayMessagesAlreadyInInventory.setText(
                    _translate(
                        "MainWindow",
                        "There are no recent broadcasts from this address"
                        " to display."
                    ))
            else:
                self.checkBoxDisplayMessagesAlreadyInInventory.setEnabled(True)
                self.checkBoxDisplayMessagesAlreadyInInventory.setText(
                    _translate(
                        "MainWindow",
                        "Display the %n recent broadcast(s) from this address.",
                        None, count
                    ))


class RegenerateAddressesDialog(QtWidgets.QDialog):
    """QDialog for regenerating deterministic addresses"""

    def __init__(self, parent=None):
        logger.debug("DEBUG: Initializing RegenerateAddressesDialog")
        super(RegenerateAddressesDialog, self).__init__(parent)
        widgets.load('regenerateaddresses.ui', self)
        self.groupBox.setTitle('')
        QtWidgets.QWidget.resize(self, QtWidgets.QWidget.sizeHint(self))
        logger.debug("DEBUG: RegenerateAddressesDialog setup complete")


class SpecialAddressBehaviorDialog(QtWidgets.QDialog):
    """
    QDialog for special address behaviour (e.g. mailing list functionality)
    """

    def __init__(self, parent=None, config=global_config):
        logger.debug("DEBUG: Initializing SpecialAddressBehaviorDialog")
        super(SpecialAddressBehaviorDialog, self).__init__(parent)
        widgets.load('specialaddressbehavior.ui', self)
        self.address = ustr(parent.getCurrentAccount())
        self.parent = parent
        self.config = config
        logger.debug(f"DEBUG: Working with address: {self.address}")

        try:
            self.address_is_chan = config.safeGetBoolean(
                self.address, 'chan'
            )
            logger.debug(f"DEBUG: Address is chan: {self.address_is_chan}")
        except AttributeError:
            logger.debug("DEBUG: No chan setting found for address")
            pass
        else:
            if self.address_is_chan:  # address is a chan address
                logger.debug("DEBUG: Disabling mailing list options for chan")
                self.radioButtonBehaviorMailingList.setDisabled(True)
                self.lineEditMailingListName.setText(_translate(
                    "SpecialAddressBehaviorDialog",
                    "This is a chan address. You cannot use it as a"
                    " pseudo-mailing list."
                ))
            else:
                if config.safeGetBoolean(self.address, 'mailinglist'):
                    logger.debug("DEBUG: Address is a mailing list")
                    self.radioButtonBehaviorMailingList.click()
                else:
                    logger.debug("DEBUG: Address is normal")
                    self.radioButtonBehaveNormalAddress.click()
                mailingListName = config.safeGet(
                    self.address, 'mailinglistname', '')
                self.lineEditMailingListName.setText(
                    unic(ustr(mailingListName)))
                logger.debug(f"DEBUG: Mailing list name: {mailingListName}")

        QtWidgets.QWidget.resize(self, QtWidgets.QWidget.sizeHint(self))
        self.show()
        logger.debug("DEBUG: SpecialAddressBehaviorDialog setup complete")

    def accept(self):
        """Accept callback"""
        logger.debug("DEBUG: SpecialAddressBehaviorDialog accept called")
        self.hide()
        if self.address_is_chan:
            logger.debug("DEBUG: No changes made for chan address")
            return
        
        if self.radioButtonBehaveNormalAddress.isChecked():
            logger.debug("DEBUG: Setting address to normal behavior")
            self.config.set(self.address, 'mailinglist', 'false')
            # Set the color to either black or grey
            if self.config.getboolean(self.address, 'enabled'):
                color = QtWidgets.QApplication.palette().text().color()
                logger.debug("DEBUG: Setting normal enabled address color")
            else:
                color = QtGui.QColor(128, 128, 128)
                logger.debug("DEBUG: Setting normal disabled address color")
            self.parent.setCurrentItemColor(color)
        else:
            logger.debug("DEBUG: Setting address to mailing list behavior")
            self.config.set(self.address, 'mailinglist', 'true')
            mailing_list_name = ustr(self.lineEditMailingListName.text())
            self.config.set(self.address, 'mailinglistname', mailing_list_name)
            logger.debug(f"DEBUG: Set mailing list name: {mailing_list_name}")
            self.parent.setCurrentItemColor(
                QtGui.QColor(137, 4, 177))  # magenta
        
        self.parent.rerenderComboBoxSendFrom()
        self.parent.rerenderComboBoxSendFromBroadcast()
        self.config.save()
        logger.debug("DEBUG: Saved config changes")
        self.parent.rerenderMessagelistToLabels()
        logger.debug("DEBUG: SpecialAddressBehaviorDialog accept completed")


class EmailGatewayDialog(QtWidgets.QDialog):
    """QDialog for email gateway control"""

    def __init__(self, parent, config=global_config, account=None):
        logger.debug("DEBUG: Initializing EmailGatewayDialog")
        super(EmailGatewayDialog, self).__init__(parent)
        widgets.load('emailgateway.ui', self)
        self.parent = parent
        self.config = config
        self.data = None
        
        if account:
            logger.debug("DEBUG: EmailGatewayDialog in error mode")
            self.acct = account
            self.setWindowTitle(_translate(
                "EmailGatewayDialog", "Registration failed:"))
            self.label.setText(_translate(
                "EmailGatewayDialog",
                "The requested email address is not available,"
                " please try a new one."
            ))
            self.radioButtonRegister.hide()
            self.radioButtonStatus.hide()
            self.radioButtonSettings.hide()
            self.radioButtonUnregister.hide()
        else:
            logger.debug("DEBUG: EmailGatewayDialog in normal mode")
            address = parent.getCurrentAccount()
            self.acct = accountClass(address)
            logger.debug(f"DEBUG: Working with address: {address}")
            
            try:
                label = config.get(address, 'label')
                if "@" in label:
                    logger.debug(f"DEBUG: Found email in label: {label}")
                    self.lineEditEmail.setText(label)
            except AttributeError:
                logger.debug("DEBUG: No label found for address")
                pass
            
            if isinstance(self.acct, GatewayAccount):
                logger.debug("DEBUG: Address is a gateway account")
                self.radioButtonUnregister.setEnabled(True)
                self.radioButtonStatus.setEnabled(True)
                self.radioButtonStatus.setChecked(True)
                self.radioButtonSettings.setEnabled(True)
                self.lineEditEmail.setEnabled(False)
            else:
                logger.debug("DEBUG: Creating new Mailchuck account")
                self.acct = MailchuckAccount(address)
        
        self.lineEditEmail.setFocus()
        QtWidgets.QWidget.resize(self, QtWidgets.QWidget.sizeHint(self))
        logger.debug("DEBUG: EmailGatewayDialog setup complete")

    def accept(self):
        """Accept callback"""
        logger.debug("DEBUG: EmailGatewayDialog accept called")
        self.hide()
        
        # no chans / mailinglists
        if self.acct.type != AccountMixin.NORMAL:
            logger.debug("DEBUG: Not a normal account, skipping")
            return

        if not isinstance(self.acct, GatewayAccount):
            logger.debug("DEBUG: Not a gateway account, skipping")
            return

        if self.radioButtonRegister.isChecked() \
                or self.radioButtonRegister.isHidden():
            logger.debug("DEBUG: Registering email gateway")
            email = ustr(self.lineEditEmail.text())
            logger.debug(f"DEBUG: Registering email: {email}")
            self.acct.register(email)
            self.config.set(self.acct.fromAddress, 'label', email)
            self.config.set(self.acct.fromAddress, 'gateway', 'mailchuck')
            self.config.save()
            queues.UISignalQueue.put(('updateStatusBar', _translate(
                "EmailGatewayDialog",
                "Sending email gateway registration request"
            )))
        elif self.radioButtonUnregister.isChecked():
            logger.debug("DEBUG: Unregistering email gateway")
            self.acct.unregister()
            self.config.remove_option(self.acct.fromAddress, 'gateway')
            self.config.save()
            queues.UISignalQueue.put(('updateStatusBar', _translate(
                "EmailGatewayDialog",
                "Sending email gateway unregistration request"
            )))
        elif self.radioButtonStatus.isChecked():
            logger.debug("DEBUG: Checking email gateway status")
            self.acct.status()
            queues.UISignalQueue.put(('updateStatusBar', _translate(
                "EmailGatewayDialog",
                "Sending email gateway status request"
            )))
        elif self.radioButtonSettings.isChecked():
            logger.debug("DEBUG: Saving email gateway settings")
            self.data = self.acct

        super(EmailGatewayDialog, self).accept()
        logger.debug("DEBUG: EmailGatewayDialog accept completed")
