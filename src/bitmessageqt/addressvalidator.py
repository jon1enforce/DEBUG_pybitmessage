"""
The validator for address and passphrase QLineEdits
used in `.dialogs.NewChanDialog`.
"""
# pylint: disable=too-many-arguments

import logging
from six.moves.queue import Empty

from unqstr import ustr
from qtpy import QtGui

from addresses import decodeAddress, addBMIfNotPresent
from bmconfigparser import config
from queues import apiAddressGeneratorReturnQueue, addressGeneratorQueue
from tr import _translate
from .utils import str_chan

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class AddressPassPhraseValidatorMixin(object):
    """Bitmessage address or passphrase validator class for Qt UI"""
    def setParams(
        self, passPhraseObject=None, addressObject=None,
        feedBackObject=None, button=None, addressMandatory=True
    ):
        """Initialization"""
        logger.debug("DEBUG: Setting validator parameters")
        self.addressObject = addressObject
        self.passPhraseObject = passPhraseObject
        self.feedBackObject = feedBackObject
        self.addressMandatory = addressMandatory
        self.isValid = False
        # save default text
        self.okButton = button
        if button:
            self.okButtonLabel = button.text()
            logger.debug(f"DEBUG: Saved button label: {self.okButtonLabel}")
        else:
            logger.debug("DEBUG: No button provided")

    def setError(self, string):
        """Indicate that the validation is pending or failed"""
        logger.debug(f"DEBUG: Setting error state with message: {string}")
        if string is not None and self.feedBackObject is not None:
            logger.debug("DEBUG: Configuring feedback object for error")
            font = QtGui.QFont()
            font.setBold(True)
            self.feedBackObject.setFont(font)
            self.feedBackObject.setStyleSheet("QLabel { color : red; }")
            self.feedBackObject.setText(string)
        self.isValid = False
        if self.okButton:
            self.okButton.setEnabled(False)
            if string is not None and self.feedBackObject is not None:
                logger.debug("DEBUG: Setting button to 'Invalid'")
                self.okButton.setText(
                    _translate("AddressValidator", "Invalid"))
            else:
                logger.debug("DEBUG: Setting button to 'Validating...'")
                self.okButton.setText(
                    _translate("AddressValidator", "Validating..."))

    def setOK(self, string):
        """Indicate that the validation succeeded"""
        logger.debug(f"DEBUG: Setting OK state with message: {string}")
        if string is not None and self.feedBackObject is not None:
            logger.debug("DEBUG: Configuring feedback object for success")
            font = QtGui.QFont()
            font.setBold(False)
            self.feedBackObject.setFont(font)
            self.feedBackObject.setStyleSheet("QLabel { }")
            self.feedBackObject.setText(string)
        self.isValid = True
        if self.okButton:
            logger.debug("DEBUG: Enabling OK button")
            self.okButton.setEnabled(True)
            self.okButton.setText(self.okButtonLabel)

    def checkQueue(self):
        """Validator queue loop"""
        logger.debug("DEBUG: Checking validator queue")
        gotOne = False

        # wait until processing is done
        if not addressGeneratorQueue.empty():
            logger.debug("DEBUG: Address generator queue not empty")
            self.setError(None)
            return None

        while True:
            try:
                logger.debug("DEBUG: Trying to get from apiAddressGeneratorReturnQueue")
                addressGeneratorReturnValue = \
                    apiAddressGeneratorReturnQueue.get(False)
                logger.debug(f"DEBUG: Got return value: {addressGeneratorReturnValue}")
            except Empty:
                if gotOne:
                    logger.debug("DEBUG: Queue empty after getting items")
                    break
                else:
                    logger.debug("DEBUG: Queue empty, no items received")
                    return None
            else:
                gotOne = True

        if not addressGeneratorReturnValue:
            logger.debug("DEBUG: Address already exists as identity")
            self.setError(_translate(
                "AddressValidator",
                "Address already present as one of your identities."
            ))
            return
        if addressGeneratorReturnValue[0] == \
                'chan name does not match address':
            logger.debug("DEBUG: Chan name doesn't match address")
            self.setError(_translate(
                "AddressValidator",
                "Although the Bitmessage address you entered was valid,"
                " it doesn\'t match the chan name."
            ))
            return
        logger.debug("DEBUG: Validation successful")
        self.setOK(_translate(
            "MainWindow", "Passphrase and address appear to be valid."))

    def returnValid(self):
        """Return the value of whether the validation was successful"""
        logger.debug(f"DEBUG: Returning validation state: {self.isValid}")
        return QtGui.QValidator.Acceptable if self.isValid \
            else QtGui.QValidator.Intermediate

    def validate(self, s, pos):
        """Top level validator method"""
        logger.debug("DEBUG: Starting validation")
        try:
            address = ustr(self.addressObject.text())
            logger.debug(f"DEBUG: Address input: {address}")
        except AttributeError:
            address = None
            logger.debug("DEBUG: No address object available")
        try:
            passPhrase = ustr(self.passPhraseObject.text())
            logger.debug(f"DEBUG: Passphrase input: {passPhrase}")
        except AttributeError:
            passPhrase = ""
            logger.debug("DEBUG: No passphrase object available")

        # no chan name
        if not passPhrase:
            logger.debug("DEBUG: Empty passphrase detected")
            self.setError(_translate(
                "AddressValidator",
                "Chan name/passphrase needed. You didn't enter a chan name."
            ))
            return (QtGui.QValidator.Intermediate, s, pos)

        if self.addressMandatory or address:
            logger.debug("DEBUG: Checking address validity")
            # check if address already exists:
            if address in config.addresses(True):
                logger.debug("DEBUG: Address already exists in config")
                self.setError(_translate(
                    "AddressValidator",
                    "Address already present as one of your identities."
                ))
                return (QtGui.QValidator.Intermediate, s, pos)

            status = decodeAddress(address)[0]
            logger.debug(f"DEBUG: Address decode status: {status}")
            # version too high
            if status == 'versiontoohigh':
                logger.debug("DEBUG: Address version too high")
                self.setError(_translate(
                    "AddressValidator",
                    "Address too new. Although that Bitmessage address"
                    " might be valid, its version number is too new"
                    " for us to handle. Perhaps you need to upgrade"
                    " Bitmessage."
                ))
                return (QtGui.QValidator.Intermediate, s, pos)
            # invalid
            if status != 'success':
                logger.debug("DEBUG: Invalid address format")
                self.setError(_translate(
                    "AddressValidator",
                    "The Bitmessage address is not valid."
                ))
                return (QtGui.QValidator.Intermediate, s, pos)

        # this just disables the OK button without changing the feedback text
        # but only if triggered by textEdited, not by clicking the Ok button
        if not self.okButton.hasFocus():
            logger.debug("DEBUG: OK button not focused, setting error to None")
            self.setError(None)

        # check through generator
        if not address:
            logger.debug("DEBUG: Creating new chan address")
            addressGeneratorQueue.put((
                'createChan', 4, 1,
                str_chan + ' ' + passPhrase, passPhrase.encode("utf-8", "replace"), False
            ))
        else:
            logger.debug("DEBUG: Joining existing chan")
            addressGeneratorQueue.put((
                'joinChan', addBMIfNotPresent(address),
                "{} {}".format(str_chan, passPhrase), passPhrase.encode("utf-8", "replace"), False
            ))

        if self.okButton.hasFocus():
            logger.debug("DEBUG: OK button has focus, returning validation state")
            return (self.returnValid(), s, pos)
        else:
            logger.debug("DEBUG: Returning intermediate state")
            return (QtGui.QValidator.Intermediate, s, pos)

    def checkData(self):
        """Validator Qt signal interface"""
        logger.debug("DEBUG: Checking data via signal interface")
        return self.validate(u"", 0)


class AddressValidator(QtGui.QValidator, AddressPassPhraseValidatorMixin):
    """AddressValidator class for Qt UI"""
    def __init__(
        self, parent=None, passPhraseObject=None, feedBackObject=None,
        button=None, addressMandatory=True
    ):
        logger.debug("DEBUG: Initializing AddressValidator")
        super(AddressValidator, self).__init__(parent)
        self.setParams(
            passPhraseObject, parent, feedBackObject, button,
            addressMandatory)


class PassPhraseValidator(QtGui.QValidator, AddressPassPhraseValidatorMixin):
    """PassPhraseValidator class for Qt UI"""
    def __init__(
        self, parent=None, addressObject=None, feedBackObject=None,
        button=None, addressMandatory=False
    ):
        logger.debug("DEBUG: Initializing PassPhraseValidator")
        super(PassPhraseValidator, self).__init__(parent)
        self.setParams(
            parent, addressObject, feedBackObject, button,
            addressMandatory)
