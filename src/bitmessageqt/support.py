"""Composing support request message functions."""

import ctypes
import os
import ssl
import sys
import time
import logging

from unqstr import ustr, unic
from dbcompat import dbstr

from bitmessageqt import account
import defaults
import network.stats
import paths
import proofofwork
import queues
import state
from bmconfigparser import config
from .foldertree import AccountMixin
from helper_sql import sqlExecute, sqlQuery
from l10n import getTranslationLanguage
from openclpow import openclEnabled
from pyelliptic.openssl import OpenSSL
from .settings import getSOCKSProxyType
from version import softwareVersion
from tr import _translate

# Debugging setup
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# this is BM support address going to Peter Surda
OLD_SUPPORT_ADDRESS = 'BM-2cTkCtMYkrSPwFTpgcBrMrf5d8oZwvMZWK'
SUPPORT_ADDRESS = 'BM-2cUdgkDDAahwPAU6oD2A7DnjqZz3hgY832'
SUPPORT_LABEL = _translate("Support", "PyBitmessage support")
SUPPORT_MY_LABEL = _translate("Support", "My new address")
SUPPORT_SUBJECT = _translate("Support", "Support request")
SUPPORT_MESSAGE = _translate("Support", '''
You can use this message to send a report to one of the PyBitmessage core \
developers regarding PyBitmessage or the mailchuck.com email service. \
If you are using PyBitmessage involuntarily, for example because \
your computer was infected with ransomware, this is not an appropriate venue \
for resolving such issues.

Please describe what you are trying to do:

Please describe what you expect to happen:

Please describe what happens instead:


^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Please write above this line and if possible, keep the information about your \
environment below intact.

PyBitmessage version: {}
Operating system: {}
Architecture: {}bit
Python Version: {}
OpenSSL Version: {}
Qt API: {}
Frozen: {}
Portable mode: {}
C PoW: {}
OpenCL PoW: {}
Locale: {}
SOCKS: {}
UPnP: {}
Connected hosts: {}
''')


def checkAddressBook(myapp):
    """
    Add "PyBitmessage support" address to address book, remove old one if found.
    """
    logger.debug("DEBUG: checkAddressBook() called")
    
    logger.debug(f"DEBUG: Removing old support address: {OLD_SUPPORT_ADDRESS}")
    sqlExecute('DELETE from addressbook WHERE address=?', dbstr(OLD_SUPPORT_ADDRESS))
    
    logger.debug(f"DEBUG: Checking for existing support address: {SUPPORT_ADDRESS}")
    queryreturn = sqlQuery(
        'SELECT * FROM addressbook WHERE address=?', dbstr(SUPPORT_ADDRESS))
    
    if queryreturn == []:
        logger.debug("DEBUG: Adding new support address to address book")
        sqlExecute(
            'INSERT INTO addressbook VALUES (?,?)',
            dbstr(SUPPORT_LABEL), dbstr(SUPPORT_ADDRESS))
        myapp.rerenderAddressBook()
    else:
        logger.debug("DEBUG: Support address already exists in address book")


def checkHasNormalAddress():
    """Returns first enabled normal address or False if not found."""
    logger.debug("DEBUG: checkHasNormalAddress() called")
    
    addresses = config.addresses(True)
    logger.debug(f"DEBUG: Checking {len(addresses)} addresses")
    
    for address in addresses:
        acct = account.accountClass(address)
        if acct.type == AccountMixin.NORMAL and config.safeGetBoolean(
                address, 'enabled'):
            logger.debug(f"DEBUG: Found enabled normal address: {address}")
            return address
    
    logger.debug("DEBUG: No enabled normal addresses found")
    return False


def createAddressIfNeeded(myapp):
    """Checks if user has any enabled normal address, creates new one if no."""
    logger.debug("DEBUG: createAddressIfNeeded() called")
    
    if not checkHasNormalAddress():
        logger.debug("DEBUG: Creating new random address for support")
        queues.addressGeneratorQueue.put((
            'createRandomAddress', 4, 1,
            ustr(SUPPORT_MY_LABEL),
            1, "", False,
            defaults.networkDefaultProofOfWorkNonceTrialsPerByte,
            defaults.networkDefaultPayloadLengthExtraBytes
        ))
    
    while state.shutdown == 0 and not checkHasNormalAddress():
        logger.debug("DEBUG: Waiting for address generation to complete...")
        time.sleep(.2)
    
    myapp.rerenderComboBoxSendFrom()
    result = checkHasNormalAddress()
    logger.debug(f"DEBUG: Address creation result: {result}")
    return result


def createSupportMessage(myapp):
    """
    Prepare the support request message and switch to tab "Send"
    """
    logger.debug("DEBUG: createSupportMessage() called")
    
    checkAddressBook(myapp)
    address = createAddressIfNeeded(myapp)
    
    if state.shutdown:
        logger.warning("DEBUG: Shutdown in progress, aborting support message creation")
        return

    logger.debug("DEBUG: Setting up support message UI elements")
    myapp.ui.lineEditSubject.setText(SUPPORT_SUBJECT)
    
    addrIndex = myapp.ui.comboBoxSendFrom.findData(address)
    if addrIndex == -1:  # something is very wrong
        logger.error("DEBUG: Could not find created address in combo box")
        return
    
    logger.debug(f"DEBUG: Setting sender address index: {addrIndex}")
    myapp.ui.comboBoxSendFrom.setCurrentIndex(addrIndex)
    myapp.ui.lineEditTo.setText(SUPPORT_ADDRESS)

    # Collect system information
    version = softwareVersion
    commit = paths.lastCommit().get('commit')
    if commit:
        version += " GIT " + commit
    logger.debug(f"DEBUG: Version info: {version}")

    if sys.platform.startswith("win"):
        osname = "Windows %s.%s" % sys.getwindowsversion()[:2]
        logger.debug("DEBUG: Windows platform detected")
    else:
        try:
            unixversion = os.uname()
            osname = unixversion[0] + " " + unixversion[2]
            logger.debug("DEBUG: Unix-like platform detected")
        except Exception as e:
            osname = "Unknown"
            logger.error(f"DEBUG: Error detecting OS version: {str(e)}")

    architecture = "32" if ctypes.sizeof(ctypes.c_voidp) == 4 else "64"
    pythonversion = sys.version
    logger.debug(f"DEBUG: Architecture: {architecture}bit, Python: {pythonversion}")

    opensslversion = "%s (Python internal), %s (external for PyElliptic)" % (
        ssl.OPENSSL_VERSION, OpenSSL._version)
    logger.debug(f"DEBUG: OpenSSL versions: {opensslversion}")

    qtapi = os.environ.get('QT_API', 'fallback')
    frozen = "N/A" if not paths.frozen else paths.frozen
    portablemode = str(state.appdata == paths.lookupExeFolder())
    cpow = "True" if proofofwork.bmpow else "False"
    openclpow = ustr(
        config.safeGet('bitmessagesettings', 'opencl')
    ) if openclEnabled() else "None"
    locale = getTranslationLanguage()
    socks = getSOCKSProxyType(config) or 'N/A'
    upnp = config.safeGet('bitmessagesettings', 'upnp', 'N/A')
    connectedhosts = len(network.stats.connectedHostsList())

    logger.debug("DEBUG: Formatting support message template")
    message_text = unic(ustr(SUPPORT_MESSAGE).format(
        version, osname, architecture, pythonversion, opensslversion, qtapi,
        frozen, portablemode, cpow, openclpow, locale, socks, upnp,
        connectedhosts
    ))
    myapp.ui.textEditMessage.setText(message_text)

    # Switch to send tab
    logger.debug("DEBUG: Switching to send tab")
    myapp.ui.tabWidgetSend.setCurrentIndex(
        myapp.ui.tabWidgetSend.indexOf(myapp.ui.sendDirect)
    )
    myapp.ui.tabWidget.setCurrentIndex(
        myapp.ui.tabWidget.indexOf(myapp.ui.send)
    )
    logger.debug("DEBUG: Support message setup complete")
