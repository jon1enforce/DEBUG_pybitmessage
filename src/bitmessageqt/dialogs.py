"""
All dialogs are available in this module.
"""
# pylint: disable=too-few-public-methods
import logging
import sys
from unqstr import ustr

from qtpy import QtWidgets

import paths
from bitmessageqt import widgets
from .address_dialogs import (
    AddAddressDialog, EmailGatewayDialog, NewAddressDialog,
    NewSubscriptionDialog, RegenerateAddressesDialog,
    SpecialAddressBehaviorDialog
)
from .newchandialog import NewChanDialog
from .settings import SettingsDialog
from tr import _translate
from version import softwareVersion

# Set up basic logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

__all__ = [
    "NewChanDialog", "AddAddressDialog", "NewAddressDialog",
    "NewSubscriptionDialog", "RegenerateAddressesDialog",
    "SpecialAddressBehaviorDialog", "EmailGatewayDialog",
    "SettingsDialog"
]


class AboutDialog(QtWidgets.QDialog):
    """The "About" dialog"""
    def __init__(self, parent=None):
        logger.debug("AboutDialog.__init__ called with parent=%s", parent)
        super(AboutDialog, self).__init__(parent)
        logger.debug("Loading about.ui")
        widgets.load('about.ui', self)
        
        last_commit = paths.lastCommit()
        logger.debug("Got last commit info: %s", last_commit)
        
        version = softwareVersion
        logger.debug("Software version: %s", version)
        
        commit = last_commit.get('commit')
        if commit:
            version += '-' + commit[:7]
            logger.debug("Added commit hash to version: %s", version)
        
        logger.debug("Setting version label text")
        self.labelVersion.setText(
            ustr(self.labelVersion.text()).replace(
                ':version:', version
            ).replace(':branch:', commit or 'v%s' % version)
        )
        self.labelVersion.setOpenExternalLinks(True)
        logger.debug("Set version label and enabled external links")

        try:
            logger.debug("Attempting to set copyright year")
            self.label_2.setText(
                ustr(self.label_2.text()).replace(
                    '2022', ustr(last_commit.get('time').year)
                ))
            logger.debug("Updated copyright year successfully")
        except AttributeError as e:
            logger.debug("Failed to update copyright year: %s", str(e))
            pass

        logger.debug("Setting fixed dialog size")
        self.setFixedSize(QtWidgets.QWidget.sizeHint(self))
        logger.debug("AboutDialog initialization complete")


class IconGlossaryDialog(QtWidgets.QDialog):
    """The "Icon Glossary" dialog, explaining the status icon colors"""
    def __init__(self, parent=None, config=None):
        logger.debug("IconGlossaryDialog.__init__ called with parent=%s, config=%s", parent, config)
        super(IconGlossaryDialog, self).__init__(parent)
        logger.debug("Loading iconglossary.ui")
        widgets.load('iconglossary.ui', self)

        # .. todo:: FIXME: check the window title visibility here
        logger.debug("Setting empty group box title")
        self.groupBox.setTitle('')

        port = config.getint('bitmessagesettings', 'port')
        logger.debug("Got port number from config: %s", port)
        
        port_text = _translate(
            "iconGlossaryDialog",
            "You are using TCP port {0}."
            " (This can be changed in the settings)."
        ).format(port)
        logger.debug("Setting port number label text: %s", port_text)
        self.labelPortNumber.setText(port_text)
        
        logger.debug("Setting fixed dialog size")
        self.setFixedSize(QtWidgets.QWidget.sizeHint(self))
        logger.debug("IconGlossaryDialog initialization complete")


class HelpDialog(QtWidgets.QDialog):
    """The "Help" dialog"""
    def __init__(self, parent=None):
        logger.debug("HelpDialog.__init__ called with parent=%s", parent)
        super(HelpDialog, self).__init__(parent)
        logger.debug("Loading help.ui")
        widgets.load('help.ui', self)
        
        logger.debug("Setting fixed dialog size")
        self.setFixedSize(QtWidgets.QWidget.sizeHint(self))
        logger.debug("HelpDialog initialization complete")


class ConnectDialog(QtWidgets.QDialog):
    """The "Connect" dialog"""
    def __init__(self, parent=None):
        logger.debug("ConnectDialog.__init__ called with parent=%s", parent)
        super(ConnectDialog, self).__init__(parent)
        logger.debug("Loading connect.ui")
        widgets.load('connect.ui', self)
        
        logger.debug("Setting fixed dialog size")
        self.setFixedSize(QtWidgets.QWidget.sizeHint(self))
        logger.debug("ConnectDialog initialization complete")
