"""
Folder tree and messagelist widgets definitions.
"""
# pylint: disable=too-many-arguments
# pylint: disable=attribute-defined-outside-init

import sys
import logging

# Set up basic logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

try:
    from cgi import escape
    logger.debug("Using escape from cgi module")
except ImportError:
    from html import escape
    logger.debug("Using escape from html module")

from unqstr import ustr, unic
from dbcompat import dbstr
from qtpy import QtCore, QtGui, QtWidgets

from bmconfigparser import config
from helper_sql import sqlExecute, sqlQuery
from .settingsmixin import SettingsMixin
from tr import _translate
from .utils import avatarize

# for pylupdate
_translate("MainWindow", "inbox")
_translate("MainWindow", "new")
_translate("MainWindow", "sent")
_translate("MainWindow", "trash")

TimestampRole = QtCore.Qt.UserRole + 1
logger.debug(f"Defined TimestampRole as Qt.UserRole + 1 = {TimestampRole}")

class AccountMixin(object):
    """UI-related functionality for accounts"""
    ALL = 0
    NORMAL = 1
    CHAN = 2
    MAILINGLIST = 3
    SUBSCRIPTION = 4
    BROADCAST = 5

    def accountColor(self):
        """QT UI color for an account"""
        logger.debug(f"AccountMixin.accountColor called for {self}")
        if not self.isEnabled:
            logger.debug("Account disabled, returning gray color")
            return QtGui.QColor(128, 128, 128)
        elif self.type == self.CHAN:
            logger.debug("Account is CHAN, returning orange color")
            return QtGui.QColor(216, 119, 0)
        elif self.type in (self.MAILINGLIST, self.SUBSCRIPTION):
            logger.debug("Account is MAILINGLIST/SUBSCRIPTION, returning purple color")
            return QtGui.QColor(137, 4, 177)

        logger.debug("Returning default text color")
        return QtWidgets.QApplication.palette().text().color()

    def folderColor(self):
        """QT UI color for a folder"""
        logger.debug(f"AccountMixin.folderColor called for {self}")
        if not self.parent().isEnabled:
            logger.debug("Parent account disabled, returning gray color")
            return QtGui.QColor(128, 128, 128)
        logger.debug("Returning default text color")
        return QtWidgets.QApplication.palette().text().color()

    def accountBrush(self):
        """Account brush (for QT UI)"""
        logger.debug(f"AccountMixin.accountBrush called for {self}")
        brush = QtGui.QBrush(self.accountColor())
        brush.setStyle(QtCore.Qt.NoBrush)
        logger.debug(f"Returning brush: {brush}")
        return brush

    def folderBrush(self):
        """Folder brush (for QT UI)"""
        logger.debug(f"AccountMixin.folderBrush called for {self}")
        brush = QtGui.QBrush(self.folderColor())
        brush.setStyle(QtCore.Qt.NoBrush)
        logger.debug(f"Returning brush: {brush}")
        return brush

    def accountString(self):
        """Account string suitable for use in To: field: label <address>"""
        logger.debug(f"AccountMixin.accountString called for {self}")
        label = ustr(self._getLabel())
        result = (
            self.address if label == self.address
            else '%s <%s>' % (label, self.address)
        )
        logger.debug(f"Returning account string: {result}")
        return result

    def setAddress(self, address):
        """Set bitmessage address of the object"""
        logger.debug(f"AccountMixin.setAddress called with address: {address}")
        if address is None:
            self.address = None
            logger.debug("Address set to None")
        else:
            self.address = ustr(address)
            logger.debug(f"Address set to: {self.address}")

    def setUnreadCount(self, cnt):
        """Set number of unread messages"""
        logger.debug(f"AccountMixin.setUnreadCount called with count: {cnt}")
        try:
            if self.unreadCount == int(cnt):
                logger.debug("Unread count unchanged, returning")
                return
        except AttributeError:
            logger.debug("No existing unreadCount attribute")
            pass
        self.unreadCount = int(cnt)
        logger.debug(f"Set unreadCount to: {self.unreadCount}")
        if isinstance(self, QtWidgets.QTreeWidgetItem):
            logger.debug("Emitting dataChanged signal")
            self.emitDataChanged()

    def setEnabled(self, enabled):
        """Set account enabled (QT UI)"""
        logger.debug(f"AccountMixin.setEnabled called with: {enabled}")
        self.isEnabled = enabled
        try:
            self.setExpanded(enabled)
            logger.debug(f"Set expanded to: {enabled}")
        except AttributeError:
            logger.debug("setExpanded not available for this object")
            pass
        if isinstance(self, Ui_AddressWidget):
            logger.debug("Processing children for Ui_AddressWidget")
            for i in range(self.childCount()):
                if isinstance(self.child(i), Ui_FolderWidget):
                    self.child(i).setEnabled(enabled)
        if isinstance(self, QtWidgets.QTreeWidgetItem):
            logger.debug("Emitting dataChanged signal")
            self.emitDataChanged()

    def setType(self):
        """Set account type (QT UI)"""
        logger.debug(f"AccountMixin.setType called for {self}")
        self.setFlags(self.flags() | QtCore.Qt.ItemIsEditable)
        if self.address is None:
            self.type = self.ALL
            self.setFlags(self.flags() & ~QtCore.Qt.ItemIsEditable)
            logger.debug("Account type set to ALL (no address)")
        elif config.safeGetBoolean(self.address, 'chan'):
            self.type = self.CHAN
            logger.debug("Account type set to CHAN")
        elif config.safeGetBoolean(self.address, 'mailinglist'):
            self.type = self.MAILINGLIST
            logger.debug("Account type set to MAILINGLIST")
        elif sqlQuery(
            'SELECT label FROM subscriptions WHERE address=?',
            dbstr(self.address)
        ):
            self.type = AccountMixin.SUBSCRIPTION
            logger.debug("Account type set to SUBSCRIPTION")
        else:
            self.type = self.NORMAL
            logger.debug("Account type set to NORMAL")

    def defaultLabel(self):
        """Default label (in case no label is set manually)"""
        logger.debug(f"AccountMixin.defaultLabel called for {self}")
        queryreturn = retval = None
        if self.type in (
                AccountMixin.NORMAL,
                AccountMixin.CHAN, AccountMixin.MAILINGLIST):
            try:
                retval = unic(ustr(config.get(self.address, 'label')))
                logger.debug(f"Got label from config: {retval}")
            except Exception as e:
                logger.debug(f"Error getting label from config: {e}")
                queryreturn = sqlQuery(
                    'SELECT label FROM addressbook WHERE address=?',
                    dbstr(self.address)
                )
        elif self.type == AccountMixin.SUBSCRIPTION:
            queryreturn = sqlQuery(
                'SELECT label FROM subscriptions WHERE address=?',
                dbstr(self.address)
            )
            logger.debug(f"Got subscription query result: {queryreturn}")
        if queryreturn:
            retval = unic(ustr(queryreturn[-1][0]))
            logger.debug(f"Got label from query: {retval}")
        elif self.address is None or self.type == AccountMixin.ALL:
            retval = unic(_translate("MainWindow", "All accounts"))
            logger.debug(f"Returning 'All accounts' label: {retval}")
            return retval

        retval = retval or unic(self.address)
        logger.debug(f"Returning label: {retval}")
        return retval


class BMTreeWidgetItem(QtWidgets.QTreeWidgetItem, AccountMixin):
    """A common abstract class for Tree widget item"""

    def __init__(self, parent, pos, address, unreadCount):
        logger.debug(f"BMTreeWidgetItem.__init__ called with parent={parent}, pos={pos}, address={address}, unreadCount={unreadCount}")
        super(QtWidgets.QTreeWidgetItem, self).__init__()
        self.setAddress(address)
        self.setUnreadCount(unreadCount)
        self._setup(parent, pos)

    def _getAddressBracket(self, unreadCount=False):
        logger.debug(f"BMTreeWidgetItem._getAddressBracket called with unreadCount={unreadCount}")
        result = " (" + ustr(self.unreadCount) + ")" if unreadCount else ""
        logger.debug(f"Returning: {result}")
        return result

    def data(self, column, role):
        """Override internal Qt method for returning object data"""
        logger.debug(f"BMTreeWidgetItem.data called with column={column}, role={role}")
        if column == 0:
            if role == QtCore.Qt.DisplayRole:
                result = self._getLabel() + self._getAddressBracket(
                    self.unreadCount > 0)
                logger.debug(f"DisplayRole result: {result}")
                return result
            elif role == QtCore.Qt.EditRole:
                result = self._getLabel()
                logger.debug(f"EditRole result: {result}")
                return result
            elif role == QtCore.Qt.ToolTipRole:
                result = self._getLabel() + self._getAddressBracket(False)
                logger.debug(f"ToolTipRole result: {result}")
                return result
            elif role == QtCore.Qt.FontRole:
                font = QtGui.QFont()
                font.setBold(self.unreadCount > 0)
                logger.debug(f"FontRole result: bold={self.unreadCount > 0}")
                return font
        result = super(BMTreeWidgetItem, self).data(column, role)
        logger.debug(f"Super data result: {result}")
        return result


class Ui_FolderWidget(BMTreeWidgetItem):
    """Item in the account/folder tree representing a folder"""
    folderWeight = {"inbox": 1, "new": 2, "sent": 3, "trash": 4}

    def __init__(
            self, parent, pos=0, address="", folderName="", unreadCount=0):
        logger.debug(f"Ui_FolderWidget.__init__ called with parent={parent}, pos={pos}, address={address}, folderName={folderName}, unreadCount={unreadCount}")
        self.setFolderName(folderName)
        super(Ui_FolderWidget, self).__init__(
            parent, pos, address, unreadCount)

    def _setup(self, parent, pos):
        logger.debug(f"Ui_FolderWidget._setup called with parent={parent}, pos={pos}")
        parent.insertChild(pos, self)
        logger.debug(f"Inserted child at position {pos}")

    def _getLabel(self):
        result = _translate("MainWindow", self.folderName)
        logger.debug(f"Ui_FolderWidget._getLabel returning: {result}")
        return result

    def setFolderName(self, fname):
        """Set folder name (for Qt UI)"""
        logger.debug(f"Ui_FolderWidget.setFolderName called with: {fname}")
        self.folderName = ustr(fname)
        logger.debug(f"Set folderName to: {self.folderName}")

    def data(self, column, role):
        """Override internal Qt method for returning object data"""
        logger.debug(f"Ui_FolderWidget.data called with column={column}, role={role}")
        if column == 0 and role == QtCore.Qt.ForegroundRole:
            result = self.folderBrush()
            logger.debug(f"ForegroundRole result: {result}")
            return result
        result = super(Ui_FolderWidget, self).data(column, role)
        logger.debug(f"Super data result: {result}")
        return result

    # inbox, sent, thrash first, rest alphabetically
    def __lt__(self, other):
        logger.debug(f"Ui_FolderWidget.__lt__ called with other={other}")
        if isinstance(other, Ui_FolderWidget):
            if self.folderName in self.folderWeight:
                x = self.folderWeight[self.folderName]
                logger.debug(f"Found folder weight for {self.folderName}: {x}")
            else:
                x = 99
                logger.debug(f"No folder weight for {self.folderName}, using 99")
            if other.folderName in self.folderWeight:
                y = self.folderWeight[other.folderName]
                logger.debug(f"Found folder weight for {other.folderName}: {y}")
            else:
                y = 99
                logger.debug(f"No folder weight for {other.folderName}, using 99")
            reverse = QtCore.Qt.DescendingOrder == \
                self.treeWidget().header().sortIndicatorOrder()
            logger.debug(f"Reverse sorting: {reverse}")
            if x == y:
                result = self.folderName < other.folderName
                logger.debug(f"Same weight, comparing names: {result}")
                return result
            result = x >= y if reverse else x < y
            logger.debug(f"Different weights, result: {result}")
            return result

        result = super(QtWidgets.QTreeWidgetItem, self).__lt__(other)
        logger.debug(f"Super __lt__ result: {result}")
        return result


class Ui_AddressWidget(BMTreeWidgetItem, SettingsMixin):
    """Item in the account/folder tree representing an account"""
    def __init__(
        self, parent, pos=0, address=None, unreadCount=0, enabled=True
    ):
        logger.debug(f"Ui_AddressWidget.__init__ called with parent={parent}, pos={pos}, address={address}, unreadCount={unreadCount}, enabled={enabled}")
        super(Ui_AddressWidget, self).__init__(
            parent, pos, address, unreadCount)
        self.setEnabled(enabled)

    def _setup(self, parent, pos):
        logger.debug(f"Ui_AddressWidget._setup called with parent={parent}, pos={pos}")
        self.setType()
        parent.insertTopLevelItem(pos, self)
        logger.debug(f"Inserted top level item at position {pos}")

    def _getLabel(self):
        if self.address is None:
            result = unic(_translate("MainWindow", "All accounts"))
            logger.debug(f"Address is None, returning 'All accounts': {result}")
            return result
        else:
            try:
                result = unic(ustr(
                    config.get(self.address, 'label')))
                logger.debug(f"Got label from config: {result}")
                return result
            except Exception as e:
                logger.debug(f"Error getting label from config: {e}, returning address")
                return unic(self.address)

    def _getAddressBracket(self, unreadCount=False):
        logger.debug(f"Ui_AddressWidget._getAddressBracket called with unreadCount={unreadCount}")
        ret = "" if self.isExpanded() \
            else super(Ui_AddressWidget, self)._getAddressBracket(unreadCount)
        if self.address is not None:
            ret += " (" + self.address + ")"
        logger.debug(f"Returning: {ret}")
        return ret

    def data(self, column, role):
        """Override internal QT method for returning object data"""
        logger.debug(f"Ui_AddressWidget.data called with column={column}, role={role}")
        if column == 0:
            if role == QtCore.Qt.DecorationRole:
                result = avatarize(
                    self.address or self._getLabel().encode('utf8'))
                logger.debug(f"DecorationRole result: {result}")
                return result
            elif role == QtCore.Qt.ForegroundRole:
                result = self.accountBrush()
                logger.debug(f"ForegroundRole result: {result}")
                return result
        result = super(Ui_AddressWidget, self).data(column, role)
        logger.debug(f"Super data result: {result}")
        return result

    def setData(self, column, role, value):
        """
        Save account label (if you edit in the the UI, this will be
        triggered and will save it to keys.dat)
        """
        logger.debug(f"Ui_AddressWidget.setData called with column={column}, role={role}, value={value}")
        if role == QtCore.Qt.EditRole \
                and self.type != AccountMixin.SUBSCRIPTION:
            config.set(self.address, 'label', ustr(value))
            config.save()
            logger.debug(f"Saved label '{value}' to config for address {self.address}")
        result = super(Ui_AddressWidget, self).setData(column, role, value)
        logger.debug(f"Super setData result: {result}")
        return result

    def setAddress(self, address):
        """Set address to object (for QT UI)"""
        logger.debug(f"Ui_AddressWidget.setAddress called with address={address}")
        super(Ui_AddressWidget, self).setAddress(address)
        self.setData(0, QtCore.Qt.UserRole, self.address)
        logger.debug(f"Set UserRole data to address: {self.address}")

    def _getSortRank(self):
        result = self.type if self.isEnabled else (self.type + 100)
        logger.debug(f"Ui_AddressWidget._getSortRank returning: {result}")
        return result

    # label (or address) alphabetically, disabled at the end
    def __lt__(self, other):
        logger.debug(f"Ui_AddressWidget.__lt__ called with other={other}")
        # pylint: disable=protected-access
        if isinstance(other, Ui_AddressWidget):
            reverse = QtCore.Qt.DescendingOrder == \
                self.treeWidget().header().sortIndicatorOrder()
            logger.debug(f"Reverse sorting: {reverse}")
            if self._getSortRank() == other._getSortRank():
                x = self._getLabel().lower()
                y = other._getLabel().lower()
                result = x < y
                logger.debug(f"Same sort rank, comparing labels: {x} < {y} = {result}")
                return result
            result = (
                not reverse
                if self._getSortRank() < other._getSortRank() else reverse
            )
            logger.debug(f"Different sort ranks, result: {result}")
            return result

        result = super(Ui_AddressWidget, self).__lt__(other)
        logger.debug(f"Super __lt__ result: {result}")
        return result


class Ui_SubscriptionWidget(Ui_AddressWidget):
    """Special treating of subscription addresses"""
    # pylint: disable=unused-argument
    def __init__(
        self, parent, pos=0, address="", unreadCount=0, label="",
        enabled=True
    ):
        logger.debug(f"Ui_SubscriptionWidget.__init__ called with parent={parent}, pos={pos}, address={address}, unreadCount={unreadCount}, label={label}, enabled={enabled}")
        super(Ui_SubscriptionWidget, self).__init__(
            parent, pos, address, unreadCount, enabled)

    def _getLabel(self):
        queryreturn = sqlQuery(
            'SELECT label FROM subscriptions WHERE address=?',
            dbstr(self.address))
        logger.debug(f"Ui_SubscriptionWidget._getLabel query result: {queryreturn}")
        if queryreturn:
            result = unic(ustr(queryreturn[-1][0]))
            logger.debug(f"Returning label from query: {result}")
            return result
        result = unic(self.address)
        logger.debug(f"Returning address as label: {result}")
        return result

    def setType(self):
        """Set account type"""
        logger.debug("Ui_SubscriptionWidget.setType called")
        super(Ui_SubscriptionWidget, self).setType()  # sets it editable
        self.type = AccountMixin.SUBSCRIPTION  # overrides type
        logger.debug(f"Set type to SUBSCRIPTION: {self.type}")

    def setData(self, column, role, value):
        """Save subscription label to database"""
        logger.debug(f"Ui_SubscriptionWidget.setData called with column={column}, role={role}, value={value}")
        if role == QtCore.Qt.EditRole:
            sqlExecute(
                'UPDATE subscriptions SET label=? WHERE address=?',
                dbstr(unic(ustr(value))), dbstr(self.address))
            logger.debug(f"Updated subscription label to '{value}' for address {self.address}")
        result = super(Ui_SubscriptionWidget, self).setData(column, role, value)
        logger.debug(f"Super setData result: {result}")
        return result


class BMTableWidgetItem(QtWidgets.QTableWidgetItem, SettingsMixin):
    """A common abstract class for Table widget item"""

    def __init__(self, label=None, unread=False):
        logger.debug(f"BMTableWidgetItem.__init__ called with label={label}, unread={unread}")
        super(QtWidgets.QTableWidgetItem, self).__init__()
        self.setLabel(label)
        self.setUnread(unread)
        self._setup()

    def _setup(self):
        logger.debug("BMTableWidgetItem._setup called")
        self.setFlags(QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
        logger.debug(f"Set flags to: {self.flags()}")

    def setLabel(self, label):
        """Set object label"""
        logger.debug(f"BMTableWidgetItem.setLabel called with: {label}")
        self.label = label
        logger.debug(f"Set label to: {self.label}")

    def setUnread(self, unread):
        """Set/unset read state of an item"""
        logger.debug(f"BMTableWidgetItem.setUnread called with: {unread}")
        self.unread = unread
        logger.debug(f"Set unread to: {self.unread}")

    def data(self, role):
        """Return object data (QT UI)"""
        logger.debug(f"BMTableWidgetItem.data called with role={role}")
        if role in (
            QtCore.Qt.DisplayRole, QtCore.Qt.EditRole, QtCore.Qt.ToolTipRole
        ):
            result = self.label
            logger.debug(f"Returning label: {result}")
            return result
        elif role == QtCore.Qt.FontRole:
            font = QtGui.QFont()
            font.setBold(self.unread)
            logger.debug(f"Returning font with bold={self.unread}")
            return font
        result = super(BMTableWidgetItem, self).data(role)
        logger.debug(f"Super data result: {result}")
        return result


class BMAddressWidget(BMTableWidgetItem, AccountMixin):
    """A common class for Table widget item with account"""

    def _setup(self):
        logger.debug("BMAddressWidget._setup called")
        super(BMAddressWidget, self)._setup()
        self.setEnabled(True)
        self.setType()
        logger.debug(f"Setup complete, type={self.type}, enabled={self.isEnabled}")

    def _getLabel(self):
        result = self.label
        logger.debug(f"BMAddressWidget._getLabel returning: {result}")
        return result

    def data(self, role):
        """Return object data (QT UI)"""
        logger.debug(f"BMAddressWidget.data called with role={role}")
        if role == QtCore.Qt.ToolTipRole:
            result = self.label + " (" + self.address + ")"
            logger.debug(f"ToolTipRole result: {result}")
            return result
        elif role == QtCore.Qt.DecorationRole:
            if config.safeGetBoolean(
                    'bitmessagesettings', 'useidenticons'):
                result = avatarize(self.address or self.label)
                logger.debug(f"DecorationRole result: {result}")
                return result
        elif role == QtCore.Qt.ForegroundRole:
            result = self.accountBrush()
            logger.debug(f"ForegroundRole result: {result}")
            return result
        result = super(BMAddressWidget, self).data(role)
        logger.debug(f"Super data result: {result}")
        return result


class MessageList_AddressWidget(BMAddressWidget):
    """Address item in a messagelist"""
    def __init__(self, address=None, label=None, unread=False):
        logger.debug(f"MessageList_AddressWidget.__init__ called with address={address}, label={label}, unread={unread}")
        self.setAddress(address)
        super(MessageList_AddressWidget, self).__init__(label, unread)

    def setLabel(self, label=None):
        """Set label"""
        logger.debug(f"MessageList_AddressWidget.setLabel called with: {label}")
        super(MessageList_AddressWidget, self).setLabel(label)
        if label is not None:
            logger.debug("Label provided, not calculating")
            return
        newLabel = self.address
        queryreturn = None
        if self.type in (
                AccountMixin.NORMAL,
                AccountMixin.CHAN, AccountMixin.MAILINGLIST):
            try:
                newLabel = unic(ustr(config.get(self.address, 'label')))
                logger.debug(f"Got label from config: {newLabel}")
            except Exception as e:
                logger.debug(f"Error getting label from config: {e}")
                queryreturn = sqlQuery(
                    'SELECT label FROM addressbook WHERE address=?',
                    dbstr(self.address))
        elif self.type == AccountMixin.SUBSCRIPTION:
            queryreturn = sqlQuery(
                'SELECT label FROM subscriptions WHERE address=?',
                dbstr(self.address))
            logger.debug(f"Got subscription query result: {queryreturn}")
        if queryreturn:
            newLabel = unic(ustr(queryreturn[-1][0]))
            logger.debug(f"Got label from query: {newLabel}")

        self.label = newLabel
        logger.debug(f"Set label to: {self.label}")

    def data(self, role):
        """Return object data (QT UI)"""
        logger.debug(f"MessageList_AddressWidget.data called with role={role}")
        if role == QtCore.Qt.UserRole:
            result = self.address
            logger.debug(f"UserRole result: {result}")
            return result
        result = super(MessageList_AddressWidget, self).data(role)
        logger.debug(f"Super data result: {result}")
        return result

    def setData(self, role, value):
        """Set object data"""
        logger.debug(f"MessageList_AddressWidget.setData called with role={role}, value={value}")
        if role == QtCore.Qt.EditRole:
            self.setLabel()
            logger.debug("EditRole triggered setLabel")
        result = super(MessageList_AddressWidget, self).setData(role, value)
        logger.debug(f"Super setData result: {result}")
        return result

    # label (or address) alphabetically, disabled at the end
    def __lt__(self, other):
        logger.debug(f"MessageList_AddressWidget.__lt__ called with other={other}")
        if isinstance(other, MessageList_AddressWidget):
            result = self.label.lower() < other.label.lower()
            logger.debug(f"Comparing labels: {self.label.lower()} < {other.label.lower()} = {result}")
            return result
        result = super(MessageList_AddressWidget, self).__lt__(other)
        logger.debug(f"Super __lt__ result: {result}")
        return result


class MessageList_SubjectWidget(BMTableWidgetItem):
    """Message list subject item"""
    def __init__(self, subject=None, label=None, unread=False):
        logger.debug(f"MessageList_SubjectWidget.__init__ called with subject={subject}, label={label}, unread={unread}")
        self.setSubject(subject)
        super(MessageList_SubjectWidget, self).__init__(label, unread)

    def setSubject(self, subject):
        """Set subject"""
        logger.debug(f"MessageList_SubjectWidget.setSubject called with: {subject}")
        self.subject = subject
        logger.debug(f"Set subject to: {self.subject}")

    def data(self, role):
        """Return object data (QT UI)"""
        logger.debug(f"MessageList_SubjectWidget.data called with role={role}")
        if role == QtCore.Qt.UserRole:
            result = ustr(self.subject)
            logger.debug(f"UserRole result: {result}")
            return result
        if role == QtCore.Qt.ToolTipRole:
            result = escape(unic(ustr(self.subject)))
            logger.debug(f"ToolTipRole result: {result}")
            return result
        result = super(MessageList_SubjectWidget, self).data(role)
        logger.debug(f"Super data result: {result}")
        return result

    # label (or address) alphabetically, disabled at the end
    def __lt__(self, other):
        logger.debug(f"MessageList_SubjectWidget.__lt__ called with other={other}")
        if isinstance(other, MessageList_SubjectWidget):
            result = self.label.lower() < other.label.lower()
            logger.debug(f"Comparing labels: {self.label.lower()} < {other.label.lower()} = {result}")
            return result
        result = super(MessageList_SubjectWidget, self).__lt__(other)
        logger.debug(f"Super __lt__ result: {result}")
        return result


class MessageList_TimeWidget(BMTableWidgetItem):
    """
    A subclass of QTableWidgetItem for received (lastactiontime) field.
    '<' operator is overloaded to sort by TimestampRole == 33
    msgid is available by QtCore.Qt.UserRole
    """

    def __init__(self, label=None, unread=False, timestamp=None, msgid=b''):
        logger.debug(f"MessageList_TimeWidget.__init__ called with label={label}, unread={unread}, timestamp={timestamp}, msgid={msgid}")
        super(MessageList_TimeWidget, self).__init__(label, unread)
        self.setData(QtCore.Qt.UserRole, QtCore.QByteArray(bytes(msgid)))
        self.setData(TimestampRole, int(timestamp))
        logger.debug(f"Set UserRole to msgid: {msgid}, TimestampRole to: {timestamp}")

    def __lt__(self, other):
        logger.debug(f"MessageList_TimeWidget.__lt__ called with other={other}")
        result = self.data(TimestampRole) < other.data(TimestampRole)
        logger.debug(f"Comparing timestamps: {self.data(TimestampRole)} < {other.data(TimestampRole)} = {result}")
        return result

    def data(self, role=QtCore.Qt.UserRole):
        """
        Returns expected python types for QtCore.Qt.UserRole and TimestampRole
        custom roles and super for any Qt role
        """
        logger.debug(f"MessageList_TimeWidget.data called with role={role}")
        data = super(MessageList_TimeWidget, self).data(role)
        if role == TimestampRole:
            result = int(data)
            logger.debug(f"TimestampRole result: {result}")
            return result
        if role == QtCore.Qt.UserRole:
            result = ustr(data)
            logger.debug(f"UserRole result: {result}")
            return result
        logger.debug(f"Super data result: {data}")
        return data


class Ui_AddressBookWidgetItem(BMAddressWidget):
    """Addressbook item"""
    def __init__(self, label=None, acc_type=AccountMixin.NORMAL):
        logger.debug(f"Ui_AddressBookWidgetItem.__init__ called with label={label}, acc_type={acc_type}")
        self.type = acc_type
        super(Ui_AddressBookWidgetItem, self).__init__(label=label)

    def data(self, role):
        """Return object data"""
        logger.debug(f"Ui_AddressBookWidgetItem.data called with role={role}")
        if role == QtCore.Qt.UserRole:
            result = self.type
            logger.debug(f"UserRole result: {result}")
            return result
        result = super(Ui_AddressBookWidgetItem, self).data(role)
        logger.debug(f"Super data result: {result}")
        return result

    def setData(self, role, value):
        """Set data"""
        logger.debug(f"Ui_AddressBookWidgetItem.setData called with role={role}, value={value}")
        if role == QtCore.Qt.EditRole:
            self.label = ustr(value)
            logger.debug(f"Set label to: {self.label}")
            if self.type in (
                    AccountMixin.NORMAL,
                    AccountMixin.MAILINGLIST, AccountMixin.CHAN):
                try:
                    config.get(self.address, 'label')
                    config.set(self.address, 'label', self.label)
                    config.save()
                    logger.debug(f"Saved label to config for address {self.address}")
                except Exception as e:
                    logger.debug(f"Error saving to config: {e}, trying SQL")
                    sqlExecute(
                        'UPDATE addressbook SET label=? WHERE address=?',
                        dbstr(self.label), dbstr(self.address)
                    )
                    logger.debug(f"Saved label to addressbook for address {self.address}")
            elif self.type == AccountMixin.SUBSCRIPTION:
                sqlExecute(
                    'UPDATE subscriptions SET label=? WHERE address=?',
                    dbstr(self.label), dbstr(self.address))
                logger.debug(f"Saved label to subscriptions for address {self.address}")
        result = super(Ui_AddressBookWidgetItem, self).setData(role, value)
        logger.debug(f"Super setData result: {result}")
        return result

    def __lt__(self, other):
        logger.debug(f"Ui_AddressBookWidgetItem.__lt__ called with other={other}")
        if not isinstance(other, Ui_AddressBookWidgetItem):
            result = super(Ui_AddressBookWidgetItem, self).__lt__(other)
            logger.debug(f"Other not AddressBookWidgetItem, super result: {result}")
            return result

        reverse = QtCore.Qt.DescendingOrder == \
            self.tableWidget().horizontalHeader().sortIndicatorOrder()
        logger.debug(f"Reverse sorting: {reverse}")

        if self.type == other.type:
            result = self.label.lower() < other.label.lower()
            logger.debug(f"Same type, comparing labels: {result}")
            return result

        result = not reverse if self.type < other.type else reverse
        logger.debug(f"Different types, result: {result}")
        return result


class Ui_AddressBookWidgetItemLabel(Ui_AddressBookWidgetItem):
    """Addressbook label item"""
    def __init__(self, address, label, acc_type):
        logger.debug(f"Ui_AddressBookWidgetItemLabel.__init__ called with address={address}, label={label}, acc_type={acc_type}")
        self.address = ustr(address)
        super(Ui_AddressBookWidgetItemLabel, self).__init__(label, acc_type)

    def data(self, role):
        """Return object data"""
        logger.debug(f"Ui_AddressBookWidgetItemLabel.data called with role={role}")
        self.label = self.defaultLabel()
        logger.debug(f"Set label to default: {self.label}")
        result = super(Ui_AddressBookWidgetItemLabel, self).data(role)
        logger.debug(f"Super data result: {result}")
        return result


class Ui_AddressBookWidgetItemAddress(Ui_AddressBookWidgetItem):
    """Addressbook address item"""
    def __init__(self, address, label, acc_type):
        logger.debug(f"Ui_AddressBookWidgetItemAddress.__init__ called with address={address}, label={label}, acc_type={acc_type}")
        self.address = ustr(address)
        super(Ui_AddressBookWidgetItemAddress, self).__init__(address, acc_type)

    def data(self, role):
        """Return object data"""
        logger.debug(f"Ui_AddressBookWidgetItemAddress.data called with role={role}")
        if role == QtCore.Qt.ToolTipRole:
            result = self.address
            logger.debug(f"ToolTipRole result: {result}")
            return result
        if role == QtCore.Qt.DecorationRole:
            logger.debug("DecorationRole returning None")
            return None
        result = super(Ui_AddressBookWidgetItemAddress, self).data(role)
        logger.debug(f"Super data result: {result}")
        return result


class AddressBookCompleter(QtWidgets.QCompleter):
    """Addressbook completer"""
    def __init__(self):
        logger.debug("AddressBookCompleter.__init__ called")
        super(AddressBookCompleter, self).__init__()
        self.cursorPos = -1
        logger.debug(f"Initialized with cursorPos={self.cursorPos}")

    def onCursorPositionChanged(self, oldPos, newPos):
        """Callback for cursor position change"""
        logger.debug(f"AddressBookCompleter.onCursorPositionChanged called with oldPos={oldPos}, newPos={newPos}")
        # pylint: disable=unused-argument
        if oldPos != self.cursorPos:
            self.cursorPos = -1
            logger.debug("Reset cursorPos to -1")

    def splitPath(self, path):
        """Split on semicolon"""
        logger.debug(f"AddressBookCompleter.splitPath called with path={path}")
        text = unic(ustr(path))
        result = [text[:self.widget().cursorPosition()].split(';')[-1].strip()]
        logger.debug(f"Returning split path: {result}")
        return result

    def pathFromIndex(self, index):
        """Perform autocompletion (reimplemented QCompleter method)"""
        logger.debug(f"AddressBookCompleter.pathFromIndex called with index={index}")
        autoString = unic(ustr(index.data(QtCore.Qt.EditRole).toString()))
        text = unic(ustr(self.widget().text()))
        logger.debug(f"autoString={autoString}, text={text}")

        # If cursor position was saved, restore it, else save it
        if self.cursorPos != -1:
            self.widget().setCursorPosition(self.cursorPos)
            logger.debug(f"Restored cursor position to: {self.cursorPos}")
        else:
            self.cursorPos = self.widget().cursorPosition()
            logger.debug(f"Saved cursor position: {self.cursorPos}")

        # Get current prosition
        curIndex = self.widget().cursorPosition()
        logger.debug(f"Current cursor position: {curIndex}")

        # prev_delimiter_index should actually point at final white space
        # AFTER the delimiter
        # Get index of last delimiter before current position
        prevDelimiterIndex = text[0:curIndex].rfind(";")
        while text[prevDelimiterIndex + 1] == " ":
            prevDelimiterIndex += 1
        logger.debug(f"Previous delimiter index: {prevDelimiterIndex}")

        # Get index of first delimiter after current position
        # (or EOL if no delimiter after cursor)
        nextDelimiterIndex = text.find(";", curIndex)
        if nextDelimiterIndex == -1:
            nextDelimiterIndex = len(text)
        logger.debug(f"Next delimiter index: {nextDelimiterIndex}")

        # Get part of string that occurs before cursor
        part1 = text[0:prevDelimiterIndex + 1]
        logger.debug(f"Part1: {part1}")

        # Get part of string that occurs AFTER cursor
        part2 = text[nextDelimiterIndex:]
        logger.debug(f"Part2: {part2}")

        result = part1 + autoString + part2
        logger.debug(f"Returning path: {result}")
        return result
