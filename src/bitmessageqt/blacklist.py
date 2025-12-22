from unqstr import ustr, unic
from dbcompat import dbstr
from qtpy import QtCore, QtGui, QtWidgets

import logging
import sys
from bitmessageqt import widgets
from addresses import addBMIfNotPresent
from bmconfigparser import config
from .dialogs import AddAddressDialog
from helper_sql import sqlExecute, sqlQuery
from queues import UISignalQueue
from .retranslateui import RetranslateMixin
from tr import _translate
from .uisignaler import UISignaler
from .utils import avatarize
from helper_sql import safe_decode

# Set up basic logging configuration
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

class Blacklist(QtWidgets.QWidget, RetranslateMixin):
    def __init__(self, parent=None):
        logger.debug("Blacklist.__init__ called with parent=%s", parent)
        super(Blacklist, self).__init__(parent)
        logger.debug("Loading blacklist.ui")
        widgets.load('blacklist.ui', self)

        logger.debug("Setting up signal connections")
        self.radioButtonBlacklist.clicked.connect(
            self.click_radioButtonBlacklist)
        self.radioButtonWhitelist.clicked.connect(
            self.click_radioButtonWhitelist)
        self.pushButtonAddBlacklist.clicked.connect(
            self.click_pushButtonAddBlacklist)

        logger.debug("Initializing blacklist popup menu")
        self.init_blacklist_popup_menu()

        self.tableWidgetBlacklist.itemChanged.connect(
            self.tableWidgetBlacklistItemChanged)

        # Set the icon sizes for the identicons
        identicon_size = 3 * 7
        logger.debug("Setting identicon size to %s", identicon_size)
        self.tableWidgetBlacklist.setIconSize(
            QtCore.QSize(identicon_size, identicon_size))

        logger.debug("Setting up UI signal thread")
        self.UISignalThread = UISignaler.get()
        self.UISignalThread.rerenderBlackWhiteList.connect(
            self.rerenderBlackWhiteList)
        logger.debug("Blacklist initialization complete")

    def click_radioButtonBlacklist(self):
        logger.debug("click_radioButtonBlacklist called")
        current_mode = config.get('bitmessagesettings', 'blackwhitelist')
        logger.debug("Current mode: %s", current_mode)
        if current_mode == 'white':
            logger.debug("Switching to blacklist mode")
            config.set('bitmessagesettings', 'blackwhitelist', 'black')
            config.save()
            logger.debug("Clearing table widget")
            self.tableWidgetBlacklist.setRowCount(0)
            self.rerenderBlackWhiteList()

    def click_radioButtonWhitelist(self):
        logger.debug("click_radioButtonWhitelist called")
        current_mode = config.get('bitmessagesettings', 'blackwhitelist')
        logger.debug("Current mode: %s", current_mode)
        if current_mode == 'black':
            logger.debug("Switching to whitelist mode")
            config.set('bitmessagesettings', 'blackwhitelist', 'white')
            config.save()
            logger.debug("Clearing table widget")
            self.tableWidgetBlacklist.setRowCount(0)
            self.rerenderBlackWhiteList()

    def click_pushButtonAddBlacklist(self):
        logger.debug("click_pushButtonAddBlacklist called")
        self.NewBlacklistDialogInstance = AddAddressDialog(self)
        logger.debug("Showing AddAddressDialog")
        if self.NewBlacklistDialogInstance.exec_():
            logger.debug("Dialog accepted")
            if self.NewBlacklistDialogInstance.labelAddressCheck.text() == \
                    _translate("MainWindow", "Address is valid."):
                logger.debug("Address validation passed")
                address = addBMIfNotPresent(ustr(
                    self.NewBlacklistDialogInstance.lineEditAddress.text()))
                logger.debug("Processed address: %s", address)
                
                t = (dbstr(address),)
                list_type = config.get('bitmessagesettings', 'blackwhitelist')
                logger.debug("Current list type: %s", list_type)
                
                if list_type == 'black':
                    sql = '''select * from blacklist where address=?'''
                else:
                    sql = '''select * from whitelist where address=?'''
                
                logger.debug("Checking if address exists in list")
                queryreturn = sqlQuery(sql, *t)
                if queryreturn == []:
                    logger.debug("Address not in list, adding new entry")
                    self.tableWidgetBlacklist.setSortingEnabled(False)
                    self.tableWidgetBlacklist.insertRow(0)
                    
                    label = unic(ustr(self.NewBlacklistDialogInstance.lineEditLabel.text()))
                    logger.debug("Adding label: %s", label)
                    newItem = QtWidgets.QTableWidgetItem(label)
                    newItem.setIcon(avatarize(address))
                    self.tableWidgetBlacklist.setItem(0, 0, newItem)
                    
                    logger.debug("Adding address: %s", address)
                    newItem = QtWidgets.QTableWidgetItem(address)
                    newItem.setFlags(
                        QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
                    self.tableWidgetBlacklist.setItem(0, 1, newItem)
                    self.tableWidgetBlacklist.setSortingEnabled(True)
                    
                    t = (
                        dbstr(self.NewBlacklistDialogInstance.lineEditLabel.text()), 
                        dbstr(address), 
                        True
                    )
                    if list_type == 'black':
                        sql = '''INSERT INTO blacklist VALUES (?,?,?)'''
                    else:
                        sql = '''INSERT INTO whitelist VALUES (?,?,?)'''
                    
                    logger.debug("Executing SQL: %s with params %s", sql, t)
                    sqlExecute(sql, *t)
                else:
                    logger.debug("Address already in list, showing error")
                    error_msg = _translate(
                        "MainWindow",
                        "Error: You cannot add the same address to your"
                        " list twice. Perhaps rename the existing one"
                        " if you want.")
                    logger.debug("Queueing status bar update: %s", error_msg)
                    UISignalQueue.put(('updateStatusBar', error_msg))
            else:
                logger.debug("Address validation failed")
                error_msg = _translate(
                    "MainWindow",
                    "The address you entered was invalid. Ignoring it.")
                logger.debug("Queueing status bar update: %s", error_msg)
                UISignalQueue.put(('updateStatusBar', error_msg))

    def tableWidgetBlacklistItemChanged(self, item):
        logger.debug("tableWidgetBlacklistItemChanged called for item at column %s", item.column())
        if item.column() == 0:
            addressitem = self.tableWidgetBlacklist.item(item.row(), 1)
            if isinstance(addressitem, QtWidgets.QTableWidgetItem):
                logger.debug("Updating label for address: %s", addressitem.text())
                if self.radioButtonBlacklist.isChecked():
                    sql = '''UPDATE blacklist SET label=? WHERE address=?'''
                else:
                    sql = '''UPDATE whitelist SET label=? WHERE address=?'''
                
                logger.debug("Executing SQL: %s with params (%s, %s)", 
                           sql, item.text(), addressitem.text())
                sqlExecute(sql, dbstr(item.text()), dbstr(addressitem.text()))

    def init_blacklist_popup_menu(self, connectSignal=True):
        logger.debug("init_blacklist_popup_menu called with connectSignal=%s", connectSignal)
        # Popup menu for the Blacklist page
        self.blacklistContextMenuToolbar = QtWidgets.QToolBar()
        
        # Actions
        logger.debug("Creating context menu actions")
        self.actionBlacklistNew = self.blacklistContextMenuToolbar.addAction(
            _translate("MainWindow", "Add new entry"), self.on_action_BlacklistNew)
        self.actionBlacklistDelete = self.blacklistContextMenuToolbar.addAction(
            _translate("MainWindow", "Delete"), self.on_action_BlacklistDelete)
        self.actionBlacklistClipboard = self.blacklistContextMenuToolbar.addAction(
            _translate("MainWindow", "Copy address to clipboard"),
            self.on_action_BlacklistClipboard)
        self.actionBlacklistEnable = self.blacklistContextMenuToolbar.addAction(
            _translate("MainWindow", "Enable"), self.on_action_BlacklistEnable)
        self.actionBlacklistDisable = self.blacklistContextMenuToolbar.addAction(
            _translate("MainWindow", "Disable"), self.on_action_BlacklistDisable)
        self.actionBlacklistSetAvatar = self.blacklistContextMenuToolbar.addAction(
            _translate("MainWindow", "Set avatar..."),
            self.on_action_BlacklistSetAvatar)
        
        self.tableWidgetBlacklist.setContextMenuPolicy(
            QtCore.Qt.CustomContextMenu)
        if connectSignal:
            logger.debug("Connecting context menu signal")
            self.tableWidgetBlacklist.customContextMenuRequested.connect(
                self.on_context_menuBlacklist)
        
        self.popMenuBlacklist = QtWidgets.QMenu(self)
        self.popMenuBlacklist.addAction(self.actionBlacklistDelete)
        self.popMenuBlacklist.addSeparator()
        self.popMenuBlacklist.addAction(self.actionBlacklistClipboard)
        self.popMenuBlacklist.addSeparator()
        self.popMenuBlacklist.addAction(self.actionBlacklistEnable)
        self.popMenuBlacklist.addAction(self.actionBlacklistDisable)
        self.popMenuBlacklist.addAction(self.actionBlacklistSetAvatar)
        logger.debug("Context menu initialization complete")

    def rerenderBlackWhiteList(self):
        logger.debug("rerenderBlackWhiteList called")
        tabs = self.parent().parent()
        list_type = config.get('bitmessagesettings', 'blackwhitelist')
        logger.debug("Current list type: %s", list_type)
        
        if list_type == 'black':
            tab_text = _translate('blacklist', 'Blacklist')
        else:
            tab_text = _translate('blacklist', 'Whitelist')
        
        logger.debug("Setting tab text to: %s", tab_text)
        tabs.setTabText(tabs.indexOf(self), tab_text)
        
        logger.debug("Clearing table widget")
        self.tableWidgetBlacklist.setRowCount(0)
        
        if list_type == 'black':
            sql = '''SELECT label, address, enabled FROM blacklist'''
        else:
            sql = '''SELECT label, address, enabled FROM whitelist'''
        
        logger.debug("Querying database with: %s", sql)
        queryreturn = sqlQuery(sql)
        
        self.tableWidgetBlacklist.setSortingEnabled(False)
        for row in queryreturn:
            label, address, enabled = row
            label = safe_decode(label, "utf-8", "replace")
            address = safe_decode(address, "utf-8", "replace")
            logger.debug("Processing entry - label: %s, address: %s, enabled: %s", 
                       label, address, enabled)
            
            self.tableWidgetBlacklist.insertRow(0)
            newItem = QtWidgets.QTableWidgetItem(unic(ustr(label)))
            if not enabled:
                logger.debug("Entry disabled, setting gray color")
                newItem.setForeground(QtGui.QColor(128, 128, 128))
            newItem.setIcon(avatarize(address))
            self.tableWidgetBlacklist.setItem(0, 0, newItem)
            
            newItem = QtWidgets.QTableWidgetItem(address)
            newItem.setFlags(
                QtCore.Qt.ItemIsSelectable | QtCore.Qt.ItemIsEnabled)
            if not enabled:
                newItem.setForeground(QtGui.QColor(128, 128, 128))
            self.tableWidgetBlacklist.setItem(0, 1, newItem)
        
        self.tableWidgetBlacklist.setSortingEnabled(True)
        logger.debug("Black/White list rendering complete")

    # Group of functions for the Blacklist dialog box
    def on_action_BlacklistNew(self):
        logger.debug("on_action_BlacklistNew called")
        self.click_pushButtonAddBlacklist()

    def on_action_BlacklistDelete(self):
        logger.debug("on_action_BlacklistDelete called")
        currentRow = self.tableWidgetBlacklist.currentRow()
        labelAtCurrentRow = ustr(self.tableWidgetBlacklist.item(
            currentRow, 0).text())
        addressAtCurrentRow = self.tableWidgetBlacklist.item(
            currentRow, 1).text()
        logger.debug("Deleting row %s - label: %s, address: %s", 
                   currentRow, labelAtCurrentRow, addressAtCurrentRow)
        
        list_type = config.get('bitmessagesettings', 'blackwhitelist')
        if list_type == 'black':
            sql = '''DELETE FROM blacklist WHERE label=? AND address=?'''
        else:
            sql = '''DELETE FROM whitelist WHERE label=? AND address=?'''
        
        logger.debug("Executing SQL: %s with params (%s, %s)", 
                   sql, labelAtCurrentRow, addressAtCurrentRow)
        sqlExecute(sql, dbstr(labelAtCurrentRow), dbstr(addressAtCurrentRow))
        self.tableWidgetBlacklist.removeRow(currentRow)

    def on_action_BlacklistClipboard(self):
        logger.debug("on_action_BlacklistClipboard called")
        currentRow = self.tableWidgetBlacklist.currentRow()
        addressAtCurrentRow = self.tableWidgetBlacklist.item(
            currentRow, 1).text()
        logger.debug("Copying address to clipboard: %s", addressAtCurrentRow)
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText(ustr(addressAtCurrentRow))

    def on_context_menuBlacklist(self, point):
        logger.debug("on_context_menuBlacklist called at point %s", point)
        self.popMenuBlacklist.exec_(
            self.tableWidgetBlacklist.mapToGlobal(point))

    def on_action_BlacklistEnable(self):
        logger.debug("on_action_BlacklistEnable called")
        currentRow = self.tableWidgetBlacklist.currentRow()
        addressAtCurrentRow = self.tableWidgetBlacklist.item(
            currentRow, 1).text()
        logger.debug("Enabling address: %s", addressAtCurrentRow)
        
        self.tableWidgetBlacklist.item(currentRow, 0).setForeground(
            QtWidgets.QApplication.palette().text().color())
        self.tableWidgetBlacklist.item(currentRow, 1).setForeground(
            QtWidgets.QApplication.palette().text().color())
        
        list_type = config.get('bitmessagesettings', 'blackwhitelist')
        if list_type == 'black':
            sql = '''UPDATE blacklist SET enabled=1 WHERE address=?'''
        else:
            sql = '''UPDATE whitelist SET enabled=1 WHERE address=?'''
        
        logger.debug("Executing SQL: %s with param %s", sql, addressAtCurrentRow)
        sqlExecute(sql, dbstr(addressAtCurrentRow))

    def on_action_BlacklistDisable(self):
        logger.debug("on_action_BlacklistDisable called")
        currentRow = self.tableWidgetBlacklist.currentRow()
        addressAtCurrentRow = self.tableWidgetBlacklist.item(
            currentRow, 1).text()
        logger.debug("Disabling address: %s", addressAtCurrentRow)
        
        self.tableWidgetBlacklist.item(currentRow, 0).setForeground(
            QtGui.QColor(128, 128, 128))
        self.tableWidgetBlacklist.item(currentRow, 1).setForeground(
            QtGui.QColor(128, 128, 128))
        
        list_type = config.get('bitmessagesettings', 'blackwhitelist')
        if list_type == 'black':
            sql = '''UPDATE blacklist SET enabled=0 WHERE address=?'''
        else:
            sql = '''UPDATE whitelist SET enabled=0 WHERE address=?'''
        
        logger.debug("Executing SQL: %s with param %s", sql, addressAtCurrentRow)
        sqlExecute(sql, dbstr(addressAtCurrentRow))

    def on_action_BlacklistSetAvatar(self):
        logger.debug("on_action_BlacklistSetAvatar called")
        self.window().on_action_SetAvatar(self.tableWidgetBlacklist)
