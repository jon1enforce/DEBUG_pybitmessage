# pylint: skip-file
# flake8: noqa

from qtpy import QtCore, QtGui, QtWidgets
from tr import _translate
from bmconfigparser import config
from .foldertree import AddressBookCompleter
from .messageview import MessageView
from .messagecompose import MessageCompose
from bitmessageqt import settingsmixin
from .networkstatus import NetworkStatus
from .blacklist import Blacklist
from bitmessageqt import bitmessage_icons_rc

import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        logger.debug("DEBUG: Setting up main UI")
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(885, 580)
        logger.debug("DEBUG: Main window resized to 885x580")
        
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/newPrefix/images/can-icon-24px.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        MainWindow.setWindowIcon(icon)
        MainWindow.setTabShape(QtWidgets.QTabWidget.Rounded)
        
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout_10 = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout_10.setObjectName("gridLayout_10")
        
        logger.debug("DEBUG: Creating tab widget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.tabWidget.sizePolicy().hasHeightForWidth())
        self.tabWidget.setSizePolicy(sizePolicy)
        self.tabWidget.setMinimumSize(QtCore.QSize(0, 0))
        self.tabWidget.setBaseSize(QtCore.QSize(0, 0))
        font = QtGui.QFont()
        base_size = QtWidgets.QApplication.instance().font().pointSize()
        font.setPointSize(int(base_size * 0.75))
        self.tabWidget.setFont(font)
        self.tabWidget.setTabPosition(QtWidgets.QTabWidget.North)
        self.tabWidget.setTabShape(QtWidgets.QTabWidget.Rounded)
        self.tabWidget.setObjectName("tabWidget")
        
        # Inbox Tab
        logger.debug("DEBUG: Setting up inbox tab")
        self.inbox = QtWidgets.QWidget()
        self.inbox.setObjectName("inbox")
        self.gridLayout = QtWidgets.QGridLayout(self.inbox)
        self.gridLayout.setObjectName("gridLayout")
        
        self.horizontalSplitter_3 = settingsmixin.SSplitter()
        self.horizontalSplitter_3.setObjectName("horizontalSplitter_3")
        
        self.verticalSplitter_12 = settingsmixin.SSplitter()
        self.verticalSplitter_12.setObjectName("verticalSplitter_12")
        self.verticalSplitter_12.setOrientation(QtCore.Qt.Vertical)
        
        self.treeWidgetYourIdentities = settingsmixin.STreeWidget(self.inbox)
        self.treeWidgetYourIdentities.setObjectName("treeWidgetYourIdentities")
        self.treeWidgetYourIdentities.resize(200, self.treeWidgetYourIdentities.height())
        icon1 = QtGui.QIcon()
        icon1.addPixmap(QtGui.QPixmap(":/newPrefix/images/identities.png"), QtGui.QIcon.Selected, QtGui.QIcon.Off)
        self.treeWidgetYourIdentities.headerItem().setIcon(0, icon1)
        self.verticalSplitter_12.addWidget(self.treeWidgetYourIdentities)
        
        self.pushButtonNewAddress = QtWidgets.QPushButton(self.inbox)
        self.pushButtonNewAddress.setObjectName("pushButtonNewAddress")
        self.pushButtonNewAddress.resize(200, self.pushButtonNewAddress.height())
        self.verticalSplitter_12.addWidget(self.pushButtonNewAddress)
        
        self.verticalSplitter_12.setStretchFactor(0, 1)
        self.verticalSplitter_12.setStretchFactor(1, 0)
        self.verticalSplitter_12.setCollapsible(0, False)
        self.verticalSplitter_12.setCollapsible(1, False)
        self.verticalSplitter_12.handle(1).setEnabled(False)
        
        self.horizontalSplitter_3.addWidget(self.verticalSplitter_12)
        
        self.verticalSplitter_7 = settingsmixin.SSplitter()
        self.verticalSplitter_7.setObjectName("verticalSplitter_7")
        self.verticalSplitter_7.setOrientation(QtCore.Qt.Vertical)
        
        self.horizontalSplitterSearch = QtWidgets.QSplitter()
        self.horizontalSplitterSearch.setObjectName("horizontalSplitterSearch")
        
        self.inboxSearchLineEdit = QtWidgets.QLineEdit(self.inbox)
        self.inboxSearchLineEdit.setObjectName("inboxSearchLineEdit")
        self.horizontalSplitterSearch.addWidget(self.inboxSearchLineEdit)
        
        self.inboxSearchOption = QtWidgets.QComboBox(self.inbox)
        self.inboxSearchOption.setObjectName("inboxSearchOption")
        self.inboxSearchOption.addItem("")
        self.inboxSearchOption.addItem("")
        self.inboxSearchOption.addItem("")
        self.inboxSearchOption.addItem("")
        self.inboxSearchOption.addItem("")
        self.inboxSearchOption.setSizeAdjustPolicy(QtWidgets.QComboBox.AdjustToContents)
        self.inboxSearchOption.setCurrentIndex(3)
        self.horizontalSplitterSearch.addWidget(self.inboxSearchOption)
        
        self.horizontalSplitterSearch.handle(1).setEnabled(False)
        self.horizontalSplitterSearch.setStretchFactor(0, 1)
        self.horizontalSplitterSearch.setStretchFactor(1, 0)
        
        self.verticalSplitter_7.addWidget(self.horizontalSplitterSearch)
        
        self.tableWidgetInbox = settingsmixin.STableWidget(self.inbox)
        self.tableWidgetInbox.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tableWidgetInbox.setAlternatingRowColors(True)
        self.tableWidgetInbox.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.tableWidgetInbox.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tableWidgetInbox.setWordWrap(False)
        self.tableWidgetInbox.setObjectName("tableWidgetInbox")
        self.tableWidgetInbox.setColumnCount(4)
        self.tableWidgetInbox.setRowCount(0)
        
        item = QtWidgets.QTableWidgetItem()
        self.tableWidgetInbox.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidgetInbox.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidgetInbox.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidgetInbox.setHorizontalHeaderItem(3, item)
        
        self.tableWidgetInbox.horizontalHeader().setCascadingSectionResizes(True)
        self.tableWidgetInbox.horizontalHeader().setDefaultSectionSize(200)
        self.tableWidgetInbox.horizontalHeader().setHighlightSections(False)
        self.tableWidgetInbox.horizontalHeader().setMinimumSectionSize(27)
        self.tableWidgetInbox.horizontalHeader().setSortIndicatorShown(False)
        self.tableWidgetInbox.horizontalHeader().setStretchLastSection(True)
        self.tableWidgetInbox.verticalHeader().setVisible(False)
        self.tableWidgetInbox.verticalHeader().setDefaultSectionSize(26)
        
        self.verticalSplitter_7.addWidget(self.tableWidgetInbox)
        
        self.textEditInboxMessage = MessageView(self.inbox)
        self.textEditInboxMessage.setBaseSize(QtCore.QSize(0, 500))
        self.textEditInboxMessage.setReadOnly(True)
        self.textEditInboxMessage.setObjectName("textEditInboxMessage")
        self.verticalSplitter_7.addWidget(self.textEditInboxMessage)
        
        self.verticalSplitter_7.setStretchFactor(0, 0)
        self.verticalSplitter_7.setStretchFactor(1, 1)
        self.verticalSplitter_7.setStretchFactor(2, 2)
        self.verticalSplitter_7.setCollapsible(0, False)
        self.verticalSplitter_7.setCollapsible(1, False)
        self.verticalSplitter_7.setCollapsible(2, False)
        self.verticalSplitter_7.handle(1).setEnabled(False)
        
        self.horizontalSplitter_3.addWidget(self.verticalSplitter_7)
        self.horizontalSplitter_3.setStretchFactor(0, 0)
        self.horizontalSplitter_3.setStretchFactor(1, 1)
        self.horizontalSplitter_3.setCollapsible(0, False)
        self.horizontalSplitter_3.setCollapsible(1, False)
        
        self.gridLayout.addWidget(self.horizontalSplitter_3)
        
        icon2 = QtGui.QIcon()
        icon2.addPixmap(QtGui.QPixmap(":/newPrefix/images/inbox.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.tabWidget.addTab(self.inbox, icon2, "")
        
        # Send Tab
        logger.debug("DEBUG: Setting up send tab")
        self.send = QtWidgets.QWidget()
        self.send.setObjectName("send")
        self.gridLayout_7 = QtWidgets.QGridLayout(self.send)
        self.gridLayout_7.setObjectName("gridLayout_7")
        
        self.horizontalSplitter = settingsmixin.SSplitter()
        self.horizontalSplitter.setObjectName("horizontalSplitter")
        
        self.verticalSplitter_2 = settingsmixin.SSplitter()
        self.verticalSplitter_2.setObjectName("verticalSplitter_2")
        self.verticalSplitter_2.setOrientation(QtCore.Qt.Vertical)
        
        self.tableWidgetAddressBook = settingsmixin.STableWidget(self.send)
        self.tableWidgetAddressBook.setAlternatingRowColors(True)
        self.tableWidgetAddressBook.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.tableWidgetAddressBook.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tableWidgetAddressBook.setObjectName("tableWidgetAddressBook")
        self.tableWidgetAddressBook.setColumnCount(2)
        self.tableWidgetAddressBook.setRowCount(0)
        self.tableWidgetAddressBook.resize(200, self.tableWidgetAddressBook.height())
        
        item = QtWidgets.QTableWidgetItem()
        icon3 = QtGui.QIcon()
        icon3.addPixmap(QtGui.QPixmap(":/newPrefix/images/addressbook.png"), QtGui.QIcon.Selected, QtGui.QIcon.Off)
        item.setIcon(icon3)
        self.tableWidgetAddressBook.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidgetAddressBook.setHorizontalHeaderItem(1, item)
        
        self.tableWidgetAddressBook.horizontalHeader().setCascadingSectionResizes(True)
        self.tableWidgetAddressBook.horizontalHeader().setDefaultSectionSize(200)
        self.tableWidgetAddressBook.horizontalHeader().setHighlightSections(False)
        self.tableWidgetAddressBook.horizontalHeader().setStretchLastSection(True)
        self.tableWidgetAddressBook.verticalHeader().setVisible(False)
        self.tableWidgetAddressBook.setWordWrap(False)
        
        self.verticalSplitter_2.addWidget(self.tableWidgetAddressBook)
        
        self.addressBookCompleter = AddressBookCompleter()
        self.addressBookCompleter.setCompletionMode(QtWidgets.QCompleter.PopupCompletion)
        self.addressBookCompleter.setCaseSensitivity(QtCore.Qt.CaseInsensitive)
        self.addressBookCompleterModel = QtCore.QStringListModel()
        self.addressBookCompleter.setModel(self.addressBookCompleterModel)
        
        self.pushButtonAddAddressBook = QtWidgets.QPushButton(self.send)
        self.pushButtonAddAddressBook.setObjectName("pushButtonAddAddressBook")
        self.pushButtonAddAddressBook.resize(200, self.pushButtonAddAddressBook.height())
        self.verticalSplitter_2.addWidget(self.pushButtonAddAddressBook)
        
        self.pushButtonFetchNamecoinID = QtWidgets.QPushButton(self.send)
        self.pushButtonFetchNamecoinID.resize(200, self.pushButtonFetchNamecoinID.height())
        self.pushButtonFetchNamecoinID.setObjectName("pushButtonFetchNamecoinID")
        self.verticalSplitter_2.addWidget(self.pushButtonFetchNamecoinID)
        
        self.verticalSplitter_2.setStretchFactor(0, 1)
        self.verticalSplitter_2.setStretchFactor(1, 0)
        self.verticalSplitter_2.setStretchFactor(2, 0)
        self.verticalSplitter_2.setCollapsible(0, False)
        self.verticalSplitter_2.setCollapsible(1, False)
        self.verticalSplitter_2.setCollapsible(2, False)
        self.verticalSplitter_2.handle(1).setEnabled(False)
        self.verticalSplitter_2.handle(2).setEnabled(False)
        
        self.horizontalSplitter.addWidget(self.verticalSplitter_2)
        
        self.verticalSplitter = settingsmixin.SSplitter()
        self.verticalSplitter.setObjectName("verticalSplitter")
        self.verticalSplitter.setOrientation(QtCore.Qt.Vertical)
        
        self.tabWidgetSend = QtWidgets.QTabWidget(self.send)
        self.tabWidgetSend.setObjectName("tabWidgetSend")
        
        # Send Direct Tab
        logger.debug("DEBUG: Setting up send direct tab")
        self.sendDirect = QtWidgets.QWidget()
        self.sendDirect.setObjectName("sendDirect")
        self.gridLayout_8 = QtWidgets.QGridLayout(self.sendDirect)
        self.gridLayout_8.setObjectName("gridLayout_8")
        
        self.verticalSplitter_5 = settingsmixin.SSplitter()
        self.verticalSplitter_5.setObjectName("verticalSplitter_5")
        self.verticalSplitter_5.setOrientation(QtCore.Qt.Vertical)
        
        self.gridLayout_2 = QtWidgets.QGridLayout()
        self.gridLayout_2.setObjectName("gridLayout_2")
        
        self.label_3 = QtWidgets.QLabel(self.sendDirect)
        self.label_3.setObjectName("label_3")
        self.gridLayout_2.addWidget(self.label_3, 2, 0, 1, 1)
        
        self.label_2 = QtWidgets.QLabel(self.sendDirect)
        self.label_2.setObjectName("label_2")
        self.gridLayout_2.addWidget(self.label_2, 0, 0, 1, 1)
        
        self.lineEditSubject = QtWidgets.QLineEdit(self.sendDirect)
        self.lineEditSubject.setText("")
        self.lineEditSubject.setObjectName("lineEditSubject")
        self.gridLayout_2.addWidget(self.lineEditSubject, 2, 1, 1, 1)
        
        self.label = QtWidgets.QLabel(self.sendDirect)
        self.label.setObjectName("label")
        self.gridLayout_2.addWidget(self.label, 1, 0, 1, 1)
        
        self.comboBoxSendFrom = QtWidgets.QComboBox(self.sendDirect)
        self.comboBoxSendFrom.setMinimumSize(QtCore.QSize(300, 0))
        self.comboBoxSendFrom.setObjectName("comboBoxSendFrom")
        self.gridLayout_2.addWidget(self.comboBoxSendFrom, 0, 1, 1, 1)
        
        self.lineEditTo = QtWidgets.QLineEdit(self.sendDirect)
        self.lineEditTo.setObjectName("lineEditTo")
        self.gridLayout_2.addWidget(self.lineEditTo, 1, 1, 1, 1)
        self.lineEditTo.setCompleter(self.addressBookCompleter)
        
        self.gridLayout_2_Widget = QtWidgets.QWidget()
        self.gridLayout_2_Widget.setLayout(self.gridLayout_2)
        self.verticalSplitter_5.addWidget(self.gridLayout_2_Widget)
        
        self.textEditMessage = MessageCompose(self.sendDirect)
        self.textEditMessage.setObjectName("textEditMessage")
        self.verticalSplitter_5.addWidget(self.textEditMessage)
        
        self.verticalSplitter_5.setStretchFactor(0, 0)
        self.verticalSplitter_5.setStretchFactor(1, 1)
        self.verticalSplitter_5.setCollapsible(0, False)
        self.verticalSplitter_5.setCollapsible(1, False)
        self.verticalSplitter_5.handle(1).setEnabled(False)
        
        self.gridLayout_8.addWidget(self.verticalSplitter_5, 0, 0, 1, 1)
        self.tabWidgetSend.addTab(self.sendDirect, "")
        
        # Send Broadcast Tab
        logger.debug("DEBUG: Setting up send broadcast tab")
        self.sendBroadcast = QtWidgets.QWidget()
        self.sendBroadcast.setObjectName("sendBroadcast")
        self.gridLayout_9 = QtWidgets.QGridLayout(self.sendBroadcast)
        self.gridLayout_9.setObjectName("gridLayout_9")
        
        self.verticalSplitter_6 = settingsmixin.SSplitter()
        self.verticalSplitter_6.setObjectName("verticalSplitter_6")
        self.verticalSplitter_6.setOrientation(QtCore.Qt.Vertical)
        
        self.gridLayout_5 = QtWidgets.QGridLayout()
        self.gridLayout_5.setObjectName("gridLayout_5")
        
        self.label_8 = QtWidgets.QLabel(self.sendBroadcast)
        self.label_8.setObjectName("label_8")
        self.gridLayout_5.addWidget(self.label_8, 0, 0, 1, 1)
        
        self.lineEditSubjectBroadcast = QtWidgets.QLineEdit(self.sendBroadcast)
        self.lineEditSubjectBroadcast.setText("")
        self.lineEditSubjectBroadcast.setObjectName("lineEditSubjectBroadcast")
        self.gridLayout_5.addWidget(self.lineEditSubjectBroadcast, 1, 1, 1, 1)
        
        self.label_7 = QtWidgets.QLabel(self.sendBroadcast)
        self.label_7.setObjectName("label_7")
        self.gridLayout_5.addWidget(self.label_7, 1, 0, 1, 1)
        
        self.comboBoxSendFromBroadcast = QtWidgets.QComboBox(self.sendBroadcast)
        self.comboBoxSendFromBroadcast.setMinimumSize(QtCore.QSize(300, 0))
        self.comboBoxSendFromBroadcast.setObjectName("comboBoxSendFromBroadcast")
        self.gridLayout_5.addWidget(self.comboBoxSendFromBroadcast, 0, 1, 1, 1)
        
        self.gridLayout_5_Widget = QtWidgets.QWidget()
        self.gridLayout_5_Widget.setLayout(self.gridLayout_5)
        self.verticalSplitter_6.addWidget(self.gridLayout_5_Widget)
        
        self.textEditMessageBroadcast = MessageCompose(self.sendBroadcast)
        self.textEditMessageBroadcast.setObjectName("textEditMessageBroadcast")
        self.verticalSplitter_6.addWidget(self.textEditMessageBroadcast)
        
        self.verticalSplitter_6.setStretchFactor(0, 0)
        self.verticalSplitter_6.setStretchFactor(1, 1)
        self.verticalSplitter_6.setCollapsible(0, False)
        self.verticalSplitter_6.setCollapsible(1, False)
        self.verticalSplitter_6.handle(1).setEnabled(False)
        
        self.gridLayout_9.addWidget(self.verticalSplitter_6, 0, 0, 1, 1)
        self.tabWidgetSend.addTab(self.sendBroadcast, "")
        
        self.verticalSplitter.addWidget(self.tabWidgetSend)
        
        # TTL Container
        logger.debug("DEBUG: Setting up TTL container")
        self.tTLContainer = QtWidgets.QWidget()
        self.tTLContainer.setSizePolicy(QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Fixed)
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.tTLContainer.setLayout(self.horizontalLayout_5)
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        
        self.pushButtonTTL = QtWidgets.QPushButton(self.send)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.pushButtonTTL.sizePolicy().hasHeightForWidth())
        self.pushButtonTTL.setSizePolicy(sizePolicy)
        
        palette = QtGui.QPalette()
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.ButtonText, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 0, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.ButtonText, brush)
        brush = QtGui.QBrush(QtGui.QColor(120, 120, 120))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.ButtonText, brush)
        self.pushButtonTTL.setPalette(palette)
        
        font = QtGui.QFont()
        font.setUnderline(True)
        self.pushButtonTTL.setFont(font)
        self.pushButtonTTL.setFlat(True)
        self.pushButtonTTL.setObjectName("pushButtonTTL")
        self.horizontalLayout_5.addWidget(self.pushButtonTTL, 0, QtCore.Qt.AlignRight)
        
        self.horizontalSliderTTL = QtWidgets.QSlider(self.send)
        self.horizontalSliderTTL.setMinimumSize(QtCore.QSize(70, 0))
        self.horizontalSliderTTL.setOrientation(QtCore.Qt.Horizontal)
        self.horizontalSliderTTL.setInvertedAppearance(False)
        self.horizontalSliderTTL.setInvertedControls(False)
        self.horizontalSliderTTL.setObjectName("horizontalSliderTTL")
        self.horizontalLayout_5.addWidget(self.horizontalSliderTTL, 0, QtCore.Qt.AlignLeft)
        
        self.labelHumanFriendlyTTLDescription = QtWidgets.QLabel(self.send)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.MinimumExpanding, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.labelHumanFriendlyTTLDescription.sizePolicy().hasHeightForWidth())
        self.labelHumanFriendlyTTLDescription.setSizePolicy(sizePolicy)
        self.labelHumanFriendlyTTLDescription.setMinimumSize(QtCore.QSize(45, 0))
        self.labelHumanFriendlyTTLDescription.setObjectName("labelHumanFriendlyTTLDescription")
        self.horizontalLayout_5.addWidget(self.labelHumanFriendlyTTLDescription, 1, QtCore.Qt.AlignLeft)
        
        self.pushButtonClear = QtWidgets.QPushButton(self.send)
        self.pushButtonClear.setObjectName("pushButtonClear")
        self.horizontalLayout_5.addWidget(self.pushButtonClear, 0, QtCore.Qt.AlignRight)
        
        self.pushButtonSend = QtWidgets.QPushButton(self.send)
        self.pushButtonSend.setObjectName("pushButtonSend")
        self.horizontalLayout_5.addWidget(self.pushButtonSend, 0, QtCore.Qt.AlignRight)
        
        self.horizontalSliderTTL.setMaximumSize(QtCore.QSize(105, self.pushButtonSend.height()))
        
        self.verticalSplitter.addWidget(self.tTLContainer)
        self.tTLContainer.adjustSize()
        
        self.verticalSplitter.setStretchFactor(1, 0)
        self.verticalSplitter.setStretchFactor(0, 1)
        self.verticalSplitter.setCollapsible(0, False)
        self.verticalSplitter.setCollapsible(1, False)
        self.verticalSplitter.handle(1).setEnabled(False)
        
        self.horizontalSplitter.addWidget(self.verticalSplitter)
        self.horizontalSplitter.setStretchFactor(0, 0)
        self.horizontalSplitter.setStretchFactor(1, 1)
        self.horizontalSplitter.setCollapsible(0, False)
        self.horizontalSplitter.setCollapsible(1, False)
        
        self.gridLayout_7.addWidget(self.horizontalSplitter, 0, 0, 1, 1)
        
        icon4 = QtGui.QIcon()
        icon4.addPixmap(QtGui.QPixmap(":/newPrefix/images/send.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.tabWidget.addTab(self.send, icon4, "")
        
        # Subscriptions Tab
        logger.debug("DEBUG: Setting up subscriptions tab")
        self.subscriptions = QtWidgets.QWidget()
        self.subscriptions.setObjectName("subscriptions")
        self.gridLayout_3 = QtWidgets.QGridLayout(self.subscriptions)
        self.gridLayout_3.setObjectName("gridLayout_3")
        
        self.horizontalSplitter_4 = settingsmixin.SSplitter()
        self.horizontalSplitter_4.setObjectName("horizontalSplitter_4")
        
        self.verticalSplitter_3 = settingsmixin.SSplitter()
        self.verticalSplitter_3.setObjectName("verticalSplitter_3")
        self.verticalSplitter_3.setOrientation(QtCore.Qt.Vertical)
        
        self.treeWidgetSubscriptions = settingsmixin.STreeWidget(self.subscriptions)
        self.treeWidgetSubscriptions.setAlternatingRowColors(True)
        self.treeWidgetSubscriptions.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.treeWidgetSubscriptions.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.treeWidgetSubscriptions.setObjectName("treeWidgetSubscriptions")
        self.treeWidgetSubscriptions.resize(200, self.treeWidgetSubscriptions.height())
        
        icon5 = QtGui.QIcon()
        icon5.addPixmap(QtGui.QPixmap(":/newPrefix/images/subscriptions.png"), QtGui.QIcon.Selected, QtGui.QIcon.Off)
        self.treeWidgetSubscriptions.headerItem().setIcon(0, icon5)
        self.verticalSplitter_3.addWidget(self.treeWidgetSubscriptions)
        
        self.pushButtonAddSubscription = QtWidgets.QPushButton(self.subscriptions)
        self.pushButtonAddSubscription.setObjectName("pushButtonAddSubscription")
        self.pushButtonAddSubscription.resize(200, self.pushButtonAddSubscription.height())
        self.verticalSplitter_3.addWidget(self.pushButtonAddSubscription)
        
        self.verticalSplitter_3.setStretchFactor(0, 1)
        self.verticalSplitter_3.setStretchFactor(1, 0)
        self.verticalSplitter_3.setCollapsible(0, False)
        self.verticalSplitter_3.setCollapsible(1, False)
        self.verticalSplitter_3.handle(1).setEnabled(False)
        
        self.horizontalSplitter_4.addWidget(self.verticalSplitter_3)
        
        self.verticalSplitter_4 = settingsmixin.SSplitter()
        self.verticalSplitter_4.setObjectName("verticalSplitter_4")
        self.verticalSplitter_4.setOrientation(QtCore.Qt.Vertical)
        
        self.horizontalSplitter_2 = QtWidgets.QSplitter()
        self.horizontalSplitter_2.setObjectName("horizontalSplitter_2")
        
        self.inboxSearchLineEditSubscriptions = QtWidgets.QLineEdit(self.subscriptions)
        self.inboxSearchLineEditSubscriptions.setObjectName("inboxSearchLineEditSubscriptions")
        self.horizontalSplitter_2.addWidget(self.inboxSearchLineEditSubscriptions)
        
        self.inboxSearchOptionSubscriptions = QtWidgets.QComboBox(self.subscriptions)
        self.inboxSearchOptionSubscriptions.setObjectName("inboxSearchOptionSubscriptions")
        self.inboxSearchOptionSubscriptions.addItem("")
        self.inboxSearchOptionSubscriptions.addItem("")
        self.inboxSearchOptionSubscriptions.addItem("")
        self.inboxSearchOptionSubscriptions.addItem("")
        self.inboxSearchOptionSubscriptions.setSizeAdjustPolicy(QtWidgets.QComboBox.AdjustToContents)
        self.inboxSearchOptionSubscriptions.setCurrentIndex(2)
        self.horizontalSplitter_2.addWidget(self.inboxSearchOptionSubscriptions)
        
        self.horizontalSplitter_2.handle(1).setEnabled(False)
        self.horizontalSplitter_2.setStretchFactor(0, 1)
        self.horizontalSplitter_2.setStretchFactor(1, 0)
        
        self.verticalSplitter_4.addWidget(self.horizontalSplitter_2)
        
        self.tableWidgetInboxSubscriptions = settingsmixin.STableWidget(self.subscriptions)
        self.tableWidgetInboxSubscriptions.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tableWidgetInboxSubscriptions.setAlternatingRowColors(True)
        self.tableWidgetInboxSubscriptions.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.tableWidgetInboxSubscriptions.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tableWidgetInboxSubscriptions.setWordWrap(False)
        self.tableWidgetInboxSubscriptions.setObjectName("tableWidgetInboxSubscriptions")
        self.tableWidgetInboxSubscriptions.setColumnCount(4)
        self.tableWidgetInboxSubscriptions.setRowCount(0)
        
        item = QtWidgets.QTableWidgetItem()
        self.tableWidgetInboxSubscriptions.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidgetInboxSubscriptions.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidgetInboxSubscriptions.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidgetInboxSubscriptions.setHorizontalHeaderItem(3, item)
        
        self.tableWidgetInboxSubscriptions.horizontalHeader().setCascadingSectionResizes(True)
        self.tableWidgetInboxSubscriptions.horizontalHeader().setDefaultSectionSize(200)
        self.tableWidgetInboxSubscriptions.horizontalHeader().setHighlightSections(False)
        self.tableWidgetInboxSubscriptions.horizontalHeader().setMinimumSectionSize(27)
        self.tableWidgetInboxSubscriptions.horizontalHeader().setSortIndicatorShown(False)
        self.tableWidgetInboxSubscriptions.horizontalHeader().setStretchLastSection(True)
        self.tableWidgetInboxSubscriptions.verticalHeader().setVisible(False)
        self.tableWidgetInboxSubscriptions.verticalHeader().setDefaultSectionSize(26)
        
        self.verticalSplitter_4.addWidget(self.tableWidgetInboxSubscriptions)
        
        self.textEditInboxMessageSubscriptions = MessageView(self.subscriptions)
        self.textEditInboxMessageSubscriptions.setBaseSize(QtCore.QSize(0, 500))
        self.textEditInboxMessageSubscriptions.setReadOnly(True)
        self.textEditInboxMessageSubscriptions.setObjectName("textEditInboxMessageSubscriptions")
        self.verticalSplitter_4.addWidget(self.textEditInboxMessageSubscriptions)
        
        self.verticalSplitter_4.setStretchFactor(0, 0)
        self.verticalSplitter_4.setStretchFactor(1, 1)
        self.verticalSplitter_4.setStretchFactor(2, 2)
        self.verticalSplitter_4.setCollapsible(0, False)
        self.verticalSplitter_4.setCollapsible(1, False)
        self.verticalSplitter_4.setCollapsible(2, False)
        self.verticalSplitter_4.handle(1).setEnabled(False)
        
        self.horizontalSplitter_4.addWidget(self.verticalSplitter_4)
        self.horizontalSplitter_4.setStretchFactor(0, 0)
        self.horizontalSplitter_4.setStretchFactor(1, 1)
        self.horizontalSplitter_4.setCollapsible(0, False)
        self.horizontalSplitter_4.setCollapsible(1, False)
        
        self.gridLayout_3.addWidget(self.horizontalSplitter_4, 0, 0, 1, 1)
        
        icon6 = QtGui.QIcon()
        icon6.addPixmap(QtGui.QPixmap(":/newPrefix/images/subscriptions.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.tabWidget.addTab(self.subscriptions, icon6, "")
        
        # Chans Tab
        logger.debug("DEBUG: Setting up chans tab")
        self.chans = QtWidgets.QWidget()
        self.chans.setObjectName("chans")
        self.gridLayout_4 = QtWidgets.QGridLayout(self.chans)
        self.gridLayout_4.setObjectName("gridLayout_4")
        
        self.horizontalSplitter_7 = settingsmixin.SSplitter()
        self.horizontalSplitter_7.setObjectName("horizontalSplitter_7")
        
        self.verticalSplitter_17 = settingsmixin.SSplitter()
        self.verticalSplitter_17.setObjectName("verticalSplitter_17")
        self.verticalSplitter_17.setOrientation(QtCore.Qt.Vertical)
        
        self.treeWidgetChans = settingsmixin.STreeWidget(self.chans)
        self.treeWidgetChans.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.treeWidgetChans.setLineWidth(1)
        self.treeWidgetChans.setAlternatingRowColors(True)
        self.treeWidgetChans.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.treeWidgetChans.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.treeWidgetChans.setObjectName("treeWidgetChans")
        self.treeWidgetChans.resize(200, self.treeWidgetChans.height())
        
        icon7 = QtGui.QIcon()
        icon7.addPixmap(QtGui.QPixmap(":/newPrefix/images/can-icon-16px.png"), QtGui.QIcon.Selected, QtGui.QIcon.Off)
        self.treeWidgetChans.headerItem().setIcon(0, icon7)
        self.verticalSplitter_17.addWidget(self.treeWidgetChans)
        
        self.pushButtonAddChan = QtWidgets.QPushButton(self.chans)
        self.pushButtonAddChan.setObjectName("pushButtonAddChan")
        self.pushButtonAddChan.resize(200, self.pushButtonAddChan.height())
        self.verticalSplitter_17.addWidget(self.pushButtonAddChan)
        
        self.verticalSplitter_17.setStretchFactor(0, 1)
        self.verticalSplitter_17.setStretchFactor(1, 0)
        self.verticalSplitter_17.setCollapsible(0, False)
        self.verticalSplitter_17.setCollapsible(1, False)
        self.verticalSplitter_17.handle(1).setEnabled(False)
        
        self.horizontalSplitter_7.addWidget(self.verticalSplitter_17)
        
        self.verticalSplitter_8 = settingsmixin.SSplitter()
        self.verticalSplitter_8.setObjectName("verticalSplitter_8")
        self.verticalSplitter_8.setOrientation(QtCore.Qt.Vertical)
        
        self.horizontalSplitter_6 = QtWidgets.QSplitter()
        self.horizontalSplitter_6.setObjectName("horizontalSplitter_6")
        
        self.inboxSearchLineEditChans = QtWidgets.QLineEdit(self.chans)
        self.inboxSearchLineEditChans.setObjectName("inboxSearchLineEditChans")
        self.horizontalSplitter_6.addWidget(self.inboxSearchLineEditChans)
        
        self.inboxSearchOptionChans = QtWidgets.QComboBox(self.chans)
        self.inboxSearchOptionChans.setObjectName("inboxSearchOptionChans")
        self.inboxSearchOptionChans.addItem("")
        self.inboxSearchOptionChans.addItem("")
        self.inboxSearchOptionChans.addItem("")
        self.inboxSearchOptionChans.addItem("")
        self.inboxSearchOptionChans.addItem("")
        self.inboxSearchOptionChans.setSizeAdjustPolicy(QtWidgets.QComboBox.AdjustToContents)
        self.inboxSearchOptionChans.setCurrentIndex(3)
        self.horizontalSplitter_6.addWidget(self.inboxSearchOptionChans)
        
        self.horizontalSplitter_6.handle(1).setEnabled(False)
        self.horizontalSplitter_6.setStretchFactor(0, 1)
        self.horizontalSplitter_6.setStretchFactor(1, 0)
        
        self.verticalSplitter_8.addWidget(self.horizontalSplitter_6)
        
        self.tableWidgetInboxChans = settingsmixin.STableWidget(self.chans)
        self.tableWidgetInboxChans.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.tableWidgetInboxChans.setAlternatingRowColors(True)
        self.tableWidgetInboxChans.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.tableWidgetInboxChans.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.tableWidgetInboxChans.setWordWrap(False)
        self.tableWidgetInboxChans.setObjectName("tableWidgetInboxChans")
        self.tableWidgetInboxChans.setColumnCount(4)
        self.tableWidgetInboxChans.setRowCount(0)
        
        item = QtWidgets.QTableWidgetItem()
        self.tableWidgetInboxChans.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidgetInboxChans.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidgetInboxChans.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidgetInboxChans.setHorizontalHeaderItem(3, item)
        
        self.tableWidgetInboxChans.horizontalHeader().setCascadingSectionResizes(True)
        self.tableWidgetInboxChans.horizontalHeader().setDefaultSectionSize(200)
        self.tableWidgetInboxChans.horizontalHeader().setHighlightSections(False)
        self.tableWidgetInboxChans.horizontalHeader().setMinimumSectionSize(27)
        self.tableWidgetInboxChans.horizontalHeader().setSortIndicatorShown(False)
        self.tableWidgetInboxChans.horizontalHeader().setStretchLastSection(True)
        self.tableWidgetInboxChans.verticalHeader().setVisible(False)
        self.tableWidgetInboxChans.verticalHeader().setDefaultSectionSize(26)
        
        self.verticalSplitter_8.addWidget(self.tableWidgetInboxChans)
        
        self.textEditInboxMessageChans = MessageView(self.chans)
        self.textEditInboxMessageChans.setBaseSize(QtCore.QSize(0, 500))
        self.textEditInboxMessageChans.setReadOnly(True)
        self.textEditInboxMessageChans.setObjectName("textEditInboxMessageChans")
        self.verticalSplitter_8.addWidget(self.textEditInboxMessageChans)
        
        self.verticalSplitter_8.setStretchFactor(0, 0)
        self.verticalSplitter_8.setStretchFactor(1, 1)
        self.verticalSplitter_8.setStretchFactor(2, 2)
        self.verticalSplitter_8.setCollapsible(0, False)
        self.verticalSplitter_8.setCollapsible(1, False)
        self.verticalSplitter_8.setCollapsible(2, False)
        self.verticalSplitter_8.handle(1).setEnabled(False)
        
        self.horizontalSplitter_7.addWidget(self.verticalSplitter_8)
        self.horizontalSplitter_7.setStretchFactor(0, 0)
        self.horizontalSplitter_7.setStretchFactor(1, 1)
        self.horizontalSplitter_7.setCollapsible(0, False)
        self.horizontalSplitter_7.setCollapsible(1, False)
        
        self.gridLayout_4.addWidget(self.horizontalSplitter_7, 0, 0, 1, 1)
        
        icon8 = QtGui.QIcon()
        icon8.addPixmap(QtGui.QPixmap(":/newPrefix/images/can-icon-16px.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        self.tabWidget.addTab(self.chans, icon8, "")
        
        # Blacklist/Whitelist Tab
        logger.debug("DEBUG: Setting up blacklist/whitelist tab")
        self.blackwhitelist = Blacklist()
        self.tabWidget.addTab(self.blackwhitelist, QtGui.QIcon(":/newPrefix/images/blacklist.png"), "")
        
        # Initialize the Blacklist or Whitelist
        logger.debug("DEBUG: Initializing blacklist/whitelist settings")
        if config.get('bitmessagesettings', 'blackwhitelist') == 'white':
            logger.debug("DEBUG: Whitelist mode detected")
            self.blackwhitelist.radioButtonWhitelist.click()
        self.blackwhitelist.rerenderBlackWhiteList()
        
        # Network Status Tab
        logger.debug("DEBUG: Setting up network status tab")
        self.networkstatus = NetworkStatus()
        self.tabWidget.addTab(self.networkstatus, QtGui.QIcon(":/newPrefix/images/networkstatus.png"), "")
        
        self.gridLayout_10.addWidget(self.tabWidget, 0, 0, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        
        # Menu Bar
        logger.debug("DEBUG: Setting up menu bar")
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 885, 27))
        self.menubar.setObjectName("menubar")
        
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        
        self.menuSettings = QtWidgets.QMenu(self.menubar)
        self.menuSettings.setObjectName("menuSettings")
        
        self.menuHelp = QtWidgets.QMenu(self.menubar)
        self.menuHelp.setObjectName("menuHelp")
        
        MainWindow.setMenuBar(self.menubar)
        
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setMaximumSize(QtCore.QSize(16777215, 22))
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        
        # Actions
        logger.debug("DEBUG: Setting up actions")
        self.actionImport_keys = QtWidgets.QAction(MainWindow)
        self.actionImport_keys.setObjectName("actionImport_keys")
        
        self.actionManageKeys = QtWidgets.QAction(MainWindow)
        self.actionManageKeys.setCheckable(False)
        self.actionManageKeys.setEnabled(True)
        icon = QtGui.QIcon.fromTheme("dialog-password")
        self.actionManageKeys.setIcon(icon)
        self.actionManageKeys.setObjectName("actionManageKeys")
        
        self.actionNetworkSwitch = QtWidgets.QAction(MainWindow)
        self.actionNetworkSwitch.setObjectName("actionNetworkSwitch")
        
        self.actionExit = QtWidgets.QAction(MainWindow)
        icon = QtGui.QIcon.fromTheme("application-exit")
        self.actionExit.setIcon(icon)
        self.actionExit.setObjectName("actionExit")
        
        self.actionHelp = QtWidgets.QAction(MainWindow)
        icon = QtGui.QIcon.fromTheme("help-contents")
        self.actionHelp.setIcon(icon)
        self.actionHelp.setObjectName("actionHelp")
        
        self.actionSupport = QtWidgets.QAction(MainWindow)
        icon = QtGui.QIcon.fromTheme("help-support")
        self.actionSupport.setIcon(icon)
        self.actionSupport.setObjectName("actionSupport")
        
        self.actionAbout = QtWidgets.QAction(MainWindow)
        icon = QtGui.QIcon.fromTheme("help-about")
        self.actionAbout.setIcon(icon)
        self.actionAbout.setObjectName("actionAbout")
        
        self.actionSettings = QtWidgets.QAction(MainWindow)
        icon = QtGui.QIcon.fromTheme("document-properties")
        self.actionSettings.setIcon(icon)
        self.actionSettings.setObjectName("actionSettings")
        
        self.actionRegenerateDeterministicAddresses = QtWidgets.QAction(MainWindow)
        icon = QtGui.QIcon.fromTheme("view-refresh")
        self.actionRegenerateDeterministicAddresses.setIcon(icon)
        self.actionRegenerateDeterministicAddresses.setObjectName("actionRegenerateDeterministicAddresses")
        
        self.actionDeleteAllTrashedMessages = QtWidgets.QAction(MainWindow)
        icon = QtGui.QIcon.fromTheme("user-trash")
        self.actionDeleteAllTrashedMessages.setIcon(icon)
        self.actionDeleteAllTrashedMessages.setObjectName("actionDeleteAllTrashedMessages")
        
        self.actionJoinChan = QtWidgets.QAction(MainWindow)
        icon = QtGui.QIcon.fromTheme("contact-new")
        self.actionJoinChan.setIcon(icon)
        self.actionJoinChan.setObjectName("actionJoinChan")
        
        # Menu Structure
        logger.debug("DEBUG: Building menu structure")
        self.menuFile.addAction(self.actionManageKeys)
        self.menuFile.addAction(self.actionDeleteAllTrashedMessages)
        self.menuFile.addAction(self.actionRegenerateDeterministicAddresses)
        self.menuFile.addAction(self.actionNetworkSwitch)
        self.menuFile.addAction(self.actionExit)
        
        self.menuSettings.addAction(self.actionSettings)
        
        self.menuHelp.addAction(self.actionHelp)
        self.menuHelp.addAction(self.actionSupport)
        self.menuHelp.addAction(self.actionAbout)
        
        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuSettings.menuAction())
        self.menubar.addAction(self.menuHelp.menuAction())

        # Final Setup
        logger.debug("DEBUG: Finalizing UI setup")
        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(
            self.tabWidget.indexOf(self.inbox)
        )
        self.tabWidgetSend.setCurrentIndex(
            self.tabWidgetSend.indexOf(self.sendDirect)
        )
        
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        
        MainWindow.setTabOrder(self.tableWidgetInbox, self.textEditInboxMessage)
        MainWindow.setTabOrder(self.textEditInboxMessage, self.comboBoxSendFrom)
        MainWindow.setTabOrder(self.comboBoxSendFrom, self.lineEditTo)
        MainWindow.setTabOrder(self.lineEditTo, self.lineEditSubject)
        MainWindow.setTabOrder(self.lineEditSubject, self.textEditMessage)
        MainWindow.setTabOrder(self.textEditMessage, self.pushButtonAddSubscription)

        # Popup menu actions container for the Sent page
        logger.debug("DEBUG: Setting up context menus")
        self.sentContextMenuToolbar = QtWidgets.QToolBar()
        # Popup menu actions container for chans tree
        self.addressContextMenuToolbar = QtWidgets.QToolBar()
        # Popup menu actions container for subscriptions tree
        self.subscriptionsContextMenuToolbar = QtWidgets.QToolBar()
        
        logger.debug("DEBUG: UI setup complete")

    def updateNetworkSwitchMenuLabel(self, dontconnect=None):
        logger.debug("DEBUG: Updating network switch menu label")
        if dontconnect is None:
            logger.debug("DEBUG: Fetching dontconnect from config")
            dontconnect = config.safeGetBoolean(
                'bitmessagesettings', 'dontconnect')
        
        new_text = (
            _translate("MainWindow", "Go online", None)
            if dontconnect else
            _translate("MainWindow", "Go offline", None)
        )
        logger.debug(f"DEBUG: Setting network switch label to: {new_text}")
        self.actionNetworkSwitch.setText(new_text)

    def retranslateUi(self, MainWindow):
        logger.debug("DEBUG: Retranslating UI")
        MainWindow.setWindowTitle(_translate("MainWindow", "Bitmessage", None))
        
        # Inbox Tab
        logger.debug("DEBUG: Translating inbox tab")
        self.treeWidgetYourIdentities.headerItem().setText(0, _translate("MainWindow", "Identities", None))
        self.pushButtonNewAddress.setText(_translate("MainWindow", "New Identity", None))
        self.inboxSearchLineEdit.setPlaceholderText(_translate("MainWindow", "Search", None))
        
        self.inboxSearchOption.setItemText(0, _translate("MainWindow", "All", None))
        self.inboxSearchOption.setItemText(1, _translate("MainWindow", "To", None))
        self.inboxSearchOption.setItemText(2, _translate("MainWindow", "From", None))
        self.inboxSearchOption.setItemText(3, _translate("MainWindow", "Subject", None))
        self.inboxSearchOption.setItemText(4, _translate("MainWindow", "Message", None))
        
        self.tableWidgetInbox.setSortingEnabled(True)
        item = self.tableWidgetInbox.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "To", None))
        item = self.tableWidgetInbox.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "From", None))
        item = self.tableWidgetInbox.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Subject", None))
        item = self.tableWidgetInbox.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Received", None))
        
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.inbox), _translate("MainWindow", "Messages", None))
        
        # Send Tab
        logger.debug("DEBUG: Translating send tab")
        self.tableWidgetAddressBook.setSortingEnabled(True)
        item = self.tableWidgetAddressBook.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Address book", None))
        item = self.tableWidgetAddressBook.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Address", None))
        
        self.pushButtonAddAddressBook.setText(_translate("MainWindow", "Add Contact", None))
        self.pushButtonFetchNamecoinID.setText(_translate("MainWindow", "Fetch Namecoin ID", None))
        
        self.label_3.setText(_translate("MainWindow", "Subject:", None))
        self.label_2.setText(_translate("MainWindow", "From:", None))
        self.label.setText(_translate("MainWindow", "To:", None))
        
        self.tabWidgetSend.setTabText(
            self.tabWidgetSend.indexOf(self.sendDirect), _translate("MainWindow", "Send ordinary Message", None)
        )
        
        self.label_8.setText(_translate("MainWindow", "From:", None))
        self.label_7.setText(_translate("MainWindow", "Subject:", None))
        
        self.tabWidgetSend.setTabText(
            self.tabWidgetSend.indexOf(self.sendBroadcast),
            _translate("MainWindow", "Send Message to your Subscribers", None)
        )
        
        self.pushButtonTTL.setText(_translate("MainWindow", "TTL:", None))
        hours = 48
        try:
            hours = int(config.getint('bitmessagesettings', 'ttl') / 60 / 60)
            logger.debug(f"DEBUG: TTL hours calculated as: {hours}")
        except:
            logger.debug("DEBUG: Using default TTL hours (48)")
            pass
        
        self.labelHumanFriendlyTTLDescription.setText(_translate("MainWindow", "%n hour(s)", None, hours))
        self.pushButtonClear.setText(_translate("MainWindow", "Clear", None))
        self.pushButtonSend.setText(_translate("MainWindow", "Send", None))
        
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.send), _translate("MainWindow", "Send", None))
        
        # Subscriptions Tab
        logger.debug("DEBUG: Translating subscriptions tab")
        self.treeWidgetSubscriptions.headerItem().setText(0, _translate("MainWindow", "Subscriptions", None))
        self.pushButtonAddSubscription.setText(_translate("MainWindow", "Add new Subscription", None))
        
        self.inboxSearchLineEditSubscriptions.setPlaceholderText(_translate("MainWindow", "Search", None))
        
        self.inboxSearchOptionSubscriptions.setItemText(0, _translate("MainWindow", "All", None))
        self.inboxSearchOptionSubscriptions.setItemText(1, _translate("MainWindow", "From", None))
        self.inboxSearchOptionSubscriptions.setItemText(2, _translate("MainWindow", "Subject", None))
        self.inboxSearchOptionSubscriptions.setItemText(3, _translate("MainWindow", "Message", None))
        
        self.tableWidgetInboxSubscriptions.setSortingEnabled(True)
        item = self.tableWidgetInboxSubscriptions.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "To", None))
        item = self.tableWidgetInboxSubscriptions.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "From", None))
        item = self.tableWidgetInboxSubscriptions.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Subject", None))
        item = self.tableWidgetInboxSubscriptions.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Received", None))
        
        self.tabWidget.setTabText(
            self.tabWidget.indexOf(self.subscriptions),
            _translate("MainWindow", "Subscriptions", None)
        )
        
        # Chans Tab
        logger.debug("DEBUG: Translating chans tab")
        self.treeWidgetChans.headerItem().setText(0, _translate("MainWindow", "Chans", None))
        self.pushButtonAddChan.setText(_translate("MainWindow", "Add Chan", None))
        
        self.inboxSearchLineEditChans.setPlaceholderText(_translate("MainWindow", "Search", None))
        
        self.inboxSearchOptionChans.setItemText(0, _translate("MainWindow", "All", None))
        self.inboxSearchOptionChans.setItemText(1, _translate("MainWindow", "To", None))
        self.inboxSearchOptionChans.setItemText(2, _translate("MainWindow", "From", None))
        self.inboxSearchOptionChans.setItemText(3, _translate("MainWindow", "Subject", None))
        self.inboxSearchOptionChans.setItemText(4, _translate("MainWindow", "Message", None))
        
        self.tableWidgetInboxChans.setSortingEnabled(True)
        item = self.tableWidgetInboxChans.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "To", None))
        item = self.tableWidgetInboxChans.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "From", None))
        item = self.tableWidgetInboxChans.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Subject", None))
        item = self.tableWidgetInboxChans.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Received", None))
        
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.chans), _translate("MainWindow", "Chans", None))
        
        # Blacklist/Whitelist Tab
        logger.debug("DEBUG: Translating blacklist/whitelist tab")
        self.blackwhitelist.retranslateUi()
        self.tabWidget.setTabText(
            self.tabWidget.indexOf(self.blackwhitelist),
            _translate("blacklist", "Blacklist", None)
        )
        
        # Network Status Tab
        logger.debug("DEBUG: Translating network status tab")
        self.networkstatus.retranslateUi()
        self.tabWidget.setTabText(
            self.tabWidget.indexOf(self.networkstatus),
            _translate("networkstatus", "Network Status", None)
        )
        
        # Menu Items
        logger.debug("DEBUG: Translating menu items")
        self.menuFile.setTitle(_translate("MainWindow", "File", None))
        self.menuSettings.setTitle(_translate("MainWindow", "Settings", None))
        self.menuHelp.setTitle(_translate("MainWindow", "Help", None))
        
        self.actionImport_keys.setText(_translate("MainWindow", "Import keys", None))
        self.actionManageKeys.setText(_translate("MainWindow", "Manage keys", None))
        self.actionExit.setText(_translate("MainWindow", "Quit", None))
        self.actionExit.setShortcut(_translate("MainWindow", "Ctrl+Q", None))
        self.actionHelp.setText(_translate("MainWindow", "Help", None))
        self.actionHelp.setShortcut(_translate("MainWindow", "F1", None))
        self.actionSupport.setText(_translate("MainWindow", "Contact support", None))
        self.actionAbout.setText(_translate("MainWindow", "About", None))
        self.actionSettings.setText(_translate("MainWindow", "Settings", None))
        self.actionRegenerateDeterministicAddresses.setText(
            _translate("MainWindow", "Regenerate deterministic addresses", None)
        )
        self.actionDeleteAllTrashedMessages.setText(_translate("MainWindow", "Delete all trashed messages", None))
        self.actionJoinChan.setText(_translate("MainWindow", "Join / Create chan", None))
        
        self.updateNetworkSwitchMenuLabel()
        logger.debug("DEBUG: Retranslation complete")


if __name__ == "__main__":
    import sys

    logger.debug("DEBUG: Starting application")
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = settingsmixin.SMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    logger.debug("DEBUG: Application started successfully")
    sys.exit(app.exec_())
