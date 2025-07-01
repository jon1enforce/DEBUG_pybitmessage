"""
SettingsDialog class definition
"""
from six.moves import configparser
import os
import sys
import tempfile

from qtpy import QtCore, QtGui, QtWidgets
import six
from unqstr import ustr

import debug
import defaults
import namecoin
import openclpow
import paths
import queues
import state
from bitmessageqt import widgets
from bmconfigparser import config as config_obj
from helper_sql import sqlExecute, sqlStoredProcedure
from helper_startup import start_proxyconfig
from network import connectionpool, knownnodes
from network.announcethread import AnnounceThread
from network.asyncore_pollchoose import set_rates
from tr import _translate


try:
    SafeConfigParser = configparser.SafeConfigParser
except AttributeError:
    # alpine linux, python3.12
    SafeConfigParser = configparser.ConfigParser

def getSOCKSProxyType(config):
    """Get user socksproxytype setting from *config*"""
    try:
        result = SafeConfigParser.get(
            config, 'bitmessagesettings', 'socksproxytype')
        debug.dprint(f"DEBUG: Got SOCKS proxy type from config: {result}")
    except (configparser.NoSectionError, configparser.NoOptionError) as e:
        debug.dprint(f"DEBUG: No SOCKS proxy type found in config: {e}")
        return None
    else:
        if result.lower() in ('', 'none', 'false'):
            debug.dprint("DEBUG: SOCKS proxy type is empty/None/False")
            result = None
    return result


class SettingsDialog(QtWidgets.QDialog):
    """The "Settings" dialog"""
    # pylint: disable=too-many-instance-attributes
    def __init__(self, parent=None, firstrun=False):
        debug.dprint("DEBUG: Initializing SettingsDialog")
        super(SettingsDialog, self).__init__(parent)
        widgets.load('settings.ui', self)

        self.app = QtWidgets.QApplication.instance()
        self.parent = parent
        self.firstrun = firstrun
        self.config = config_obj
        self.net_restart_needed = False
        self.font_setting = None
        self.timer = QtCore.QTimer()

        if self.config.safeGetBoolean('bitmessagesettings', 'dontconnect'):
            debug.dprint("DEBUG: dontconnect is True, setting firstrun to False")
            self.firstrun = False
            
        try:
            import pkg_resources
        except ImportError as e:
            debug.dprint(f"DEBUG: Could not import pkg_resources: {e}")
        else:
            debug.dprint("DEBUG: Appending proxy types from plugins")
            for ep in pkg_resources.iter_entry_points(
                    'bitmessage.proxyconfig'):
                try:
                    ep.load()
                except Exception as e:
                    debug.dprint(f"DEBUG: Failed to load plugin {ep.name}: {e}")
                else:
                    debug.dprint(f"DEBUG: Adding proxy type: {ep.name}")
                    self.comboBoxProxyType.addItem(ep.name)

        self.lineEditMaxOutboundConnections.setValidator(
            QtGui.QIntValidator(0, 8, self.lineEditMaxOutboundConnections))

        debug.dprint("DEBUG: Adjusting from config")
        self.adjust_from_config(self.config)
        if firstrun:
            debug.dprint("DEBUG: First run, switching to Network Settings tab")
            self.tabWidgetSettings.setCurrentIndex(
                self.tabWidgetSettings.indexOf(self.tabNetworkSettings)
            )
        QtWidgets.QWidget.resize(self, QtWidgets.QWidget.sizeHint(self))

    def adjust_from_config(self, config):
        """Adjust all widgets state according to config settings"""
        # pylint: disable=too-many-branches,too-many-statements
        debug.dprint("DEBUG: adjust_from_config started")

        current_style = self.app.get_windowstyle()
        debug.dprint(f"DEBUG: Current window style: {current_style}")
        for i, sk in enumerate(QtWidgets.QStyleFactory.keys()):
            self.comboBoxStyle.addItem(sk)
            if sk == current_style:
                self.comboBoxStyle.setCurrentIndex(i)
                debug.dprint(f"DEBUG: Set current style to index {i}")

        self.save_font_setting(self.app.font())

        if not self.parent.tray.isSystemTrayAvailable():
            debug.dprint("DEBUG: System tray not available")
            self.groupBoxTray.setEnabled(False)
            self.groupBoxTray.setTitle(_translate(
                "MainWindow", "Tray (not available in your system)"))
            for setting in (
                    'minimizetotray', 'trayonclose', 'startintray'):
                config.set('bitmessagesettings', setting, 'false')
        else:
            debug.dprint("DEBUG: System tray available, setting tray options")
            self.checkBoxMinimizeToTray.setChecked(
                config.getboolean('bitmessagesettings', 'minimizetotray'))
            self.checkBoxTrayOnClose.setChecked(
                config.safeGetBoolean('bitmessagesettings', 'trayonclose'))
            self.checkBoxStartInTray.setChecked(
                config.getboolean('bitmessagesettings', 'startintray'))

        self.checkBoxHideTrayConnectionNotifications.setChecked(
            config.getboolean(
                'bitmessagesettings', 'hidetrayconnectionnotifications'))
        self.checkBoxShowTrayNotifications.setChecked(
            config.getboolean('bitmessagesettings', 'showtraynotifications'))

        self.checkBoxStartOnLogon.setChecked(
            config.getboolean('bitmessagesettings', 'startonlogon'))

        self.checkBoxWillinglySendToMobile.setChecked(
            config.safeGetBoolean(
                'bitmessagesettings', 'willinglysendtomobile'))
        self.checkBoxUseIdenticons.setChecked(
            config.safeGetBoolean('bitmessagesettings', 'useidenticons'))
        self.checkBoxReplyBelow.setChecked(
            config.safeGetBoolean('bitmessagesettings', 'replybelow'))

        if state.appdata == paths.lookupExeFolder():
            debug.dprint("DEBUG: Running in portable mode")
            self.checkBoxPortableMode.setChecked(True)
        else:
            debug.dprint("DEBUG: Not in portable mode, checking if possible")
            try:
                tempfile.NamedTemporaryFile(
                    dir=paths.lookupExeFolder(), delete=True
                ).close()  # should autodelete
            except Exception as e:
                debug.dprint(f"DEBUG: Portable mode not possible: {e}")
                self.checkBoxPortableMode.setDisabled(True)

        if 'darwin' in sys.platform:
            debug.dprint("DEBUG: On macOS, disabling some tray features")
            self.checkBoxMinimizeToTray.setDisabled(True)
            self.checkBoxMinimizeToTray.setText(_translate(
                "MainWindow",
                "Minimize-to-tray not yet supported on your OS."))
            self.checkBoxShowTrayNotifications.setDisabled(True)
            self.checkBoxShowTrayNotifications.setText(_translate(
                "MainWindow",
                "Tray notifications not yet supported on your OS."))

        if not sys.platform.startswith('win') and not self.parent.desktop:
            debug.dprint("DEBUG: Not on Windows, disabling start-on-logon")
            self.checkBoxStartOnLogon.setDisabled(True)
            self.checkBoxStartOnLogon.setText(_translate(
                "MainWindow", "Start-on-login not yet supported on your OS."))

        # On the Network settings tab:
        debug.dprint("DEBUG: Setting network options")
        self.lineEditTCPPort.setText(str(
            config.get('bitmessagesettings', 'port')))
        self.checkBoxUPnP.setChecked(
            config.safeGetBoolean('bitmessagesettings', 'upnp'))
        self.checkBoxUDP.setChecked(
            config.safeGetBoolean('bitmessagesettings', 'udp'))
        self.checkBoxAuthentication.setChecked(
            config.getboolean('bitmessagesettings', 'socksauthentication'))
        self.checkBoxSocksListen.setChecked(
            config.getboolean('bitmessagesettings', 'sockslisten'))
        self.checkBoxOnionOnly.setChecked(
            config.safeGetBoolean('bitmessagesettings', 'onionservicesonly'))

        self._proxy_type = getSOCKSProxyType(config)
        debug.dprint(f"DEBUG: Current proxy type: {self._proxy_type}")
        self.comboBoxProxyType.setCurrentIndex(
            0 if not self._proxy_type
            else self.comboBoxProxyType.findText(self._proxy_type))
        self.comboBoxProxyTypeChanged(self.comboBoxProxyType.currentIndex())

        if self._proxy_type:
            debug.dprint("DEBUG: Checking onion nodes")
            for node, info in six.iteritems(
                knownnodes.knownNodes.get(
                    min(connectionpool.pool.streams), [])
            ):
                if (
                    node.host.endswith('.onion') and len(node.host) > 22
                    and not info.get('self')
                ):
                    break
            else:
                if self.checkBoxOnionOnly.isChecked():
                    debug.dprint("DEBUG: No onion nodes found but onion-only enabled")
                    self.checkBoxOnionOnly.setText(
                        ustr(self.checkBoxOnionOnly.text()) + ", " + _translate(
                            "MainWindow", "may cause connection problems!"))
                    self.checkBoxOnionOnly.setStyleSheet(
                        "QCheckBox { color : red; }")
                else:
                    debug.dprint("DEBUG: No onion nodes found, disabling onion-only")
                    self.checkBoxOnionOnly.setEnabled(False)

        self.lineEditSocksHostname.setText(
            config.get('bitmessagesettings', 'sockshostname'))
        self.lineEditSocksPort.setText(str(
            config.get('bitmessagesettings', 'socksport')))
        self.lineEditSocksUsername.setText(
            config.get('bitmessagesettings', 'socksusername'))
        self.lineEditSocksPassword.setText(
            config.get('bitmessagesettings', 'sockspassword'))

        self.lineEditMaxDownloadRate.setText(str(
            config.get('bitmessagesettings', 'maxdownloadrate')))
        self.lineEditMaxUploadRate.setText(str(
            config.get('bitmessagesettings', 'maxuploadrate')))
        self.lineEditMaxOutboundConnections.setText(str(
            config.get('bitmessagesettings', 'maxoutboundconnections')))

        # Demanded difficulty tab
        debug.dprint("DEBUG: Setting difficulty options")
        self.lineEditTotalDifficulty.setText(str((float(
            config.getint(
                'bitmessagesettings', 'defaultnoncetrialsperbyte')
        ) / defaults.networkDefaultProofOfWorkNonceTrialsPerByte)))
        self.lineEditSmallMessageDifficulty.setText(str((float(
            config.getint(
                'bitmessagesettings', 'defaultpayloadlengthextrabytes')
        ) / defaults.networkDefaultPayloadLengthExtraBytes)))

        # Max acceptable difficulty tab
        self.lineEditMaxAcceptableTotalDifficulty.setText(str((float(
            config.getint(
                'bitmessagesettings', 'maxacceptablenoncetrialsperbyte')
        ) / defaults.networkDefaultProofOfWorkNonceTrialsPerByte)))
        self.lineEditMaxAcceptableSmallMessageDifficulty.setText(str((float(
            config.getint(
                'bitmessagesettings', 'maxacceptablepayloadlengthextrabytes')
        ) / defaults.networkDefaultPayloadLengthExtraBytes)))

        # OpenCL
        debug.dprint("DEBUG: Setting OpenCL options")
        opencl_available = openclpow.openclAvailable()
        debug.dprint(f"DEBUG: OpenCL available: {opencl_available}")
        self.comboBoxOpenCL.setEnabled(opencl_available)
        self.comboBoxOpenCL.clear()
        self.comboBoxOpenCL.addItem("None")
        self.comboBoxOpenCL.addItems(openclpow.vendors)
        self.comboBoxOpenCL.setCurrentIndex(0)
        for i in range(self.comboBoxOpenCL.count()):
            if self.comboBoxOpenCL.itemText(i) == config.safeGet(
                    'bitmessagesettings', 'opencl'):
                debug.dprint(f"DEBUG: Found OpenCL config match at index {i}")
                self.comboBoxOpenCL.setCurrentIndex(i)
                break

        # Namecoin integration tab
        debug.dprint("DEBUG: Setting Namecoin options")
        nmctype = config.get('bitmessagesettings', 'namecoinrpctype')
        debug.dprint(f"DEBUG: Namecoin type: {nmctype}")
        self.lineEditNamecoinHost.setText(
            config.get('bitmessagesettings', 'namecoinrpchost'))
        self.lineEditNamecoinPort.setText(str(
            config.get('bitmessagesettings', 'namecoinrpcport')))
        self.lineEditNamecoinUser.setText(
            config.get('bitmessagesettings', 'namecoinrpcuser'))
        self.lineEditNamecoinPassword.setText(
            config.get('bitmessagesettings', 'namecoinrpcpassword'))

        if nmctype == "namecoind":
            debug.dprint("DEBUG: Namecoin type is namecoind")
            self.radioButtonNamecoinNamecoind.setChecked(True)
        elif nmctype == "nmcontrol":
            debug.dprint("DEBUG: Namecoin type is nmcontrol")
            self.radioButtonNamecoinNmcontrol.setChecked(True)
            self.lineEditNamecoinUser.setEnabled(False)
            self.labelNamecoinUser.setEnabled(False)
            self.lineEditNamecoinPassword.setEnabled(False)
            self.labelNamecoinPassword.setEnabled(False)
        else:
            debug.dprint(f"DEBUG: Unknown Namecoin type: {nmctype}")
            assert False

        # Message Resend tab
        debug.dprint("DEBUG: Setting message resend options")
        self.lineEditDays.setText(str(
            config.get('bitmessagesettings', 'stopresendingafterxdays')))
        self.lineEditMonths.setText(str(
            config.get('bitmessagesettings', 'stopresendingafterxmonths')))

    def comboBoxProxyTypeChanged(self, comboBoxIndex):
        """A callback for currentIndexChanged event of comboBoxProxyType"""
        debug.dprint(f"DEBUG: Proxy type changed to index {comboBoxIndex}")
        if comboBoxIndex == 0:
            debug.dprint("DEBUG: No proxy selected, disabling proxy fields")
            self.lineEditSocksHostname.setEnabled(False)
            self.lineEditSocksPort.setEnabled(False)
            self.lineEditSocksUsername.setEnabled(False)
            self.lineEditSocksPassword.setEnabled(False)
            self.checkBoxAuthentication.setEnabled(False)
            self.checkBoxSocksListen.setEnabled(False)
            self.checkBoxOnionOnly.setEnabled(False)
        else:
            debug.dprint("DEBUG: Proxy selected, enabling proxy fields")
            self.lineEditSocksHostname.setEnabled(True)
            self.lineEditSocksPort.setEnabled(True)
            self.checkBoxAuthentication.setEnabled(True)
            self.checkBoxSocksListen.setEnabled(True)
            self.checkBoxOnionOnly.setEnabled(True)
            if self.checkBoxAuthentication.isChecked():
                debug.dprint("DEBUG: Authentication enabled, enabling auth fields")
                self.lineEditSocksUsername.setEnabled(True)
                self.lineEditSocksPassword.setEnabled(True)

    def getNamecoinType(self):
        """
        Check status of namecoin integration radio buttons
        and translate it to a string as in the options.
        """
        if self.radioButtonNamecoinNamecoind.isChecked():
            debug.dprint("DEBUG: Namecoin type is namecoind")
            return "namecoind"
        if self.radioButtonNamecoinNmcontrol.isChecked():
            debug.dprint("DEBUG: Namecoin type is nmcontrol")
            return "nmcontrol"
        debug.dprint("DEBUG: Unknown Namecoin type")
        assert False

    # Namecoin connection type was changed.
    def namecoinTypeChanged(self, checked):  # pylint: disable=unused-argument
        """A callback for toggled event of radioButtonNamecoinNamecoind"""
        debug.dprint("DEBUG: Namecoin type changed")
        nmctype = self.getNamecoinType()
        assert nmctype == "namecoind" or nmctype == "nmcontrol"

        isNamecoind = (nmctype == "namecoind")
        debug.dprint(f"DEBUG: isNamecoind: {isNamecoind}")
        self.lineEditNamecoinUser.setEnabled(isNamecoind)
        self.labelNamecoinUser.setEnabled(isNamecoind)
        self.lineEditNamecoinPassword.setEnabled(isNamecoind)
        self.labelNamecoinPassword.setEnabled(isNamecoind)

        if isNamecoind:
            debug.dprint("DEBUG: Setting default namecoind port")
            self.lineEditNamecoinPort.setText(defaults.namecoinDefaultRpcPort)
        else:
            debug.dprint("DEBUG: Setting default nmcontrol port")
            self.lineEditNamecoinPort.setText("9000")

    def click_pushButtonNamecoinTest(self):
        """Test the namecoin settings specified in the settings dialog."""
        debug.dprint("DEBUG: Testing Namecoin connection")
        self.labelNamecoinTestResult.setText(
            _translate("MainWindow", "Testing..."))
        nc = namecoin.namecoinConnection({
            'type': self.getNamecoinType(),
            'host': ustr(self.lineEditNamecoinHost.text()),
            'port': ustr(self.lineEditNamecoinPort.text()),
            'user': ustr(self.lineEditNamecoinUser.text()),
            'password': ustr(self.lineEditNamecoinPassword.text())
        })
        status, text = nc.test()
        debug.dprint(f"DEBUG: Namecoin test result: {status}, {text}")
        self.labelNamecoinTestResult.setText(text)
        if status == 'success':
            debug.dprint("DEBUG: Namecoin test successful")
            self.parent.namecoin = nc

    def save_font_setting(self, font):
        """Save user font setting and set the buttonFont text"""
        debug.dprint("DEBUG: Saving font setting")
        font_setting = (font.family(), font.pointSize())
        self.buttonFont.setText('{} {}'.format(*font_setting))
        self.font_setting = '{},{}'.format(*font_setting)

    def choose_font(self):
        """Show the font selection dialog"""
        debug.dprint("DEBUG: Showing font dialog")
        font, valid = QtWidgets.QFontDialog.getFont()
        if valid:
            debug.dprint("DEBUG: Font selected")
            self.save_font_setting(font)

    def accept(self):
        """A callback for accepted event of buttonBox (OK button pressed)"""
        # pylint: disable=too-many-branches,too-many-statements
        debug.dprint("DEBUG: Settings dialog accepted, saving settings")
        super(SettingsDialog, self).accept()
        if self.firstrun:
            debug.dprint("DEBUG: First run, removing dontconnect option")
            self.config.remove_option('bitmessagesettings', 'dontconnect')
            
        debug.dprint("DEBUG: Saving basic settings")
        self.config.set('bitmessagesettings', 'startonlogon', str(
            self.checkBoxStartOnLogon.isChecked()))
        self.config.set('bitmessagesettings', 'minimizetotray', str(
            self.checkBoxMinimizeToTray.isChecked()))
        self.config.set('bitmessagesettings', 'trayonclose', str(
            self.checkBoxTrayOnClose.isChecked()))
        self.config.set(
            'bitmessagesettings', 'hidetrayconnectionnotifications',
            str(self.checkBoxHideTrayConnectionNotifications.isChecked()))
        self.config.set('bitmessagesettings', 'showtraynotifications', str(
            self.checkBoxShowTrayNotifications.isChecked()))
        self.config.set('bitmessagesettings', 'startintray', str(
            self.checkBoxStartInTray.isChecked()))
        self.config.set('bitmessagesettings', 'willinglysendtomobile', str(
            self.checkBoxWillinglySendToMobile.isChecked()))
        self.config.set('bitmessagesettings', 'useidenticons', str(
            self.checkBoxUseIdenticons.isChecked()))
        self.config.set('bitmessagesettings', 'replybelow', str(
            self.checkBoxReplyBelow.isChecked()))

        window_style = ustr(self.comboBoxStyle.currentText())
        if self.app.get_windowstyle() != window_style or self.config.safeGet(
            'bitmessagesettings', 'font'
        ) != self.font_setting:
            debug.dprint("DEBUG: Window style or font changed")
            self.config.set('bitmessagesettings', 'windowstyle', window_style)
            self.config.set('bitmessagesettings', 'font', self.font_setting)
            queues.UISignalQueue.put((
                'updateStatusBar', (
                    _translate(
                        "MainWindow",
                        "You need to restart the application to apply"
                        " the window style or default font."), 1)
            ))

        lang = ustr(self.languageComboBox.itemData(
            self.languageComboBox.currentIndex()))
        debug.dprint(f"DEBUG: Setting language to {lang}")
        self.config.set('bitmessagesettings', 'userlocale', lang)
        self.parent.change_translation()

        if int(self.config.get('bitmessagesettings', 'port')) != int(
                self.lineEditTCPPort.text()):
            debug.dprint("DEBUG: Port changed, network restart needed")
            self.config.set(
                'bitmessagesettings', 'port', str(self.lineEditTCPPort.text()))
            if not self.config.safeGetBoolean(
                    'bitmessagesettings', 'dontconnect'):
                self.net_restart_needed = True

        if self.checkBoxUPnP.isChecked() != self.config.safeGetBoolean(
                'bitmessagesettings', 'upnp'):
            debug.dprint("DEBUG: UPnP setting changed")
            self.config.set(
                'bitmessagesettings', 'upnp',
                str(self.checkBoxUPnP.isChecked()))
            if self.checkBoxUPnP.isChecked():
                debug.dprint("DEBUG: UPnP enabled, starting thread")
                import upnp
                upnpThread = upnp.uPnPThread()
                upnpThread.start()

        udp_enabled = self.checkBoxUDP.isChecked()
        if udp_enabled != self.config.safeGetBoolean(
                'bitmessagesettings', 'udp'):
            debug.dprint(f"DEBUG: UDP setting changed to {udp_enabled}")
            self.config.set('bitmessagesettings', 'udp', str(udp_enabled))
            if udp_enabled:
                debug.dprint("DEBUG: UDP enabled, starting announce thread")
                announceThread = AnnounceThread()
                announceThread.daemon = True
                announceThread.start()
            else:
                debug.dprint("DEBUG: UDP disabled, stopping announce thread")
                try:
                    state.announceThread.stopThread()
                except AttributeError as e:
                    debug.dprint(f"DEBUG: Error stopping announce thread: {e}")

        proxytype_index = self.comboBoxProxyType.currentIndex()
        debug.dprint(f"DEBUG: Proxy type index: {proxytype_index}")
        if proxytype_index == 0:
            if self._proxy_type and state.statusIconColor != 'red':
                debug.dprint("DEBUG: Proxy disabled but was enabled, network restart needed")
                self.net_restart_needed = True
        elif state.statusIconColor == 'red' and self.config.safeGetBoolean(
                'bitmessagesettings', 'dontconnect'):
            debug.dprint("DEBUG: Proxy enabled but not connected, no restart needed")
            self.net_restart_needed = False
        elif self.comboBoxProxyType.currentText() != self._proxy_type:
            debug.dprint("DEBUG: Proxy type changed, network restart needed")
            self.net_restart_needed = True
            self.parent.statusbar.clearMessage()

        self.config.set(
            'bitmessagesettings', 'socksproxytype',
            'none' if self.comboBoxProxyType.currentIndex() == 0
            else str(self.comboBoxProxyType.currentText())
        )
        if proxytype_index > 2:  # last literal proxytype in ui
            debug.dprint("DEBUG: Custom proxy type, starting proxy config")
            start_proxyconfig()

        debug.dprint("DEBUG: Saving proxy settings")
        self.config.set('bitmessagesettings', 'socksauthentication', str(
            self.checkBoxAuthentication.isChecked()))
        self.config.set('bitmessagesettings', 'sockshostname', str(
            self.lineEditSocksHostname.text()))
        self.config.set('bitmessagesettings', 'socksport', str(
            self.lineEditSocksPort.text()))
        self.config.set('bitmessagesettings', 'socksusername', str(
            self.lineEditSocksUsername.text()))
        self.config.set('bitmessagesettings', 'sockspassword', str(
            self.lineEditSocksPassword.text()))
        self.config.set('bitmessagesettings', 'sockslisten', str(
            self.checkBoxSocksListen.isChecked()))
        if (
            self.checkBoxOnionOnly.isChecked()
            and not self.config.safeGetBoolean(
                'bitmessagesettings', 'onionservicesonly')
        ):
            debug.dprint("DEBUG: Onion-only enabled, network restart needed")
            self.net_restart_needed = True
        self.config.set('bitmessagesettings', 'onionservicesonly', str(
            self.checkBoxOnionOnly.isChecked()))
        try:
            debug.dprint("DEBUG: Saving rate limits")
            # Rounding to integers just for aesthetics
            self.config.set('bitmessagesettings', 'maxdownloadrate', str(
                int(float(self.lineEditMaxDownloadRate.text()))))
            self.config.set('bitmessagesettings', 'maxuploadrate', str(
                int(float(self.lineEditMaxUploadRate.text()))))
        except ValueError as e:
            debug.dprint(f"DEBUG: Invalid rate values: {e}")
            QtWidgets.QMessageBox.about(
                self, _translate("MainWindow", "Number needed"),
                _translate(
                    "MainWindow",
                    "Your maximum download and upload rate must be numbers."
                    " Ignoring what you typed.")
            )
        else:
            debug.dprint("DEBUG: Setting new rates")
            set_rates(
                self.config.safeGetInt('bitmessagesettings', 'maxdownloadrate'),
                self.config.safeGetInt('bitmessagesettings', 'maxuploadrate'))

        self.config.set('bitmessagesettings', 'maxoutboundconnections', str(
            int(float(self.lineEditMaxOutboundConnections.text()))))

        debug.dprint("DEBUG: Saving Namecoin settings")
        self.config.set(
            'bitmessagesettings', 'namecoinrpctype', self.getNamecoinType())
        self.config.set('bitmessagesettings', 'namecoinrpchost', ustr(
            self.lineEditNamecoinHost.text()))
        self.config.set('bitmessagesettings', 'namecoinrpcport', ustr(
            self.lineEditNamecoinPort.text()))
        self.config.set('bitmessagesettings', 'namecoinrpcuser', ustr(
            self.lineEditNamecoinUser.text()))
        self.config.set('bitmessagesettings', 'namecoinrpcpassword', ustr(
            self.lineEditNamecoinPassword.text()))
        self.parent.resetNamecoinConnection()

        # Demanded difficulty tab
        debug.dprint("DEBUG: Saving difficulty settings")
        if float(self.lineEditTotalDifficulty.text()) >= 1:
            self.config.set(
                'bitmessagesettings', 'defaultnoncetrialsperbyte',
                str(int(
                    float(self.lineEditTotalDifficulty.text())
                    * defaults.networkDefaultProofOfWorkNonceTrialsPerByte)))
        if float(self.lineEditSmallMessageDifficulty.text()) >= 1:
            self.config.set(
                'bitmessagesettings', 'defaultpayloadlengthextrabytes',
                str(int(
                    float(self.lineEditSmallMessageDifficulty.text())
                    * defaults.networkDefaultPayloadLengthExtraBytes)))

        if ustr(self.comboBoxOpenCL.currentText()) != ustr(self.config.safeGet(
                'bitmessagesettings', 'opencl')):
            debug.dprint("DEBUG: OpenCL setting changed")
            self.config.set(
                'bitmessagesettings', 'opencl',
                ustr(self.comboBoxOpenCL.currentText()))
            queues.workerQueue.put(('resetPoW', ''))

        acceptableDifficultyChanged = False

        if (
            float(self.lineEditMaxAcceptableTotalDifficulty.text()) >= 1
            or float(self.lineEditMaxAcceptableTotalDifficulty.text()) == 0
        ):
            if self.config.get(
                'bitmessagesettings', 'maxacceptablenoncetrialsperbyte'
            ) != str(int(
                float(self.lineEditMaxAcceptableTotalDifficulty.text())
                    * defaults.networkDefaultProofOfWorkNonceTrialsPerByte)):
                debug.dprint("DEBUG: Max acceptable total difficulty changed")
                acceptableDifficultyChanged = True
                self.config.set(
                    'bitmessagesettings', 'maxacceptablenoncetrialsperbyte',
                    str(int(
                        float(self.lineEditMaxAcceptableTotalDifficulty.text())
                        * defaults.networkDefaultProofOfWorkNonceTrialsPerByte))
                )
        if (
            float(self.lineEditMaxAcceptableSmallMessageDifficulty.text()) >= 1
            or float(self.lineEditMaxAcceptableSmallMessageDifficulty.text()) == 0
        ):
            if self.config.get(
                'bitmessagesettings', 'maxacceptablepayloadlengthextrabytes'
            ) != str(int(
                float(self.lineEditMaxAcceptableSmallMessageDifficulty.text())
                    * defaults.networkDefaultPayloadLengthExtraBytes)):
                debug.dprint("DEBUG: Max acceptable small message difficulty changed")
                acceptableDifficultyChanged = True
                self.config.set(
                    'bitmessagesettings', 'maxacceptablepayloadlengthextrabytes',
                    str(int(
                        float(self.lineEditMaxAcceptableSmallMessageDifficulty.text())
                        * defaults.networkDefaultPayloadLengthExtraBytes))
                )
        if acceptableDifficultyChanged:
            debug.dprint("DEBUG: Acceptable difficulty changed, updating messages")
            sqlExecute(
                "UPDATE sent SET status='msgqueued'"
                " WHERE status='toodifficult'")
            queues.workerQueue.put(('sendmessage', ''))

        stopResendingDefaults = False

        debug.dprint("DEBUG: Processing message resend settings")
        if self.lineEditDays.text() == '' and self.lineEditMonths.text() == '':
            debug.dprint("DEBUG: Using default resend behavior")
            self.config.set('bitmessagesettings', 'stopresendingafterxdays', '')
            self.config.set('bitmessagesettings', 'stopresendingafterxmonths', '')
            state.maximumLengthOfTimeToBotherResendingMessages = float('inf')
            stopResendingDefaults = True

        try:
            days = float(self.lineEditDays.text())
        except ValueError:
            debug.dprint("DEBUG: Invalid days value, setting to 0")
            self.lineEditDays.setText("0")
            days = 0.0
        try:
            months = float(self.lineEditMonths.text())
        except ValueError:
            debug.dprint("DEBUG: Invalid months value, setting to 0")
            self.lineEditMonths.setText("0")
            months = 0.0

        if days >= 0 and months >= 0 and not stopResendingDefaults:
            state.maximumLengthOfTimeToBotherResendingMessages = \
                days * 24 * 60 * 60 + months * 60 * 60 * 24 * 365 / 12
            if state.maximumLengthOfTimeToBotherResendingMessages < 432000:
                debug.dprint("DEBUG: Resend time too short, setting to never")
                QtWidgets.QMessageBox.about(
                    self,
                    _translate("MainWindow", "Will not resend ever"),
                    _translate(
                        "MainWindow",
                        "Note that the time limit you entered is less"
                        " than the amount of time Bitmessage waits for"
                        " the first resend attempt therefore your"
                        " messages will never be resent.")
                )
                self.config.set(
                    'bitmessagesettings', 'stopresendingafterxdays', '0')
                self.config.set(
                    'bitmessagesettings', 'stopresendingafterxmonths', '0')
                state.maximumLengthOfTimeToBotherResendingMessages = 0.0
            else:
                debug.dprint(f"DEBUG: Setting resend time to {state.maximumLengthOfTimeToBotherResendingMessages} seconds")
                self.config.set(
                    'bitmessagesettings', 'stopresendingafterxdays', str(days))
                self.config.set(
                    'bitmessagesettings', 'stopresendingafterxmonths',
                    str(months))

        debug.dprint("DEBUG: Saving config")
        self.config.save()

        if self.net_restart_needed:
            debug.dprint("DEBUG: Network restart needed, scheduling")
            self.net_restart_needed = False
            self.config.setTemp('bitmessagesettings', 'dontconnect', 'true')
            self.timer.singleShot(
                5000, lambda:
                self.config.setTemp(
                    'bitmessagesettings', 'dontconnect', 'false')
            )

        self.parent.updateStartOnLogon()

        if (
            state.appdata != paths.lookupExeFolder()
            and self.checkBoxPortableMode.isChecked()
        ):
            debug.dprint("DEBUG: Switching to portable mode")
            sqlStoredProcedure('movemessagstoprog')
            with open(paths.lookupExeFolder() + 'keys.dat', 'wb') as configfile:
                self.config.write(configfile)
            knownnodes.saveKnownNodes(paths.lookupExeFolder())
            try:
                os.remove(state.appdata + 'keys.dat')
                os.remove(state.appdata + 'knownnodes.dat')
            except Exception as e:
                debug.dprint(f"DEBUG: Error removing old files: {e}")
            previousAppdataLocation = state.appdata
            state.appdata = paths.lookupExeFolder()
            debug.resetLogging()
            try:
                os.remove(previousAppdataLocation + 'debug.log')
                os.remove(previousAppdataLocation + 'debug.log.1')
            except Exception as e:
                debug.dprint(f"DEBUG: Error removing old log files: {e}")

        if (
            state.appdata == paths.lookupExeFolder()
            and not self.checkBoxPortableMode.isChecked()
        ):
            debug.dprint("DEBUG: Switching from portable mode")
            state.appdata = paths.lookupAppdataFolder()
            if not os.path.exists(state.appdata):
                debug.dprint("DEBUG: Creating appdata directory")
                os.makedirs(state.appdata)
            sqlStoredProcedure('movemessagstoappdata')
            self.config.save()
            knownnodes.saveKnownNodes(state.appdata)
            try:
                os.remove(paths.lookupExeFolder() + 'keys.dat')
                os.remove(paths.lookupExeFolder() + 'knownnodes.dat')
            except Exception as e:
                debug.dprint(f"DEBUG: Error removing portable files: {e}")
            debug.resetLogging()
            try:
                os.remove(paths.lookupExeFolder() + 'debug.log')
                os.remove(paths.lookupExeFolder() + 'debug.log.1')
            except Exception as e:
                debug.dprint(f"DEBUG: Error removing portable log files: {e}")
