"""
Network status tab widget definition.
"""

import time

from qtpy import QtCore, QtGui, QtWidgets

import l10n
import network.stats
import state
from bitmessageqt import widgets
from network import connectionpool, knownnodes
from .retranslateui import RetranslateMixin
from tr import _translate
from .uisignaler import UISignaler
from helper_sql import safe_decode


class NetworkStatus(QtWidgets.QWidget, RetranslateMixin):
    """Network status tab"""
    def __init__(self, parent=None):
        super(NetworkStatus, self).__init__(parent)
        widgets.load('networkstatus.ui', self)

        header = self.tableWidgetConnectionCount.horizontalHeader()
        header.setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)

        # Somehow this value was 5 when I tested
        if header.sortIndicatorSection() > 4:
            header.setSortIndicator(0, QtCore.Qt.AscendingOrder)

        self.startup = time.localtime()

        self.UISignalThread = UISignaler.get()
        self.UISignalThread.updateNumberOfMessagesProcessed.connect(
            self.updateNumberOfMessagesProcessed)
        self.UISignalThread.updateNumberOfPubkeysProcessed.connect(
            self.updateNumberOfPubkeysProcessed)
        self.UISignalThread.updateNumberOfBroadcastsProcessed.connect(
            self.updateNumberOfBroadcastsProcessed)
        self.UISignalThread.updateNetworkStatusTab.connect(
            self.updateNetworkStatusTab)

        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.runEveryTwoSeconds)
        
        # Cache für Status-Icon Updates
        self.status_update_pending = False
        self.status_color_cache = None
        self.status_update_timer = QtCore.QTimer()
        self.status_update_timer.timeout.connect(self._performStatusIconUpdate)
        self.status_update_timer.setSingleShot(True)

    def startUpdate(self):
        """Start a timer to update counters every 2 seconds"""
        state.Inventory.numberOfInventoryLookupsPerformed = 0
        self.runEveryTwoSeconds()
        self.timer.start(2000)  # milliseconds

    def stopUpdate(self):
        """Stop counter update timer"""
        self.timer.stop()

    @staticmethod
    def formatBytes(num):
        """Format bytes nicely (binary prefixes - KiB, MiB, GiB)"""
        if num is None:
            num = 0
        
        # Konvertiere zu float für die Berechnung
        num_float = float(num)
        
        units = [
            _translate("networkstatus", "byte(s)", None, int(num)),
            "KiB",  # Kibibytes (1024 bytes)
            "MiB",  # Mebibytes
            "GiB",  # Gibibytes
            "TiB"   # Tebibytes
        ]
        
        unit_index = 0
        formatted_num = num_float
        
        # Use 1024 for binary prefixes
        while abs(formatted_num) >= 1024.0 and unit_index < len(units) - 1:
            formatted_num /= 1024.0
            unit_index += 1
        
        # Für die Übersetzung müssen wir sicherstellen, dass die Zahl im 32-Bit Bereich ist
        # Aber hier geben wir nur einen formatierten String zurück, keine Übersetzung
        if unit_index == 0:  # bytes
            return "%3.0f %s" % (formatted_num, units[unit_index])
        else:  # KiB, MiB, etc.
            return "%3.1f %s" % (formatted_num, units[unit_index])

    @staticmethod
    def formatByteRate(num):
        """Format transfer speed in kB/s"""
        num /= 1000
        return "%4.0f kB" % num

    def updateNumberOfObjectsToBeSynced(self):
        """Update the counter for number of objects to be synced"""
        pending = network.stats.pendingDownload() + network.stats.pendingUpload()
        # Sicherstellen, dass die Zahl für die Übersetzung im 32-Bit Bereich ist
        safe_pending = min(pending, 2147483647) if pending >= 0 else max(pending, -2147483648)
        self.labelSyncStatus.setText(_translate(
            "networkstatus", "Object(s) to be synced: %n", None, safe_pending))

    def updateNumberOfMessagesProcessed(self):
        """Update the counter for number of processed messages"""
        self.updateNumberOfObjectsToBeSynced()
        # Sicherstellen, dass die Zahl für die Übersetzung im 32-Bit Bereich ist
        safe_count = min(state.numberOfMessagesProcessed, 2147483647) if state.numberOfMessagesProcessed >= 0 else max(state.numberOfMessagesProcessed, -2147483648)
        self.labelMessageCount.setText(_translate(
            "networkstatus", "Processed %n person-to-person message(s).",
            None, safe_count))

    def updateNumberOfBroadcastsProcessed(self):
        """Update the counter for the number of processed broadcasts"""
        self.updateNumberOfObjectsToBeSynced()
        # Sicherstellen, dass die Zahl für die Übersetzung im 32-Bit Bereich ist
        safe_count = min(state.numberOfBroadcastsProcessed, 2147483647) if state.numberOfBroadcastsProcessed >= 0 else max(state.numberOfBroadcastsProcessed, -2147483648)
        self.labelBroadcastCount.setText(_translate(
            "networkstatus", "Processed %n broadcast message(s).", None, safe_count))

    def updateNumberOfPubkeysProcessed(self):
        """Update the counter for the number of processed pubkeys"""
        self.updateNumberOfObjectsToBeSynced()
        # Sicherstellen, dass die Zahl für die Übersetzung im 32-Bit Bereich ist
        safe_count = min(state.numberOfPubkeysProcessed, 2147483647) if state.numberOfPubkeysProcessed >= 0 else max(state.numberOfPubkeysProcessed, -2147483648)
        self.labelPubkeyCount.setText(_translate(
            "networkstatus", "Processed %n public key(s).", None, safe_count))

    def updateNumberOfBytes(self):
        """
        This function is run every two seconds, so we divide the rate
        of bytes sent and received by 2.
        """
        # Hier verwenden wir keine _translate() mit %n Platzhalter,
        # sondern nur String-Formatierung, da die Byte-Zahlen zu groß sein können
        download_speed = network.stats.downloadSpeed()
        total_download = network.stats.receivedBytes()
        upload_speed = network.stats.uploadSpeed()
        total_upload = network.stats.sentBytes()
        
        # Nur den statischen Text übersetzen
        down_text = _translate("networkstatus", "Down: {0}/s  Total: {1}")
        up_text = _translate("networkstatus", "Up: {0}/s  Total: {1}")
        
        # Formatierte Strings einfügen
        self.labelBytesRecvCount.setText(down_text.format(
            self.formatByteRate(download_speed),
            self.formatBytes(total_download)
        ))
        self.labelBytesSentCount.setText(up_text.format(
            self.formatByteRate(upload_speed),
            self.formatBytes(total_upload)
        ))

    def updateNetworkStatusTab(self, outbound, add, destination):
        """Add or remove an entry to the list of connected peers"""
        # pylint: disable=too-many-branches,undefined-variable
        if outbound:
            try:
                c = connectionpool.pool.outboundConnections[destination]
            except KeyError:
                if add:
                    return
        else:
            try:
                c = connectionpool.pool.inboundConnections[destination]
            except KeyError:
                try:
                    c = connectionpool.pool.inboundConnections[destination.host]
                except KeyError:
                    if add:
                        return

        self.tableWidgetConnectionCount.setUpdatesEnabled(False)
        self.tableWidgetConnectionCount.setSortingEnabled(False)

        if add:
            self.tableWidgetConnectionCount.insertRow(0)
            self.tableWidgetConnectionCount.setItem(
                0, 0, QtWidgets.QTableWidgetItem(
                    "%s:%i" % (destination.host, destination.port)))
            self.tableWidgetConnectionCount.setItem(
                0, 2, QtWidgets.QTableWidgetItem("%s" % (safe_decode(c.userAgent, "utf-8", "replace"))))
            self.tableWidgetConnectionCount.setItem(
                0, 3, QtWidgets.QTableWidgetItem("%s" % (c.tlsVersion)))
            self.tableWidgetConnectionCount.setItem(
                0, 4, QtWidgets.QTableWidgetItem(
                    "%s" % ",".join(map(str, c.streams))))
            try:
                # .. todo:: FIXME: hard coded stream no
                rating = "%.1f" % knownnodes.knownNodes[1][destination]['rating']
            except KeyError:
                rating = "-"
            self.tableWidgetConnectionCount.setItem(
                0, 1, QtWidgets.QTableWidgetItem("%s" % (rating)))
            if outbound:
                brush = QtGui.QBrush(
                    QtGui.QColor("yellow"), QtCore.Qt.SolidPattern)
            else:
                brush = QtGui.QBrush(
                    QtGui.QColor("green"), QtCore.Qt.SolidPattern)
            for j in range(1):
                self.tableWidgetConnectionCount.item(0, j).setBackground(brush)
            self.tableWidgetConnectionCount.item(0, 0).setData(
                QtCore.Qt.UserRole, destination)
            self.tableWidgetConnectionCount.item(0, 1).setData(
                QtCore.Qt.UserRole, outbound)
        else:
            if not connectionpool.pool.inboundConnections:
                # Deferred status icon update to avoid deadlock
                self._scheduleStatusIconUpdate('yellow')
            for i in range(self.tableWidgetConnectionCount.rowCount()):
                if self.tableWidgetConnectionCount.item(i, 0).data(
                        QtCore.Qt.UserRole) != destination:
                    continue
                if self.tableWidgetConnectionCount.item(i, 1).data(
                        QtCore.Qt.UserRole) == outbound:
                    self.tableWidgetConnectionCount.removeRow(i)
                    break

        self.tableWidgetConnectionCount.setUpdatesEnabled(True)
        self.tableWidgetConnectionCount.setSortingEnabled(True)
        self.labelTotalConnections.setText(_translate(
            "networkstatus", "Total Connections: {0}").format(
                self.tableWidgetConnectionCount.rowCount()
        ))
        # FYI: The 'singlelistener' thread sets the icon color to green
        # when it receives an incoming connection, meaning that the user's
        # firewall is configured correctly.
        if self.tableWidgetConnectionCount.rowCount():
            # Check if there are any outbound connections
            has_outbound = False
            for i in range(self.tableWidgetConnectionCount.rowCount()):
                if self.tableWidgetConnectionCount.item(i, 1).data(QtCore.Qt.UserRole):
                    has_outbound = True
                    break
            
            if has_outbound:
                self._scheduleStatusIconUpdate('green')
            elif state.statusIconColor == 'red':
                self._scheduleStatusIconUpdate('yellow')
        elif state.statusIconColor != 'red':
            self._scheduleStatusIconUpdate('red')

    def _scheduleStatusIconUpdate(self, color):
        """Schedule status icon update to avoid SQL deadlocks"""
        if color == self.status_color_cache and not self.status_update_pending:
            return  # No change needed
            
        self.status_color_cache = color
        if not self.status_update_pending:
            self.status_update_pending = True
            # Delay update to allow SQL locks to be released
            self.status_update_timer.start(100)  # 100ms delay

    def _performStatusIconUpdate(self):
        """Actually update the status icon (called from timer)"""
        if self.status_color_cache is not None:
            # Use QTimer.singleShot to ensure we're in main thread context
            QtCore.QTimer.singleShot(0, 
                lambda: self.window().setStatusIcon(self.status_color_cache))
        self.status_update_pending = False

    # timer driven
    def runEveryTwoSeconds(self):
        """Updates counters, runs every 2 seconds if the timer is running"""
        lookups = state.Inventory.numberOfInventoryLookupsPerformed / 2
        # Sicherstellen, dass die Zahl für die Übersetzung im 32-Bit Bereich ist
        safe_lookups = min(lookups, 2147483647) if lookups >= 0 else max(lookups, -2147483648)
        self.labelLookupsPerSecond.setText(_translate(
            "networkstatus", "Inventory lookups per second: {0}"
        ).format(safe_lookups))
        state.Inventory.numberOfInventoryLookupsPerformed = 0
        self.updateNumberOfBytes()
        self.updateNumberOfObjectsToBeSynced()

    def retranslateUi(self):
        """Conventional Qt Designer method for dynamic l10n"""
        super(NetworkStatus, self).retranslateUi()
        self.labelTotalConnections.setText(_translate(
            "networkstatus", "Total Connections: {0}"
        ).format(self.tableWidgetConnectionCount.rowCount()))
        self.labelStartupTime.setText(_translate(
            "networkstatus", "Since startup on {0}"
        ).format(l10n.formatTimestamp(self.startup)))
        self.updateNumberOfMessagesProcessed()
        self.updateNumberOfBroadcastsProcessed()
        self.updateNumberOfPubkeysProcessed()
