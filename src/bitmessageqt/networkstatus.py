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


class NetworkStatus(QtWidgets.QWidget, RetranslateMixin):
    """Network status tab"""
    def __init__(self, parent=None):
        print("DEBUG: [NetworkStatus.__init__] Initializing NetworkStatus")
        super(NetworkStatus, self).__init__(parent)
        
        try:
            print("DEBUG: [NetworkStatus.__init__] Loading UI file")
            widgets.load('networkstatus.ui', self)

            print("DEBUG: [NetworkStatus.__init__] Configuring table header")
            header = self.tableWidgetConnectionCount.horizontalHeader()
            header.setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)
            header.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
            header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)

            if header.sortIndicatorSection() > 4:
                print("DEBUG: [NetworkStatus.__init__] Resetting sort indicator")
                header.setSortIndicator(0, QtCore.Qt.AscendingOrder)

            self.startup = time.localtime()
            print(f"DEBUG: [NetworkStatus.__init__] Startup time set to {self.startup}")

            print("DEBUG: [NetworkStatus.__init__] Setting up signal connections")
            self.UISignalThread = UISignaler.get()
            self.UISignalThread.updateNumberOfMessagesProcessed.connect(
                self.updateNumberOfMessagesProcessed)
            self.UISignalThread.updateNumberOfPubkeysProcessed.connect(
                self.updateNumberOfPubkeysProcessed)
            self.UISignalThread.updateNumberOfBroadcastsProcessed.connect(
                self.updateNumberOfBroadcastsProcessed)
            self.UISignalThread.updateNetworkStatusTab.connect(
                self.updateNetworkStatusTab)

            print("DEBUG: [NetworkStatus.__init__] Setting up timer")
            self.timer = QtCore.QTimer()
            self.timer.timeout.connect(self.runEveryTwoSeconds)
            
        except Exception as e:
            print(f"DEBUG: [NetworkStatus.__init__] Error during initialization: {e}")
            raise

    def startUpdate(self):
        """Start a timer to update counters every 2 seconds"""
        print("DEBUG: [NetworkStatus.startUpdate] Starting updates")
        state.Inventory.numberOfInventoryLookupsPerformed = 0
        self.runEveryTwoSeconds()
        self.timer.start(2000)  # milliseconds
        print("DEBUG: [NetworkStatus.startUpdate] Timer started")

    def stopUpdate(self):
        """Stop counter update timer"""
        print("DEBUG: [NetworkStatus.stopUpdate] Stopping updates")
        self.timer.stop()

    @staticmethod
    def formatBytes(num):
        """Format bytes nicely (SI prefixes)"""
        print(f"DEBUG: [NetworkStatus.formatBytes] Formatting {num} bytes")
        for x in (
            _translate("networkstatus", "byte(s)", None, num),
            "kB", "MB", "GB"
        ):
            if num < 1000.0:
                result = "%3.0f %s" % (num, x)
                print(f"DEBUG: [NetworkStatus.formatBytes] Result: {result}")
                return result
            num /= 1000.0
        result = "%3.0f %s" % (num, "TB")
        print(f"DEBUG: [NetworkStatus.formatBytes] Result: {result}")
        return result

    @staticmethod
    def formatByteRate(num):
        """Format transfer speed in kB/s"""
        print(f"DEBUG: [NetworkStatus.formatByteRate] Formatting {num} bytes/s")
        num /= 1000
        result = "%4.0f kB" % num
        print(f"DEBUG: [NetworkStatus.formatByteRate] Result: {result}")
        return result

    def updateNumberOfObjectsToBeSynced(self):
        """Update the counter for number of objects to be synced"""
        pending = network.stats.pendingDownload() + network.stats.pendingUpload()
        print(f"DEBUG: [NetworkStatus.updateNumberOfObjectsToBeSynced] Pending objects: {pending}")
        self.labelSyncStatus.setText(_translate(
            "networkstatus", "Object(s) to be synced: %n", None, pending))

    def updateNumberOfMessagesProcessed(self):
        """Update the counter for number of processed messages"""
        print(f"DEBUG: [NetworkStatus.updateNumberOfMessagesProcessed] Messages: {state.numberOfMessagesProcessed}")
        self.updateNumberOfObjectsToBeSynced()
        self.labelMessageCount.setText(_translate(
            "networkstatus", "Processed %n person-to-person message(s).",
            None, state.numberOfMessagesProcessed))

    def updateNumberOfBroadcastsProcessed(self):
        """Update the counter for the number of processed broadcasts"""
        print(f"DEBUG: [NetworkStatus.updateNumberOfBroadcastsProcessed] Broadcasts: {state.numberOfBroadcastsProcessed}")
        self.updateNumberOfObjectsToBeSynced()
        self.labelBroadcastCount.setText(_translate(
            "networkstatus", "Processed %n broadcast message(s).", None,
            state.numberOfBroadcastsProcessed))

    def updateNumberOfPubkeysProcessed(self):
        """Update the counter for the number of processed pubkeys"""
        print(f"DEBUG: [NetworkStatus.updateNumberOfPubkeysProcessed] Pubkeys: {state.numberOfPubkeysProcessed}")
        self.updateNumberOfObjectsToBeSynced()
        self.labelPubkeyCount.setText(_translate(
            "networkstatus", "Processed %n public key(s).", None,
            state.numberOfPubkeysProcessed))

    def updateNumberOfBytes(self):
        """
        This function is run every two seconds, so we divide the rate
        of bytes sent and received by 2.
        """
        print("DEBUG: [NetworkStatus.updateNumberOfBytes] Updating byte counters")
        download_speed = network.stats.downloadSpeed()
        received_bytes = network.stats.receivedBytes()
        upload_speed = network.stats.uploadSpeed()
        sent_bytes = network.stats.sentBytes()
        
        print(f"DEBUG: [NetworkStatus.updateNumberOfBytes] Down: {download_speed}/s, Total: {received_bytes}")
        print(f"DEBUG: [NetworkStatus.updateNumberOfBytes] Up: {upload_speed}/s, Total: {sent_bytes}")
        
        self.labelBytesRecvCount.setText(_translate(
            "networkstatus", "Down: {0}/s  Total: {1}").format(
                self.formatByteRate(download_speed),
                self.formatBytes(received_bytes)
        ))
        self.labelBytesSentCount.setText(_translate(
            "networkstatus", "Up: {0}/s  Total: {1}").format(
                self.formatByteRate(upload_speed),
                self.formatBytes(sent_bytes)
        ))

    def updateNetworkStatusTab(self, outbound, add, destination):
        """Add or remove an entry to the list of connected peers"""
        print(f"DEBUG: [NetworkStatus.updateNetworkStatusTab] Updating connection: outbound={outbound}, add={add}, dest={destination}")
        
        try:
            if outbound:
                print("DEBUG: [NetworkStatus.updateNetworkStatusTab] Handling outbound connection")
                try:
                    c = connectionpool.pool.outboundConnections[destination]
                    print(f"DEBUG: [NetworkStatus.updateNetworkStatusTab] Found outbound connection: {c}")
                except KeyError:
                    if add:
                        print("DEBUG: [NetworkStatus.updateNetworkStatusTab] No outbound connection found for add operation")
                        return
            else:
                print("DEBUG: [NetworkStatus.updateNetworkStatusTab] Handling inbound connection")
                try:
                    c = connectionpool.pool.inboundConnections[destination]
                    print(f"DEBUG: [NetworkStatus.updateNetworkStatusTab] Found inbound connection: {c}")
                except KeyError:
                    try:
                        c = connectionpool.pool.inboundConnections[destination.host]
                        print(f"DEBUG: [NetworkStatus.updateNetworkStatusTab] Found inbound connection by host: {c}")
                    except KeyError:
                        if add:
                            print("DEBUG: [NetworkStatus.updateNetworkStatusTab] No inbound connection found for add operation")
                            return

            print("DEBUG: [NetworkStatus.updateNetworkStatusTab] Disabling table updates for performance")
            self.tableWidgetConnectionCount.setUpdatesEnabled(False)
            self.tableWidgetConnectionCount.setSortingEnabled(False)

            if add:
                print("DEBUG: [NetworkStatus.updateNetworkStatusTab] Adding new connection row")
                self.tableWidgetConnectionCount.insertRow(0)
                host_port = "%s:%i" % (destination.host, destination.port)
                print(f"DEBUG: [NetworkStatus.updateNetworkStatusTab] Setting host:port: {host_port}")
                self.tableWidgetConnectionCount.setItem(
                    0, 0, QtWidgets.QTableWidgetItem(host_port))
                
                user_agent = c.userAgent.decode("utf-8", "replace")
                print(f"DEBUG: [NetworkStatus.updateNetworkStatusTab] Setting user agent: {user_agent}")
                self.tableWidgetConnectionCount.setItem(
                    0, 2, QtWidgets.QTableWidgetItem("%s" % user_agent))
                
                tls_version = c.tlsVersion
                print(f"DEBUG: [NetworkStatus.updateNetworkStatusTab] Setting TLS version: {tls_version}")
                self.tableWidgetConnectionCount.setItem(
                    0, 3, QtWidgets.QTableWidgetItem("%s" % tls_version))
                
                streams = ",".join(map(str, c.streams))
                print(f"DEBUG: [NetworkStatus.updateNetworkStatusTab] Setting streams: {streams}")
                self.tableWidgetConnectionCount.setItem(
                    0, 4, QtWidgets.QTableWidgetItem("%s" % streams))
                
                try:
                    rating = "%.1f" % knownnodes.knownNodes[1][destination]['rating']
                    print(f"DEBUG: [NetworkStatus.updateNetworkStatusTab] Found rating: {rating}")
                except KeyError:
                    rating = "-"
                    print("DEBUG: [NetworkStatus.updateNetworkStatusTab] No rating found")
                self.tableWidgetConnectionCount.setItem(
                    0, 1, QtWidgets.QTableWidgetItem("%s" % rating))
                
                color = "yellow" if outbound else "green"
                print(f"DEBUG: [NetworkStatus.updateNetworkStatusTab] Setting color: {color}")
                brush = QtGui.QBrush(QtGui.QColor(color), QtCore.Qt.SolidPattern)
                for j in range(1):
                    self.tableWidgetConnectionCount.item(0, j).setBackground(brush)
                
                print("DEBUG: [NetworkStatus.updateNetworkStatusTab] Setting item data")
                self.tableWidgetConnectionCount.item(0, 0).setData(
                    QtCore.Qt.UserRole, destination)
                self.tableWidgetConnectionCount.item(0, 1).setData(
                    QtCore.Qt.UserRole, outbound)
            else:
                print("DEBUG: [NetworkStatus.updateNetworkStatusTab] Removing connection row")
                if not connectionpool.pool.inboundConnections:
                    print("DEBUG: [NetworkStatus.updateNetworkStatusTab] No inbound connections, setting yellow status")
                    self.window().setStatusIcon('yellow')
                    
                for i in range(self.tableWidgetConnectionCount.rowCount()):
                    if self.tableWidgetConnectionCount.item(i, 0).data(
                            QtCore.Qt.UserRole) != destination:
                        continue
                    if self.tableWidgetConnectionCount.item(i, 1).data(
                            QtCore.Qt.UserRole) == outbound:
                        print(f"DEBUG: [NetworkStatus.updateNetworkStatusTab] Removing row {i}")
                        self.tableWidgetConnectionCount.removeRow(i)
                        break

            print("DEBUG: [NetworkStatus.updateNetworkStatusTab] Enabling table updates")
            self.tableWidgetConnectionCount.setUpdatesEnabled(True)
            self.tableWidgetConnectionCount.setSortingEnabled(True)
            
            row_count = self.tableWidgetConnectionCount.rowCount()
            print(f"DEBUG: [NetworkStatus.updateNetworkStatusTab] Updating total connections: {row_count}")
            self.labelTotalConnections.setText(_translate(
                "networkstatus", "Total Connections: {0}").format(row_count))
            
            if row_count:
                if state.statusIconColor == 'red':
                    print("DEBUG: [NetworkStatus.updateNetworkStatusTab] Setting yellow status icon")
                    self.window().setStatusIcon('yellow')
            elif state.statusIconColor != 'red':
                print("DEBUG: [NetworkStatus.updateNetworkStatusTab] Setting red status icon")
                self.window().setStatusIcon('red')
                
        except Exception as e:
            print(f"DEBUG: [NetworkStatus.updateNetworkStatusTab] Error updating network status: {e}")
            raise
        finally:
            self.tableWidgetConnectionCount.setUpdatesEnabled(True)
            self.tableWidgetConnectionCount.setSortingEnabled(True)

    def runEveryTwoSeconds(self):
        """Updates counters, runs every 2 seconds if the timer is running"""
        print("DEBUG: [NetworkStatus.runEveryTwoSeconds] Running periodic update")
        lookups = state.Inventory.numberOfInventoryLookupsPerformed / 2
        print(f"DEBUG: [NetworkStatus.runEveryTwoSeconds] Inventory lookups: {lookups}/s")
        self.labelLookupsPerSecond.setText(_translate(
            "networkstatus", "Inventory lookups per second: {0}"
        ).format(lookups))
        state.Inventory.numberOfInventoryLookupsPerformed = 0
        self.updateNumberOfBytes()
        self.updateNumberOfObjectsToBeSynced()

    def retranslateUi(self):
        """Conventional Qt Designer method for dynamic l10n"""
        print("DEBUG: [NetworkStatus.retranslateUi] Retranslating UI")
        super(NetworkStatus, self).retranslateUi()
        
        row_count = self.tableWidgetConnectionCount.rowCount()
        print(f"DEBUG: [NetworkStatus.retranslateUi] Total connections: {row_count}")
        self.labelTotalConnections.setText(_translate(
            "networkstatus", "Total Connections: {0}"
        ).format(row_count))
        
        startup_time = l10n.formatTimestamp(self.startup)
        print(f"DEBUG: [NetworkStatus.retranslateUi] Startup time: {startup_time}")
        self.labelStartupTime.setText(_translate(
            "networkstatus", "Since startup on {0}"
        ).format(startup_time))
        
        self.updateNumberOfMessagesProcessed()
        self.updateNumberOfBroadcastsProcessed()
        self.updateNumberOfPubkeysProcessed()
