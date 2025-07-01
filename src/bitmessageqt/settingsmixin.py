"""
src/settingsmixin.py
====================

Mixin classes for saving and restoring widget state and geometry between sessions.
"""

from unqstr import ustr
from qtpy import QtCore, QtWidgets


class SettingsMixin(object):
    """Mixin for adding geometry and state saving between restarts"""
    
    def warnIfNoObjectName(self):
        """
        Handle objects which don't have a name. Currently it ignores them. Objects without a name can't have their
        state/geometry saved as they don't have an identifier.
        """
        if self.objectName() == "":
            print("DEBUG: [SettingsMixin] Object has no name, cannot save state/geometry")
            # .. todo:: logger
            pass

    def writeState(self, source):
        """Save object state (e.g. relative position of a splitter)"""
        print(f"DEBUG: [SettingsMixin.writeState] Saving state for {self.objectName()}")
        self.warnIfNoObjectName()
        if self.objectName():
            settings = QtCore.QSettings()
            settings.beginGroup(self.objectName())
            state_data = source.saveState()
            settings.setValue("state", state_data)
            settings.endGroup()
            print(f"DEBUG: [SettingsMixin.writeState] State saved for {self.objectName()}")

    def writeGeometry(self, source):
        """Save object geometry (e.g. window size and position)"""
        print(f"DEBUG: [SettingsMixin.writeGeometry] Saving geometry for {self.objectName()}")
        self.warnIfNoObjectName()
        if self.objectName():
            settings = QtCore.QSettings()
            settings.beginGroup(self.objectName())
            geom_data = source.saveGeometry()
            settings.setValue("geometry", geom_data)
            settings.endGroup()
            print(f"DEBUG: [SettingsMixin.writeGeometry] Geometry saved for {self.objectName()}")

    def readGeometry(self, target):
        """Load object geometry"""
        print(f"DEBUG: [SettingsMixin.readGeometry] Attempting to load geometry for {self.objectName()}")
        self.warnIfNoObjectName()
        if self.objectName():
            settings = QtCore.QSettings()
            try:
                geom = settings.value("/".join([ustr(self.objectName()), "geometry"]))
                if geom:
                    success = target.restoreGeometry(geom)
                    print(f"DEBUG: [SettingsMixin.readGeometry] Geometry {'restored' if success else 'failed to restore'} for {self.objectName()}")
                else:
                    print(f"DEBUG: [SettingsMixin.readGeometry] No saved geometry found for {self.objectName()}")
            except Exception as e:
                print(f"DEBUG: [SettingsMixin.readGeometry] Error restoring geometry for {self.objectName()}: {e}")

    def readState(self, target):
        """Load object state"""
        print(f"DEBUG: [SettingsMixin.readState] Attempting to load state for {self.objectName()}")
        self.warnIfNoObjectName()
        if self.objectName():
            settings = QtCore.QSettings()
            try:
                state = settings.value("/".join([ustr(self.objectName()), "state"]))
                if state:
                    success = target.restoreState(state)
                    print(f"DEBUG: [SettingsMixin.readState] State {'restored' if success else 'failed to restore'} for {self.objectName()}")
                else:
                    print(f"DEBUG: [SettingsMixin.readState] No saved state found for {self.objectName()}")
            except Exception as e:
                print(f"DEBUG: [SettingsMixin.readState] Error restoring state for {self.objectName()}: {e}")


class SMainWindow(QtWidgets.QMainWindow, SettingsMixin):
    """Main window with Settings functionality"""

    def loadSettings(self):
        """Load main window settings."""
        print("DEBUG: [SMainWindow.loadSettings] Loading main window settings")
        self.readGeometry(self)
        self.readState(self)

    def saveSettings(self):
        """Save main window settings"""
        print("DEBUG: [SMainWindow.saveSettings] Saving main window settings")
        self.writeState(self)
        self.writeGeometry(self)


class STableWidget(QtWidgets.QTableWidget, SettingsMixin):
    """Table widget with Settings functionality"""

    def loadSettings(self):
        """Load table settings."""
        print(f"DEBUG: [STableWidget.loadSettings] Loading table settings for {self.objectName()}")
        self.readState(self.horizontalHeader())

    def saveSettings(self):
        """Save table settings."""
        print(f"DEBUG: [STableWidget.saveSettings] Saving table settings for {self.objectName()}")
        self.writeState(self.horizontalHeader())


class SSplitter(QtWidgets.QSplitter, SettingsMixin):
    """Splitter with Settings functionality"""

    def loadSettings(self):
        """Load splitter settings"""
        print(f"DEBUG: [SSplitter.loadSettings] Loading splitter settings for {self.objectName()}")
        self.readState(self)

    def saveSettings(self):
        """Save splitter settings."""
        print(f"DEBUG: [SSplitter.saveSettings] Saving splitter settings for {self.objectName()}")
        self.writeState(self)


class STreeWidget(QtWidgets.QTreeWidget, SettingsMixin):
    """Tree widget with settings functionality"""

    def loadSettings(self):
        """Load tree settings. Unimplemented."""
        print(f"DEBUG: [STreeWidget.loadSettings] Tree widget settings loading not implemented for {self.objectName()}")
        # recurse children
        # self.readState(self)
        pass

    def saveSettings(self):
        """Save tree settings. Unimplemented."""
        print(f"DEBUG: [STreeWidget.saveSettings] Tree widget settings saving not implemented for {self.objectName()}")
        # recurse children
        # self.writeState(self)
        pass
