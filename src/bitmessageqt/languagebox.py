"""LanguageBox widget is for selecting UI language"""

import glob
import os

from qtpy import QtCore, QtWidgets

import paths
from bmconfigparser import config
from tr import _translate


# pylint: disable=too-few-public-methods
class LanguageBox(QtWidgets.QComboBox):
    """A subclass of `QtWidgets.QComboBox` for selecting language"""
    languageName = {
        "system": "System Settings",
        "eo": "Esperanto",
        "en_pirate": "Pirate English"
    }

    def __init__(self, parent=None):
        print("DEBUG: [LanguageBox.__init__] Initializing LanguageBox")
        super(LanguageBox, self).__init__(parent)
        try:
            self.populate()
            print("DEBUG: [LanguageBox.__init__] Language box initialized successfully")
        except Exception as e:
            print(f"DEBUG: [LanguageBox.__init__] Error during initialization: {e}")
            raise

    def populate(self):
        """Populates drop down list with all available languages."""
        print("DEBUG: [LanguageBox.populate] Starting language list population")
        try:
            self.clear()
            localesPath = os.path.join(paths.codePath(), 'translations')
            print(f"DEBUG: [LanguageBox.populate] Looking for translations in: {localesPath}")

            # Add system default option
            print("DEBUG: [LanguageBox.populate] Adding system default option")
            self.addItem(
                _translate("settingsDialog", "System Settings", "system"),
                "system"
            )
            self.setCurrentIndex(0)
            self.setInsertPolicy(QtWidgets.QComboBox.InsertAlphabetically)

            # Find and process all translation files
            translation_files = sorted(glob.glob(os.path.join(localesPath, "bitmessage_*.qm")))
            print(f"DEBUG: [LanguageBox.populate] Found {len(translation_files)} translation files")

            for translationFile in translation_files:
                try:
                    filename = os.path.split(translationFile)[1]
                    localeShort = filename.split("_", 1)[1][:-3]  # Remove 'bitmessage_' and '.qm'
                    print(f"DEBUG: [LanguageBox.populate] Processing locale: {localeShort}")

                    if localeShort in LanguageBox.languageName:
                        # Use predefined display name
                        display_name = LanguageBox.languageName[localeShort]
                        print(f"DEBUG: [LanguageBox.populate] Using predefined name: {display_name}")
                        self.addItem(display_name, localeShort)
                    else:
                        locale = QtCore.QLocale(localeShort)
                        native_name = locale.nativeLanguageName()
                        
                        if not native_name:
                            print(f"DEBUG: [LanguageBox.populate] No native name, using code: {localeShort}")
                            self.addItem(localeShort, localeShort)
                        else:
                            print(f"DEBUG: [LanguageBox.populate] Using native name: {native_name}")
                            self.addItem(native_name or localeShort, localeShort)
                except Exception as e:
                    print(f"DEBUG: [LanguageBox.populate] Error processing {translationFile}: {e}")
                    continue

            # Set configured locale if available
            configuredLocale = config.safeGet('bitmessagesettings', 'userlocale', 'system')
            print(f"DEBUG: [LanguageBox.populate] Looking for configured locale: {configuredLocale}")

            for i in range(self.count()):
                if self.itemData(i) == configuredLocale:
                    print(f"DEBUG: [LanguageBox.populate] Found configured locale at index {i}")
                    self.setCurrentIndex(i)
                    break
            else:
                print("DEBUG: [LanguageBox.populate] Configured locale not found, using default")

            print(f"DEBUG: [LanguageBox.populate] Language box populated with {self.count()} items")
        except Exception as e:
            print(f"DEBUG: [LanguageBox.populate] Error populating language box: {e}")
            raise
