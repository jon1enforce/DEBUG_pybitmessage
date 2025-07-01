"""
retranslateui.py - UI Translation Mixin
"""

from unqstr import ustr
import six
from bitmessageqt import widgets
from qtpy import QtWidgets


class RetranslateMixin(object):
    """Mixin class for retranslating UI elements"""
    
    def retranslateUi(self):
        """Retranslate all UI elements by reloading from .ui file"""
        print("DEBUG: [RetranslateMixin.retranslateUi] Starting UI retranslation")
        
        # Create temporary widget to load default translations
        defaults = QtWidgets.QWidget()
        ui_file = self.__class__.__name__.lower() + '.ui'
        print(f"DEBUG: [RetranslateMixin.retranslateUi] Loading UI file: {ui_file}")
        
        try:
            widgets.load(ui_file, defaults)
            print("DEBUG: [RetranslateMixin.retranslateUi] Successfully loaded UI file")
        except Exception as e:
            print(f"DEBUG: [RetranslateMixin.retranslateUi] Error loading UI file: {e}")
            return

        # Process all widgets in the defaults
        print(f"DEBUG: [RetranslateMixin.retranslateUi] Processing {len(defaults.__dict__)} widgets")
        
        for attr, value in six.iteritems(defaults.__dict__):
            print(f"DEBUG: [RetranslateMixin.retranslateUi] Processing widget: {attr}")
            
            # Check if widget exists in current instance
            if not hasattr(self, attr):
                print(f"DEBUG: [RetranslateMixin.retranslateUi] Widget {attr} not found in instance, skipping")
                continue

            # Handle text elements
            setTextMethod = getattr(value, "setText", None)
            if callable(setTextMethod):
                try:
                    default_text = getattr(defaults, attr).text()
                    print(f"DEBUG: [RetranslateMixin.retranslateUi] Setting text for {attr}: {default_text}")
                    getattr(self, attr).setText(ustr(default_text))
                except Exception as e:
                    print(f"DEBUG: [RetranslateMixin.retranslateUi] Error setting text for {attr}: {e}")
            
            # Handle table widgets
            elif isinstance(value, QtWidgets.QTableWidget):
                print(f"DEBUG: [RetranslateMixin.retranslateUi] Processing table widget: {attr}")
                
                # Process horizontal headers
                try:
                    cols = value.columnCount()
                    print(f"DEBUG: [RetranslateMixin.retranslateUi] Processing {cols} columns")
                    for i in range(cols):
                        header_text = getattr(defaults, attr).horizontalHeaderItem(i).text()
                        print(f"DEBUG: [RetranslateMixin.retranslateUi] Setting column {i} header: {header_text}")
                        getattr(self, attr).horizontalHeaderItem(i).setText(ustr(header_text))
                except Exception as e:
                    print(f"DEBUG: [RetranslateMixin.retranslateUi] Error processing columns for {attr}: {e}")
                
                # Process vertical headers
                try:
                    rows = value.rowCount()
                    print(f"DEBUG: [RetranslateMixin.retranslateUi] Processing {rows} rows")
                    for i in range(rows):
                        header_text = getattr(defaults, attr).verticalHeaderItem(i).text()
                        print(f"DEBUG: [RetranslateMixin.retranslateUi] Setting row {i} header: {header_text}")
                        getattr(self, attr).verticalHeaderItem(i).setText(ustr(header_text))
                except Exception as e:
                    print(f"DEBUG: [RetranslateMixin.retranslateUi] Error processing rows for {attr}: {e}")
            
            else:
                print(f"DEBUG: [RetranslateMixin.retranslateUi] Widget {attr} is not a text element or table, skipping")

        print("DEBUG: [RetranslateMixin.retranslateUi] UI retranslation completed")
