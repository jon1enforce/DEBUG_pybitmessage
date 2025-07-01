"""The MessageCompose class definition"""

from qtpy import QtCore, QtWidgets
from tr import _translate


class MessageCompose(QtWidgets.QTextEdit):
    """Editor class with wheel zoom functionality"""
    def __init__(self, parent=None):
        print("DEBUG: [MessageCompose.__init__] Initializing MessageCompose")
        super(MessageCompose, self).__init__(parent)
        
        try:
            # we'll deal with this later when we have a new message format
            print("DEBUG: [MessageCompose.__init__] Configuring rich text handling")
            self.setAcceptRichText(False)
            
            self.defaultFontPointSize = self.currentFont().pointSize()
            print(f"DEBUG: [MessageCompose.__init__] Default font size: {self.defaultFontPointSize}")
            
        except Exception as e:
            print(f"DEBUG: [MessageCompose.__init__] Error during initialization: {e}")
            raise

    def wheelEvent(self, event):
        """Mouse wheel scroll event handler"""
        print("DEBUG: [MessageCompose.wheelEvent] Handling wheel event")
        
        try:
            modifiers = QtWidgets.QApplication.queryKeyboardModifiers()
            ctrl_pressed = (modifiers & QtCore.Qt.ControlModifier) == QtCore.Qt.ControlModifier
            delta_y = event.angleDelta().y()
            
            print(f"DEBUG: [MessageCompose.wheelEvent] Modifiers: Ctrl={ctrl_pressed}, DeltaY={delta_y}")
            
            if ctrl_pressed and delta_y != 0:
                current_size = self.currentFont().pointSize()
                zoom_level = current_size * 100 / self.defaultFontPointSize
                
                if delta_y > 0:
                    print(f"DEBUG: [MessageCompose.wheelEvent] Zooming in from {current_size}pt")
                    self.zoomIn(1)
                else:
                    print(f"DEBUG: [MessageCompose.wheelEvent] Zooming out from {current_size}pt")
                    self.zoomOut(1)
                
                new_size = self.currentFont().pointSize()
                zoom_level = new_size * 100 / self.defaultFontPointSize
                print(f"DEBUG: [MessageCompose.wheelEvent] New zoom level: {zoom_level}%")
                
                QtWidgets.QApplication.activeWindow().statusbar.showMessage(
                    _translate("MainWindow", "Zoom level {0}%").format(zoom_level))
            else:
                print("DEBUG: [MessageCompose.wheelEvent] Performing normal scroll")
                # in QTextEdit, super does not zoom, only scroll
                super(MessageCompose, self).wheelEvent(event)
                
        except Exception as e:
            print(f"DEBUG: [MessageCompose.wheelEvent] Error handling wheel event: {e}")
            raise

    def reset(self):
        """Clear the edit content"""
        print("DEBUG: [MessageCompose.reset] Clearing editor content")
        try:
            self.setText('')
            print("DEBUG: [MessageCompose.reset] Editor cleared successfully")
        except Exception as e:
            print(f"DEBUG: [MessageCompose.reset] Error clearing editor: {e}")
            raise
