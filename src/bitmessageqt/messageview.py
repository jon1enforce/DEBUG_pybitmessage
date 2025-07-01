"""
Custom message viewer with support for switching between HTML and plain
text rendering, HTML sanitization, lazy rendering (as you scroll down),
zoom and URL click warning popup.
"""

from unqstr import ustr, unic
from qtpy import QtCore, QtGui, QtWidgets

from .safehtmlparser import SafeHTMLParser
from tr import _translate


class MessageView(QtWidgets.QTextBrowser):
    """Message content viewer class, can switch between plaintext and HTML"""
    MODE_PLAIN = 0
    MODE_HTML = 1

    def __init__(self, parent=None):
        print("DEBUG: [MessageView.__init__] Initializing MessageView")
        super(MessageView, self).__init__(parent)
        
        try:
            self.mode = MessageView.MODE_PLAIN
            self.html = None
            self.setOpenExternalLinks(False)
            self.setOpenLinks(False)
            print("DEBUG: [MessageView.__init__] Configured link handling")
            
            self.anchorClicked.connect(self.confirmURL)
            self.out = ""
            self.outpos = 0
            self.document().setUndoRedoEnabled(False)
            self.rendering = False
            self.defaultFontPointSize = self.currentFont().pointSize()
            print(f"DEBUG: [MessageView.__init__] Default font size: {self.defaultFontPointSize}")
            
            self.verticalScrollBar().valueChanged.connect(self.lazyRender)
            self.setWrappingWidth()
            print("DEBUG: [MessageView.__init__] Initialization complete")
            
        except Exception as e:
            print(f"DEBUG: [MessageView.__init__] Error during initialization: {e}")
            raise

    def resizeEvent(self, event):
        """View resize event handler"""
        print(f"DEBUG: [MessageView.resizeEvent] New size: {event.size()}")
        super(MessageView, self).resizeEvent(event)
        self.setWrappingWidth(event.size().width())

    def mousePressEvent(self, event):
        """Mouse press button event handler"""
        print(f"DEBUG: [MessageView.mousePressEvent] Mouse press at {event.pos()}")
        try:
            cursor = self.cursorForPosition(event.pos())
            block_num = cursor.block().blockNumber()
            print(f"DEBUG: [MessageView.mousePressEvent] Block number: {block_num}")
            
            if (event.button() == QtCore.Qt.LeftButton and 
                self.html and self.html.has_html and 
                block_num == 0):
                
                if self.mode == MessageView.MODE_PLAIN:
                    print("DEBUG: [MessageView.mousePressEvent] Switching to HTML mode")
                    self.showHTML()
                else:
                    print("DEBUG: [MessageView.mousePressEvent] Switching to plain mode")
                    self.showPlain()
            else:
                super(MessageView, self).mousePressEvent(event)
                
        except Exception as e:
            print(f"DEBUG: [MessageView.mousePressEvent] Error handling mouse press: {e}")
            raise

    def wheelEvent(self, event):
        """Mouse wheel scroll event handler"""
        print("DEBUG: [MessageView.wheelEvent] Handling wheel event")
        try:
            # super will actually automatically take care of zooming
            super(MessageView, self).wheelEvent(event)
            
            modifiers = QtWidgets.QApplication.queryKeyboardModifiers()
            ctrl_pressed = (modifiers & QtCore.Qt.ControlModifier) == QtCore.Qt.ControlModifier
            delta_y = event.angleDelta().y()
            
            print(f"DEBUG: [MessageView.wheelEvent] Ctrl pressed: {ctrl_pressed}, Delta Y: {delta_y}")
            
            if ctrl_pressed and delta_y != 0:
                current_size = self.currentFont().pointSize()
                zoom = current_size * 100 / self.defaultFontPointSize
                print(f"DEBUG: [MessageView.wheelEvent] Zoom level: {zoom}%")
                QtWidgets.QApplication.activeWindow().statusbar.showMessage(
                    _translate("MainWindow", "Zoom level {0}%").format(zoom))
                
        except Exception as e:
            print(f"DEBUG: [MessageView.wheelEvent] Error handling wheel event: {e}")
            raise

    def setWrappingWidth(self, width=None):
        """Set word-wrapping width"""
        wrap_width = width or self.width()
        print(f"DEBUG: [MessageView.setWrappingWidth] Setting wrap width: {wrap_width}")
        self.setLineWrapMode(QtWidgets.QTextEdit.FixedPixelWidth)
        self.setLineWrapColumnOrWidth(wrap_width)

    def confirmURL(self, link):
        """Show a dialog requesting URL opening confirmation"""
        print(f"DEBUG: [MessageView.confirmURL] Handling link click: {link.toString()}")
        try:
            if link.scheme() == "mailto":
                print("DEBUG: [MessageView.confirmURL] Handling mailto link")
                window = QtWidgets.QApplication.activeWindow()
                window.ui.lineEditTo.setText(link.path())
                
                if link.hasQueryItem("subject"):
                    subject = link.queryItemValue("subject")
                    print(f"DEBUG: [MessageView.confirmURL] Setting subject: {subject}")
                    window.ui.lineEditSubject.setText(subject)
                    
                if link.hasQueryItem("body"):
                    body = link.queryItemValue("body")
                    print(f"DEBUG: [MessageView.confirmURL] Setting body (length: {len(body)})")
                    window.ui.textEditMessage.setText(body)
                    
                window.setSendFromComboBox()
                window.ui.tabWidgetSend.setCurrentIndex(0)
                window.ui.tabWidget.setCurrentIndex(
                    window.ui.tabWidget.indexOf(window.ui.send)
                )
                window.ui.textEditMessage.setFocus()
                return
                
            print("DEBUG: [MessageView.confirmURL] Showing confirmation dialog")
            reply = QtWidgets.QMessageBox.warning(
                self, _translate("MessageView", "Follow external link"),
                _translate(
                    "MessageView",
                    "The link \"{0}\" will open in a browser. It may be"
                    " a security risk, it could de-anonymise you or download"
                    " malicious data. Are you sure?"
                ).format(unic(ustr(link.toString()))),
                QtWidgets.QMessageBox.Yes, QtWidgets.QMessageBox.No)
                
            if reply == QtWidgets.QMessageBox.Yes:
                print("DEBUG: [MessageView.confirmURL] User confirmed, opening URL")
                QtGui.QDesktopServices.openUrl(link)
            else:
                print("DEBUG: [MessageView.confirmURL] User cancelled URL opening")
                
        except Exception as e:
            print(f"DEBUG: [MessageView.confirmURL] Error handling URL click: {e}")
            raise

    def loadResource(self, restype, name):
        """
        Callback for loading referenced objects, such as an image.
        For security reasons at the moment doesn't do anything
        """
        print(f"DEBUG: [MessageView.loadResource] Blocked resource load - Type: {restype}, Name: {name}")
        pass

    def lazyRender(self):
        """
        Partially render a message. This is to avoid UI freezing when
        loading huge messages. It continues loading as you scroll down.
        """
        if self.rendering:
            print("DEBUG: [MessageView.lazyRender] Already rendering, skipping")
            return
            
        print("DEBUG: [MessageView.lazyRender] Starting lazy render")
        self.rendering = True
        
        try:
            position = self.verticalScrollBar().value()
            doc_height = self.document().size().height()
            view_height = self.size().height()
            threshold = doc_height - 2 * view_height
            
            print(f"DEBUG: [MessageView.lazyRender] Position: {position}, Threshold: {threshold}")
            
            cursor = QtGui.QTextCursor(self.document())
            while (self.outpos < len(self.out)) and (position >= threshold):
                startpos = self.outpos
                self.outpos += 10240
                
                if self.mode == MessageView.MODE_HTML:
                    pos = self.out.find(">", self.outpos)
                    if pos > self.outpos:
                        self.outpos = pos + 1
                        
                print(f"DEBUG: [MessageView.lazyRender] Rendering chunk {startpos}-{self.outpos}")
                cursor.movePosition(QtGui.QTextCursor.End, QtGui.QTextCursor.MoveAnchor)
                cursor.insertHtml(unic(self.out[startpos:self.outpos]))
                
                # Update position and threshold for next iteration
                position = self.verticalScrollBar().value()
                doc_height = self.document().size().height()
                threshold = doc_height - 2 * view_height
                
            self.verticalScrollBar().setValue(position)
            
        except Exception as e:
            print(f"DEBUG: [MessageView.lazyRender] Error during rendering: {e}")
            raise
        finally:
            self.rendering = False
            print("DEBUG: [MessageView.lazyRender] Rendering complete")

    def showPlain(self):
        """Render message as plain text."""
        print("DEBUG: [MessageView.showPlain] Switching to plain mode")
        self.mode = MessageView.MODE_PLAIN
        
        try:
            out = self.html.raw
            if self.html.has_html:
                print("DEBUG: [MessageView.showPlain] Adding HTML detection notice")
                out = (
                    '<div align="center" style="text-decoration: underline;"><b>'
                    + unic(ustr(_translate(
                        "MessageView", "HTML detected, click here to display"
                    ))) + '</b></div><br/>' + out)
                    
            self.out = out
            self.outpos = 0
            self.setHtml("")
            print(f"DEBUG: [MessageView.showPlain] Starting render (length: {len(out)})")
            self.lazyRender()
            
        except Exception as e:
            print(f"DEBUG: [MessageView.showPlain] Error switching to plain mode: {e}")
            raise

    def showHTML(self):
        """Render message as HTML"""
        print("DEBUG: [MessageView.showHTML] Switching to HTML mode")
        self.mode = MessageView.MODE_HTML
        
        try:
            self.out = (
                '<div align="center" style="text-decoration: underline;"><b>'
                + _translate("MessageView", "Click here to disable HTML")
                + '</b></div><br/>' + self.html.sanitised)
                
            self.outpos = 0
            self.setHtml("")
            print(f"DEBUG: [MessageView.showHTML] Starting render (length: {len(self.out)})")
            self.lazyRender()
            
        except Exception as e:
            print(f"DEBUG: [MessageView.showHTML] Error switching to HTML mode: {e}")
            raise

    def setContent(self, data):
        """Set message content from argument"""
        print(f"DEBUG: [MessageView.setContent] Setting new content (length: {len(data)})")
        try:
            self.html = SafeHTMLParser()
            self.html.allow_picture = True
            print("DEBUG: [MessageView.setContent] Parsing content")
            self.html.feed(data)
            self.html.close()
            print(f"DEBUG: [MessageView.setContent] HTML detected: {self.html.has_html}")
            self.showPlain()
        except Exception as e:
            print(f"DEBUG: [MessageView.setContent] Error setting content: {e}")
            raise
