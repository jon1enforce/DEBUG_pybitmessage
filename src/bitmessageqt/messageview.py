"""
Custom message viewer with LaTeX/PDF support using mdtex2html for LaTeX rendering
"""

import re
import tempfile
import subprocess
import os
from pathlib import Path
from qtpy import QtCore, QtGui, QtWidgets
from unqstr import ustr, unic

from .safehtmlparser import SafeHTMLParser
from tr import _translate


class LatexPDFProcessor:
    """Class for PDF processing with PyPDF2"""
    
    def __init__(self):
        self.max_compilation_time = 30
        self.has_pypdf2 = self._check_pypdf2()
        self.has_mdtex2html = self._check_mdtex2html()
        print(f"[LaTeX] PyPDF2 available: {self.has_pypdf2}")
        print(f"[LaTeX] mdtex2html available: {self.has_mdtex2html}")
    
    def _check_pypdf2(self):
        """Check if PyPDF2 is available"""
        try:
            import PyPDF2
            return True
        except ImportError:
            print("[LaTeX] PyPDF2 not available. pip install PyPDF2")
            return False
    
    def _check_mdtex2html(self):
        """Check if mdtex2html is available"""
        try:
            import mdtex2html
            return True
        except ImportError:
            print("[LaTeX] mdtex2html not available. pip install mdtex2html")
            return False
    
    def is_latex_document(self, content):
        """Check if it's a complete LaTeX document"""
        stripped = content.strip()
        
        has_begin = r'\begin{document}' in stripped
        has_end = r'\end{document}' in stripped
        
        if has_begin and has_end:
            begin_pos = stripped.find(r'\begin{document}')
            end_pos = stripped.find(r'\end{document}')
            
            if begin_pos < end_pos:
                return True
        
        return False
    
    def convert_latex_to_html(self, latex_content):
        """Convert LaTeX to HTML using mdtex2html"""
        if not self.has_mdtex2html:
            print("[LaTeX] mdtex2html not available")
            return latex_content  # Return original content
        
        try:
            import mdtex2html
            
            print(f"[LaTeX] Converting LaTeX to HTML: {len(latex_content)} chars")
            
            # Use mdtex2html to convert LaTeX to HTML
            html_content = mdtex2html.convert(latex_content)
            
            print(f"[LaTeX] ✅ HTML conversion successful: {len(html_content)} chars")
            return html_content
            
        except Exception as e:
            print(f"[LaTeX] mdtex2html conversion error: {str(e)}")
            return latex_content  # Return original content on error
    
    def compile_latex_to_pdf(self, latex_content):
        """Compile LaTeX to PDF"""
        print(f"[LaTeX] Compiling PDF, length: {len(latex_content)}")
        
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)
                
                # Write LaTeX file
                tex_file = tmp_path / "message.tex"
                tex_file.write_text(latex_content, encoding='utf-8')
                
                # Compile PDF
                pdf_file = tmp_path / "message.pdf"
                
                result = subprocess.run(
                    ['pdflatex', '-interaction=nonstopmode', '-halt-on-error', 
                     '-no-shell-escape', str(tex_file)],
                    cwd=tmp_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if pdf_file.exists() and pdf_file.stat().st_size > 0:
                    with open(pdf_file, 'rb') as f:
                        pdf_data = f.read()
                    
                    if pdf_data[:4] == b'%PDF':
                        print(f"[LaTeX] ✅ PDF successful: {len(pdf_data)} bytes")
                        return pdf_data
                    
                print(f"[LaTeX] ❌ PDF not created")
                return None
                    
        except Exception as e:
            print(f"[LaTeX] Error: {str(e)}")
            return None
    
    def get_pdf_info(self, pdf_data):
        """Extract information from PDF with PyPDF2"""
        if not pdf_data or not self.has_pypdf2:
            return {"pages": 0, "size_kb": 0}
        
        try:
            import PyPDF2
            import io
            
            pdf_stream = io.BytesIO(pdf_data)
            pdf_reader = PyPDF2.PdfReader(pdf_stream)
            
            size_kb = len(pdf_data) / 1024
            
            return {
                "pages": len(pdf_reader.pages),
                "size_kb": size_kb,
                "encrypted": pdf_reader.is_encrypted,
                "metadata": pdf_reader.metadata
            }
            
        except Exception as e:
            print(f"[LaTeX] PyPDF2 error: {str(e)}")
            return {"pages": 0, "size_kb": len(pdf_data) / 1024}
    
    def extract_first_page_text(self, pdf_data, max_chars=500):
        """Extract text from first page"""
        if not pdf_data or not self.has_pypdf2:
            return "No text preview available"
        
        try:
            import PyPDF2
            import io
            
            pdf_stream = io.BytesIO(pdf_data)
            pdf_reader = PyPDF2.PdfReader(pdf_stream)
            
            if len(pdf_reader.pages) > 0:
                page = pdf_reader.pages[0]
                text = page.extract_text()
                
                # Format text
                if text:
                    text = ' '.join(text.split())  # Remove extra spaces
                    if len(text) > max_chars:
                        text = text[:max_chars] + "..."
                    return text
                
            return "No text found on first page"
            
        except Exception as e:
            print(f"[LaTeX] Text extraction error: {str(e)}")
            return "Text could not be extracted"
    
    def save_pdf_to_file(self, pdf_data):
        """Save PDF to temporary file"""
        try:
            import tempfile
            import uuid
            
            filename = f"bm_pdf_{uuid.uuid4().hex[:8]}.pdf"
            temp_dir = tempfile.gettempdir()
            pdf_path = os.path.join(temp_dir, filename)
            
            with open(pdf_path, 'wb') as f:
                f.write(pdf_data)
            
            return pdf_path
            
        except Exception as e:
            print(f"[LaTeX] Error saving: {str(e)}")
            return None


class MessageView(QtWidgets.QTextBrowser):
    """Message viewer with LaTeX/PDF support (buttons only)"""
    
    MODE_PLAIN = 0
    MODE_HTML = 1
    MODE_LATEX = 2
    
    def __init__(self, parent=None):
        super(MessageView, self).__init__(parent)
        self.mode = MessageView.MODE_PLAIN
        self.html = None
        self.latex_processor = LatexPDFProcessor()
        
        # Normal initialization
        self.setOpenExternalLinks(False)
        self.setOpenLinks(False)
        self.anchorClicked.connect(self.confirmURL)
        self.out = ""
        self.outpos = 0
        self.document().setUndoRedoEnabled(False)
        self.rendering = False
        self.defaultFontPointSize = self.currentFont().pointSize()
        self.verticalScrollBar().valueChanged.connect(self.lazyRender)
        self.setWrappingWidth()
        
        # PDF data
        self.current_pdf_data = None
        self.current_pdf_path = None
        self.latex_source = None
        
        # Button Container
        self.button_container = None
        self.button_layout = None
    
    def setContent(self, data):
        """Set message content"""
        print(f"[MessageView] Message received ({len(data)} chars)")
        
        # Hide buttons
        self._hide_buttons()
        
        # Check if LaTeX document (ONLY if \begin{document} AND \end{document})
        if self.latex_processor.is_latex_document(data):
            print("[MessageView] LaTeX document detected")
            
            # Compile PDF
            self.latex_source = data
            pdf_data = self.latex_processor.compile_latex_to_pdf(data)
            
            if pdf_data:
                self.current_pdf_data = pdf_data
                self.current_pdf_path = self.latex_processor.save_pdf_to_file(pdf_data)
                
                # Extract PDF info
                pdf_info = self.latex_processor.get_pdf_info(pdf_data)
                preview_text = self.latex_processor.extract_first_page_text(pdf_data)
                
                # Convert LaTeX to HTML for display
                html_content = self.latex_processor.convert_latex_to_html(data)
                
                # Create HTML parser
                self.html = SafeHTMLParser()
                self.html.allow_picture = True
                
                # Add PDF info as HTML + converted LaTeX content
                pdf_info_html = self._create_pdf_info_html(pdf_info, preview_text)
                full_content = pdf_info_html + "\n\n" + html_content
                self.html.feed(full_content)
                self.html.close()
                
                # Create buttons
                self._create_action_buttons()
                
                # Show HTML directly
                self.showHTML()
                return
            else:
                print("[MessageView] PDF compilation failed, showing LaTeX as HTML")
                # Convert LaTeX to HTML even if PDF fails
                html_content = self.latex_processor.convert_latex_to_html(data)
                
                self.html = SafeHTMLParser()
                self.html.allow_picture = True
                self.html.feed(html_content)
                self.html.close()
                
                self.showHTML()
                return
        
        # Normal message - convert any LaTeX math to HTML
        print("[MessageView] Normal message - converting LaTeX if present")
        
        # Convert LaTeX math in the content
        converted_content = self.latex_processor.convert_latex_to_html(data)
        
        self.html = SafeHTMLParser()
        self.html.allow_picture = True
        self.html.feed(converted_content)
        self.html.close()
        
        # Show HTML directly if HTML is present
        if self.html and self.html.has_html:
            self.showHTML()
        else:
            self.showPlain()
    
    def _create_pdf_info_html(self, pdf_info, preview_text):
        """Create HTML for PDF info"""
        size_kb = pdf_info.get('size_kb', 0)
        pages = pdf_info.get('pages', 0)
        
        if size_kb < 1024:
            size_str = f"{size_kb:.0f} KB"
        else:
            size_str = f"{size_kb/1024:.1f} MB"
        
        info_html = f'''
        <div style="
            margin: 10px 0;
            padding: 10px;
            background-color: #e8f5e9;
            border: 1px solid #c8e6c9;
            border-radius: 5px;
            font-size: 12px;
            color: #2e7d32;
        ">
            <div style="font-weight: bold; margin-bottom: 5px;">
                📄 PDF successfully created ({size_str}, {pages} pages)
            </div>
            <div style="
                background-color: white;
                border: 1px solid #ddd;
                border-radius: 3px;
                padding: 8px;
                margin-top: 5px;
                font-family: monospace;
                font-size: 11px;
                max-height: 100px;
                overflow-y: auto;
                color: #333;
            ">
                {preview_text}
            </div>
        </div>
        '''
        
        return info_html
    
    def _create_action_buttons(self):
        """Create action buttons below the text field"""
        if not self.parent():
            return
        
        # Remove old buttons
        self._hide_buttons()
        
        # Create new container
        self.button_container = QtWidgets.QWidget(self.parent())
        self.button_layout = QtWidgets.QHBoxLayout(self.button_container)
        self.button_layout.setContentsMargins(10, 5, 10, 10)
        
        # Download Button
        download_btn = QtWidgets.QPushButton("💾 Download PDF")
        download_btn.clicked.connect(self.downloadPDF)
        download_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 15px;
                font-weight: bold;
                font-size: 12px;
                min-width: 150px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.button_layout.addWidget(download_btn)
        
        # Open Button
        open_btn = QtWidgets.QPushButton("📖 Open PDF")
        open_btn.clicked.connect(self.openPDFExternal)
        open_btn.setStyleSheet("""
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 15px;
                font-weight: bold;
                font-size: 12px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #1976D2;
            }
        """)
        self.button_layout.addWidget(open_btn)
        
        # Source Button
        source_btn = QtWidgets.QPushButton("📝 View Source")
        source_btn.clicked.connect(self.showLatexSource)
        source_btn.setStyleSheet("""
            QPushButton {
                background-color: #FF9800;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 15px;
                font-weight: bold;
                font-size: 12px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #F57C00;
            }
        """)
        self.button_layout.addWidget(source_btn)
        
        # Position button container (below the text field)
        parent_layout = self.parent().layout()
        if parent_layout:
            parent_layout.addWidget(self.button_container)
        
        self.button_container.show()
    
    def _hide_buttons(self):
        """Hide the buttons"""
        if self.button_container:
            self.button_container.hide()
            self.button_container.deleteLater()
            self.button_container = None
    
    def showPlain(self):
        """Render message as plain text."""
        self.mode = MessageView.MODE_PLAIN
        
        # Hide buttons
        self._hide_buttons()
        
        out = self.html.raw if self.html else ""
        
        # NO "HTML detected" banner - show directly
        self.out = out
        self.outpos = 0
        self.setHtml("")
        self.lazyRender()
    
    def showHTML(self):
        """Render message as HTML"""
        self.mode = MessageView.MODE_HTML
        
        # Buttons remain visible for LaTeX documents
        
        # NO "Click here to disable HTML" banner - show HTML directly
        self.out = self.html.sanitised if self.html else ""
        self.outpos = 0
        self.setHtml("")
        self.lazyRender()
    
    def confirmURL(self, link):
        """URL-Click-Handler"""
        if link.scheme() == "action":
            action = link.path()
            
            if action == "download_pdf":
                self.downloadPDF()
            elif action == "open_pdf":
                self.openPDFExternal()
            elif action == "show_source":
                self.showLatexSource()
            else:
                super(MessageView, self).confirmURL(link)
            return
        
        if link.scheme() == "mailto":
            window = QtWidgets.QApplication.activeWindow()
            window.ui.lineEditTo.setText(link.path())
            if link.hasQueryItem("subject"):
                window.ui.lineEditSubject.setText(
                    link.queryItemValue("subject"))
            if link.hasQueryItem("body"):
                window.ui.textEditMessage.setText(
                    link.queryItemValue("body"))
            window.setSendFromComboBox()
            window.ui.tabWidgetSend.setCurrentIndex(0)
            window.ui.tabWidget.setCurrentIndex(
                window.ui.tabWidget.indexOf(window.ui.send)
            )
            window.ui.textEditMessage.setFocus()
            return
        
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
            QtGui.QDesktopServices.openUrl(link)
    
    def downloadPDF(self):
        """Download the PDF"""
        if not self.current_pdf_data:
            QtWidgets.QMessageBox.warning(self, "Error", "No PDF available.")
            return
        
        filename, _ = QtWidgets.QFileDialog.getSaveFileName(
            self, "Save PDF", "document.pdf", "PDF Files (*.pdf)"
        )
        
        if filename:
            try:
                with open(filename, 'wb') as f:
                    f.write(self.current_pdf_data)
                
                QtWidgets.QMessageBox.information(
                    self, "Success", 
                    f"PDF saved:\n{filename}"
                )
            except Exception as e:
                QtWidgets.QMessageBox.warning(
                    self, "Error", f"Save failed:\n{str(e)}"
                )
    
    def openPDFExternal(self):
        """Open PDF with external viewer"""
        if not self.current_pdf_path or not os.path.exists(self.current_pdf_path):
            QtWidgets.QMessageBox.warning(self, "Error", "PDF not available.")
            return
        
        try:
            import webbrowser
            webbrowser.open(f"file://{self.current_pdf_path}")
            
            print(f"[LaTeX] PDF opened: {self.current_pdf_path}")
            
            window = QtWidgets.QApplication.activeWindow()
            if window and hasattr(window, 'statusbar'):
                window.statusbar.showMessage("Opening PDF...", 3000)
            
        except Exception as e:
            QtWidgets.QMessageBox.warning(
                self, "Error", f"Could not open PDF:\n{str(e)}"
            )
    
    def showLatexSource(self):
        """Show LaTeX source code"""
        if not self.latex_source:
            QtWidgets.QMessageBox.warning(self, "Error", "No LaTeX source available.")
            return
        
        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("LaTeX Source Code")
        dialog.resize(800, 600)
        
        layout = QtWidgets.QVBoxLayout(dialog)
        
        text_edit = QtWidgets.QTextEdit()
        text_edit.setPlainText(self.latex_source)
        text_edit.setFont(QtGui.QFont("Courier", 10))
        text_edit.setReadOnly(True)
        
        layout.addWidget(text_edit)
        
        button_box = QtWidgets.QDialogButtonBox()
        
        copy_btn = QtWidgets.QPushButton("Copy")
        copy_btn.clicked.connect(lambda: self.copyToClipboard(self.latex_source))
        
        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        
        button_box.addButton(copy_btn, QtWidgets.QDialogButtonBox.ActionRole)
        button_box.addButton(close_btn, QtWidgets.QDialogButtonBox.RejectRole)
        
        layout.addWidget(button_box)
        
        dialog.exec_()
    
    def copyToClipboard(self, text):
        """Copy text to clipboard"""
        clipboard = QtWidgets.QApplication.clipboard()
        clipboard.setText(text)
        
        QtWidgets.QMessageBox.information(
            self, "Copied", 
            "LaTeX source code copied."
        )
    
    # --- EXISTING METHODS ---
    
    def resizeEvent(self, event):
        super(MessageView, self).resizeEvent(event)
        self.setWrappingWidth(event.size().width())
    
    def mousePressEvent(self, event):
        if (
            event.button() == QtCore.Qt.LeftButton
            and self.html and self.html.has_html
            and self.cursorForPosition(event.pos()).block().blockNumber() == 0
        ):
            if self.mode == MessageView.MODE_PLAIN:
                self.showHTML()
            else:
                self.showPlain()
        else:
            super(MessageView, self).mousePressEvent(event)
    
    def wheelEvent(self, event):
        super(MessageView, self).wheelEvent(event)
        if (
            (QtWidgets.QApplication.queryKeyboardModifiers()
             & QtCore.Qt.ControlModifier) == QtCore.Qt.ControlModifier
            and event.angleDelta().y() != 0
        ):
            zoom = self.currentFont().pointSize() * 100 / self.defaultFontPointSize
            QtWidgets.QApplication.activeWindow().statusbar.showMessage(
                _translate("MainWindow", "Zoom level {0}%").format(zoom))
    
    def setWrappingWidth(self, width=None):
        self.setLineWrapMode(QtWidgets.QTextEdit.FixedPixelWidth)
        self.setLineWrapColumnOrWidth(width or self.width())
    
    def loadResource(self, restype, name):
        pass
    
    def lazyRender(self):
        if self.rendering:
            return
        self.rendering = True
        position = self.verticalScrollBar().value()
        cursor = QtGui.QTextCursor(self.document())
        while (
            self.outpos < len(self.out)
            and self.verticalScrollBar().value()
            >= self.document().size().height() - 2 * self.size().height()
        ):
            startpos = self.outpos
            self.outpos += 10240
            if self.mode == MessageView.MODE_HTML:
                pos = self.out.find(">", self.outpos)
                if pos > self.outpos:
                    self.outpos = pos + 1
            cursor.movePosition(
                QtGui.QTextCursor.End, QtGui.QTextCursor.MoveAnchor)
            cursor.insertHtml(unic(self.out[startpos:self.outpos]))
        self.verticalScrollBar().setValue(position)
        self.rendering = False