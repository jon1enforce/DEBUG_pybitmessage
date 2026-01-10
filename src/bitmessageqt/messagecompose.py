"""The MessageCompose class definition WITH LaTeX TEMPLATES - COMPLETE WORKING VERSION"""

from qtpy import QtCore, QtGui, QtWidgets
from tr import _translate
import re
import tempfile
import subprocess
import os
from pathlib import Path
import webbrowser


class LatexPDFProcessor:
    """Simple PDF compilation for preview"""
    
    def compile_latex_to_pdf(self, latex_content):
        """Compiles LaTeX to PDF"""
        try:
            # Make sure it's a complete document
            if r'\documentclass' not in latex_content:
                latex_content = r"""\documentclass{article}
\begin{document}
""" + latex_content + r"""
\end{document}"""
            
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp_path = Path(tmpdir)
                
                # Write LaTeX file
                tex_file = tmp_path / "preview.tex"
                tex_file.write_text(latex_content, encoding='utf-8')
                
                # Compile PDF
                result = subprocess.run(
                    ['pdflatex', '-interaction=nonstopmode', '-halt-on-error', 
                     '-no-shell-escape', str(tex_file)],
                    cwd=tmp_path,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                # Read PDF if exists
                pdf_file = tmp_path / "preview.pdf"
                if pdf_file.exists() and pdf_file.stat().st_size > 0:
                    return pdf_file.read_bytes()
                
                return None
                
        except Exception as e:
            print(f"[LaTeX Preview] Error: {str(e)}")
            return None


class LatexTemplateManager:
    """Manages 8 LaTeX templates by status/profession"""
    
    TEMPLATES = {
        "standard": {
            "name": "📧 Standard Email",
            "button": "Standard",
            "description": "Professional business email with all formalities",
            "icon": "📧",
            "template": r"""\documentclass[11pt]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\geometry{a4paper, left=3cm, right=2cm, top=3cm, bottom=3cm}

\begin{document}

\begin{flushleft}
+++your name+++ \\
+++your street+++ \\
+++your zip city+++ \\
Phone: +++your phone+++ \\
Email: +++your email+++
\end{flushleft}

\begin{flushright}
\today
\end{flushright}

\vspace{1cm}

\begin{flushleft}
\textbf{To:} \\
+++recipient name+++ \\
+++recipient company+++ \\
+++recipient street+++ \\
+++recipient zip city+++
\end{flushleft}

\vspace{1cm}

\begin{center}
\textbf{\Large +++subject+++}
\end{center}

\vspace{1cm}

\noindent
\textbf{Dear +++recipient title+++ +++recipient name+++,}

\vspace{0.5cm}

+++body+++

\vspace{0.5cm}

+++final statement+++

\vspace{1cm}

\noindent
\textbf{Sincerely yours,}

\vspace{1cm}

\noindent
+++your name+++ \\
+++your position+++ \\
+++your company+++

\end{document}"""
        },
        
        "darling": {
            "name": "💝 Darling Email",
            "button": "Darling",
            "description": "Personal and warm correspondence for special people",
            "icon": "💝",
            "template": r"""\documentclass[12pt]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\geometry{a4paper, left=3.5cm, right=2.5cm, top=3cm, bottom=3cm}

\begin{document}

\pagestyle{empty}

\begin{center}
\Huge
\textcolor{purple}{For My Darling} \\
\vspace{0.5cm}
\Large
\textcolor{magenta}{+++recipient name+++} \\
\vspace{1cm}
\end{center}

\begin{flushright}
\small
From: +++your name+++ \\
Date: \today \\
\vspace{0.2cm}
\end{flushright}

\vspace{1cm}

\begin{center}
\Large
\textbf{My darling,}
\end{center}

\vspace{0.5cm}

\Large
+++body+++

\vspace{1cm}

\begin{center}
\fontsize{40}{40}\selectfont
\color{red}
$\heartsuit$ \\
\vspace{0.5cm}
\Large
I'm thinking of you! \\
\small
Every second, every day
\end{center}

\vspace{1cm}

\Large
+++final statement+++

\vspace{2cm}

\begin{flushright}
\Large
\textbf{With love,} \\
\vspace{0.5cm}
\Huge
+++your name+++
\end{flushright}

\end{document}"""
        },
        
        "scientist": {
            "name": "🔬 Scientist Report",
            "button": "Scientist",
            "description": "Scientific report with formulas, tables and measurement data",
            "icon": "🔬",
            "template": r"""\documentclass[12pt]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\geometry{a4paper, margin=2.5cm}
\usepackage{amsmath, amssymb}
\usepackage{booktabs}

\begin{document}

\title{\textbf{+++report title+++}}
\author{+++your name+++ \\ \small +++your institution+++}
\date{Experiment date: +++experiment date+++ \\ Report created: \today}
\maketitle

\begin{abstract}
\noindent
\textbf{Abstract:} +++abstract text+++
\end{abstract}

\section*{1. Introduction and Hypothesis}
\noindent
\textbf{Research question:} +++research question+++

\noindent
\textbf{Hypothesis:} +++hypothesis+++

\section*{2. Methodology}
+++methodology+++

\section*{3. Results}

\subsection*{3.1 Measurement Data Table}

\begin{table}[h]
\centering
\caption{+++table caption+++}
\begin{tabular}{lccc}
\toprule
\textbf{Sample} & \textbf{Measurement 1} & \textbf{Measurement 2} & \textbf{Average} \\
\midrule
Sample A & +++value a1+++ & +++value a2+++ & +++mean a+++ \\
Sample B & +++value b1+++ & +++value b2+++ & +++mean b+++ \\
Sample C & +++value c1+++ & +++value c2+++ & +++mean c+++ \\
\bottomrule
\end{tabular}
\end{table}

\subsection*{3.2 Mathematical Analysis}

\paragraph{Basic formulas:}
\begin{align}
F &= ma \tag{Newton's second law} \\
E &= mc^2 \tag{Mass-energy equivalence}
\end{align}

\paragraph{Experiment-specific calculation:}
\begin{equation}
+++formula 1+++
\end{equation}

\section*{4. Discussion}
\noindent
\textbf{Interpretation:} +++interpretation+++

\section*{5. Conclusion}
+++conclusion+++

\section*{6. Appendix}
\subsection*{Raw Data}
+++raw data+++

\vspace{1cm}

\noindent
\rule{\textwidth}{0.5pt}
\begin{center}
\small
\textbf{Protocol by:} +++your name+++ \\
\textbf{Protocol number:} PRT-+++protocol number+++ \\
\textbf{Classification:} +++classification+++
\end{center}

\end{document}"""
        },
        
        "president": {
            "name": "👔 President Memo",
            "button": "President",
            "description": "Board and executive level: strategic memos",
            "icon": "👔",
            "template": r"""\documentclass[12pt]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\geometry{a4paper, margin=3cm}

\begin{document}

\thispagestyle{empty}

\vspace*{2cm}

\begin{center}
\Huge \textbf{EXECUTIVE MEMO} \\
\vspace{0.5cm}
\Large \textbf{+++memo title+++} \\
\vspace{0.3cm}
\large \today
\end{center}

\vspace{2cm}

\begin{tabular}{ll}
\textbf{From:} & \textbf{+++your name+++} \\
& \small +++your position+++ \\
& \small +++your department+++ \\
& \\
\textbf{To:} & \textbf{+++recipient name+++} \\
& \small +++recipient position+++ \\
& \small +++recipient department+++ \\
& \\
\textbf{Priority:} & \textbf{+++priority+++} \\
\textbf{Deadline:} & \textbf{+++deadline+++} \\
\end{tabular}

\vspace{1.5cm}

\section*{Executive Summary}
+++executive summary+++

\section*{1. Strategic Context}
+++strategic context+++

\section*{2. Core Recommendation}
\noindent
\textbf{Recommendation:} +++recommendation+++

\noindent
\textbf{Justification:} +++justification+++

\section*{3. Risk Analysis}
\begin{itemize}
\item \textbf{Financial:} +++financial risk+++
\item \textbf{Operational:} +++operational risk+++
\end{itemize}

\section*{4. Implementation Plan}
\begin{itemize}
\item \textbf{Immediate:} +++immediate action+++
\item \textbf{Short-term:} +++shortterm action+++
\end{itemize}

\vspace{1.5cm}

\begin{tabular}{p{0.4\textwidth}p{0.4\textwidth}}
\textbf{Approved by:} & \textbf{Receipt confirmation:} \\
\vspace{1cm} & \vspace{1cm} \\
\hline
Name: & Name: \\
Position: & Position: \\
Date: & Date: \\
\end{tabular}

\end{document}"""
        },
        
        "confidential": {
            "name": "🔒 Strictly Confidential",
            "button": "Confidential",
            "description": "For highest confidentiality levels with security notes",
            "icon": "🔒",
            "template": r"""\documentclass[12pt]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\geometry{a4paper, margin=2.5cm}
\usepackage{xcolor}

\begin{document}

\thispagestyle{empty}

\vspace*{1cm}

\begin{center}
\Huge \textcolor{red}{\textbf{STRICTLY CONFIDENTIAL}} \\
\vspace{0.5cm}
\Large For authorized persons only - No distribution!
\end{center}

\vspace{2cm}

\begin{center}
\Huge \textbf{SECURITY DOCUMENT} \\
\vspace{0.5cm}
\Large Classification: \textbf{+++classification level+++} \\
\vspace{0.3cm}
\small Document number: +++document number+++ \\
\small Creation date: \today
\end{center}

\vspace{1cm}

\begin{tabular}{|l|l|}
\hline
\textbf{Recipient:} & +++recipient clearance+++ \\
\hline
\textbf{Authorization:} & +++access level+++ \\
\hline
\textbf{Valid until:} & +++valid until+++ \\
\hline
\end{tabular}

\vspace{1cm}

\section*{SECURITY NOTE}
\begin{itemize}
\item \textcolor{red}{\textbf{This document must not be copied or distributed}}
\item Only viewable in secured rooms
\item After reading, either destroy or store in safe
\end{itemize}

\section*{Content}
+++content+++

\section*{Special Instructions}
+++special instructions+++

\vspace{1cm}

\begin{tabular}{p{0.45\textwidth}p{0.45\textwidth}}
\textbf{Issued by:} & \textbf{Receipt confirmation:} \\
\vspace{0.5cm} & \vspace{0.5cm} \\
Name: \underline{\hspace{4cm}} & Name: \underline{\hspace{4cm}} \\
Date: \underline{\hspace{4cm}} & Date: \underline{\hspace{4cm}} \\
Signature: \underline{\hspace{4cm}} & Signature: \underline{\hspace{4cm}} \\
\end{tabular}

\end{document}"""
        },
        
        "legal": {
            "name": "⚖️ Legal Document",
            "button": "Legal",
            "description": "Legal document with paragraphs and formalities",
            "icon": "⚖️",
            "template": r"""\documentclass[12pt]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\geometry{a4paper, left=3cm, right=2cm, top=3cm, bottom=3cm}

\begin{document}

\begin{center}
\LARGE \textbf{LEGAL DOCUMENT} \\
\vspace{0.3cm}
\large +++document title+++ \\
\vspace{0.2cm}
\small Contract number: +++contract number+++ \\
\small Date: \today
\end{center}

\vspace{1cm}

\begin{tabular}{ll}
\textbf{Party A:} & +++party a name+++ \\
& \small +++party a address+++ \\
& \small Represented by: +++party a representative+++ \\
& \\
\textbf{Party B:} & +++party b name+++ \\
& \small +++party b address+++ \\
& \small Represented by: +++party b representative+++ \\
\end{tabular}

\vspace{1cm}

\section*{Preamble}
+++preamble+++

\section*{\S 1 Subject of Contract}
+++contract subject+++

\section*{\S 2 Obligations}
+++obligations+++

\section*{\S 3 Remuneration}
+++compensation+++

\section*{\S 4 Term and Termination}
+++duration termination+++

\section*{\S 5 Final Provisions}
+++final provisions+++

\vspace{2cm}

\begin{tabular}{p{0.45\textwidth}p{0.45\textwidth}}
\textbf{For Party A:} & \textbf{For Party B:} \\
\vspace{1.5cm} & \vspace{1.5cm} \\
\hline
Place, Date: & Place, Date: \\
\vspace{0.5cm} & \vspace{0.5cm} \\
Signature: & Signature: \\
Name: & Name: \\
Position: & Position: \\
\end{tabular}

\end{document}"""
        },
        
        "quick": {
            "name": "📝 Quick Note",
            "button": "Quick",
            "description": "Quick note for daily use",
            "icon": "📝",
            "template": r"""\documentclass[12pt]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\geometry{a4paper, margin=2cm}

\begin{document}

\begin{center}
\Large \textbf{NOTE} \\
\small from +++your name+++ | \today
\end{center}

\vspace{0.5cm}

\noindent
\textbf{Topic:} +++topic+++

\vspace{0.5cm}

\noindent
\textbf{Content:} \\
+++content+++

\vspace{0.5cm}

\noindent
\textbf{Actions:}
\begin{itemize}
\item +++action 1+++
\item +++action 2+++
\end{itemize}

\vspace{0.5cm}

\noindent
\textbf{Deadline:} +++deadline+++

\vspace{0.5cm}

\noindent
\textbf{Status:} +++status+++

\vspace{1cm}

\noindent
\rule{\textwidth}{0.2pt}
\begin{center}
\small
Created: \today | Priority: +++priority+++
\end{center}

\end{document}"""
        },
        
        "code": {
            "name": "💻 Code Documentation",
            "button": "Code",
            "description": "For programmers and developers",
            "icon": "💻",
            "template": r"""\documentclass[12pt]{article}
\usepackage[utf8]{inputenc}
\usepackage[T1]{fontenc}
\usepackage{geometry}
\geometry{a4paper, margin=2.5cm}
\usepackage{listings}
\usepackage{xcolor}

\lstset{
    basicstyle=\ttfamily\small,
    keywordstyle=\color{blue},
    commentstyle=\color{green},
    stringstyle=\color{red},
    numbers=left,
    numberstyle=\tiny\color{gray}
}

\begin{document}

\title{+++documentation title+++}
\author{+++author name+++ \\ +++author email+++}
\date{Version +++version+++ | \today}
\maketitle

\section*{Overview}
+++overview+++

\section*{Installation}
\begin{lstlisting}[language=bash]
+++installation command+++
\end{lstlisting}

\section*{Example Code}
\begin{lstlisting}[language=python]
+++example code+++
\end{lstlisting}

\section*{API Documentation}
+++api documentation+++

\section*{Known Issues}
+++known issues+++

\end{document}"""
        }
    }
    
    @classmethod
    def get_template_buttons(cls):
        """Returns all templates for buttons"""
        return [(key, template["name"], template["button"], template["icon"]) 
                for key, template in cls.TEMPLATES.items()]
    
    @classmethod
    def get_template_by_key(cls, key):
        """Finds template by key"""
        return cls.TEMPLATES.get(key)


class MessageCompose(QtWidgets.QTextEdit):
    """Editor class with LaTeX TEMPLATES - WORKING VERSION with buttons"""
    
    def __init__(self, parent=None):
        super(MessageCompose, self).__init__(parent)
        self.setAcceptRichText(False)
        self.defaultFontPointSize = self.currentFont().pointSize()
        
        # Initialize buttons - IMPORTANT: after widget is visible
        QtCore.QTimer.singleShot(100, self.init_latex_buttons)
    
    def init_latex_buttons(self):
        """Initializes LaTeX buttons - CALLED AFTER LOADING"""
        try:
            # Find the splitter widget that contains us
            parent = self.parent()
            
            # Traverse hierarchy to find verticalSplitter
            while parent:
                # Check if it's a splitter
                if hasattr(parent, 'addWidget'):
                    # This is our splitter!
                    self.add_buttons_to_splitter(parent)
                    return
                
                # Next parent
                parent = parent.parent()
            
            print("[LaTeX Buttons] No splitter found, trying alternative method")
            self.add_buttons_alternative()
            
        except Exception as e:
            print(f"[LaTeX Buttons] Error: {str(e)}")
    
    def add_buttons_to_splitter(self, splitter):
        """Adds buttons to splitter"""
        # Container for buttons
        button_widget = QtWidgets.QWidget()
        button_layout = QtWidgets.QHBoxLayout(button_widget)
        button_layout.setContentsMargins(5, 2, 5, 2)
        button_layout.setSpacing(3)
        
        # Add buttons
        self.create_template_buttons(button_layout)
        
        # Insert button widget at BEGINNING of splitter
        splitter.insertWidget(0, button_widget)
        
        print(f"[LaTeX Buttons] Buttons added to splitter: {splitter}")
    
    def add_buttons_alternative(self):
        """Alternative method if no splitter found"""
        # Find main window
        main_window = QtWidgets.QApplication.activeWindow()
        if not main_window:
            return
        
        # Search for suitable layout
        for widget in main_window.findChildren(QtWidgets.QWidget):
            if hasattr(widget, 'layout') and widget.layout():
                # Try to add buttons
                try:
                    button_widget = QtWidgets.QWidget()
                    button_layout = QtWidgets.QHBoxLayout(button_widget)
                    button_layout.setContentsMargins(5, 2, 5, 2)
                    
                    self.create_template_buttons(button_layout)
                    
                    # Add widget to layout
                    widget.layout().addWidget(button_widget)
                    print(f"[LaTeX Buttons] Buttons added to {widget}")
                    return
                except:
                    continue
    
    def create_template_buttons(self, layout):
        """Creates template buttons in given layout"""
        # Template manager
        template_manager = LatexTemplateManager()
        
        # Label
        label = QtWidgets.QLabel("LaTeX:")
        label.setStyleSheet("font-weight: bold; color: #0066cc;")
        layout.addWidget(label)
        
        # Buttons for each template
        button_count = 0
        for key, name, button_text, icon in template_manager.get_template_buttons():
            # Show only 8 buttons (all 8 templates)
            if button_count >= 8:
                break
                
            btn = QtWidgets.QPushButton(f"{icon} {button_text}")
            btn.setToolTip(name)
            btn.setMinimumHeight(28)
            btn.setMaximumHeight(28)
            btn.setMinimumWidth(70)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #f0f0f0;
                    border: 1px solid #ccc;
                    border-radius: 4px;
                    padding: 2px 5px;
                    font-size: 10px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #e0e0e0;
                    border-color: #999;
                }
                QPushButton:pressed {
                    background-color: #d0d0d0;
                }
            """)
            
            # Connect button to template function
            btn.clicked.connect(lambda checked, k=key: self.insert_template(k))
            layout.addWidget(btn)
            button_count += 1
        
        # Spacer
        layout.addSpacing(10)
        
        # Preview Button
        preview_btn = QtWidgets.QPushButton("👁 PDF Preview")
        preview_btn.setToolTip("Generate PDF preview")
        preview_btn.setMinimumHeight(28)
        preview_btn.setMaximumHeight(28)
        preview_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 2px 8px;
                font-size: 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3d8b40;
            }
        """)
        preview_btn.clicked.connect(self.show_preview)
        layout.addWidget(preview_btn)
        
        # Spacer at end
        layout.addStretch()
    
    def insert_template(self, template_key):
        """Inserts a template directly"""
        template_manager = LatexTemplateManager()
        template = template_manager.get_template_by_key(template_key)
        
        if template:
            # Replace current text
            self.setPlainText(template["template"])
            
            # Show status
            window = QtWidgets.QApplication.activeWindow()
            if window and hasattr(window, 'statusbar'):
                window.statusbar.showMessage(
                    _translate("MainWindow", f"Template '{template['name']}' inserted"), 
                    3000
                )
            
            # Move cursor to end
            cursor = self.textCursor()
            cursor.movePosition(QtGui.QTextCursor.End)
            self.setTextCursor(cursor)
            self.setFocus()
    
    def show_preview(self):
        """Shows PDF preview of current content"""
        latex_content = self.toPlainText()
        
        if not latex_content.strip():
            QtWidgets.QMessageBox.information(
                self, 
                "Info", 
                "No LaTeX code to preview.\n\n" +
                "Please select a template from the buttons above first."
            )
            return
        
        # Check if it's LaTeX
        if r'\begin{document}' not in latex_content or r'\end{document}' not in latex_content:
            reply = QtWidgets.QMessageBox.question(
                self, 
                "No complete LaTeX document",
                "The text doesn't contain a complete LaTeX document.\n" +
                "Should \\documentclass and \\begin/\\end{document} be added automatically?\n\n" +
                "Recommendation: Use a template from the buttons above.",
                QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
                QtWidgets.QMessageBox.No
            )
            
            if reply == QtWidgets.QMessageBox.Yes:
                latex_content = r"""\documentclass{article}
\begin{document}
""" + latex_content + r"""
\end{document}"""
            else:
                return
        
        # Compile PDF
        processor = LatexPDFProcessor()
        pdf_data = processor.compile_latex_to_pdf(latex_content)
        
        if pdf_data:
            try:
                # Create temporary PDF file
                with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp:
                    tmp.write(pdf_data)
                    tmp_path = tmp.name
                
                # Open PDF
                webbrowser.open(f"file://{tmp_path}")
                
                # Delete after 60 seconds
                QtCore.QTimer.singleShot(60000, 
                    lambda: os.unlink(tmp_path) if os.path.exists(tmp_path) else None)
                
                # Show status
                window = QtWidgets.QApplication.activeWindow()
                if window and hasattr(window, 'statusbar'):
                    window.statusbar.showMessage(
                        _translate("MainWindow", "PDF preview opened"), 
                        3000
                    )
                    
            except Exception as e:
                QtWidgets.QMessageBox.warning(
                    self, 
                    "Error",
                    f"PDF could not be opened:\n{str(e)}"
                )
        else:
            QtWidgets.QMessageBox.warning(
                self, 
                "Error",
                "PDF could not be created.\n\n" +
                "Possible causes:\n" +
                "• pdflatex is not installed\n" +
                "• LaTeX code contains errors\n" +
                "• Not enough memory available\n\n" +
                "Installation:\n" +
                "Ubuntu/Debian: sudo apt-get install texlive-latex-base\n" +
                "Windows: Install MikTeX (https://miktex.org)\n" +
                "macOS: Install MacTeX"
            )
    
    def wheelEvent(self, event):
        """Mouse wheel scroll event handler"""
        if (
            (QtWidgets.QApplication.queryKeyboardModifiers()
             & QtCore.Qt.ControlModifier) == QtCore.Qt.ControlModifier
            and event.angleDelta().y() != 0
        ):
            if event.angleDelta().y() > 0:
                self.zoomIn(1)
            else:
                self.zoomOut(1)
            QtWidgets.QApplication.activeWindow().statusbar.showMessage(
                _translate("MainWindow", "Zoom level {0}%").format(
                    self.currentFont().pointSize() * 100
                    / self.defaultFontPointSize
                ))
        else:
            super(MessageCompose, self).wheelEvent(event)

    def reset(self):
        """Clear the edit content"""
        self.setText('')