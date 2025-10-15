#!/usr/bin/env python3
import sqlite3
import os
import time
import subprocess
import tempfile

class LaTeXBridge:
    def __init__(self):
        self.db_path = "/home/jon/.config/PyBitmessage/messages.dat"
        
    def wrap_latex(self, content, title="BitMessage"):
        return f"""\\documentclass[12pt]{{article}}
\\usepackage[utf8]{{inputenc}}
\\usepackage[german]{{babel}}

\\title{{{title}}}
\\author{{BitMessage}}
\\date{{\\today}}

\\begin{{document}}

\\maketitle

{content}

\\end{{document}}"""
    
    def process_message(self, msgid, message, subject):
        print(f"📨 Neue Nachricht: {subject}")
        
        latex_content = self.wrap_latex(message, subject)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.tex', delete=False) as f:
            f.write(latex_content)
            temp_file = f.name
        
        print(f"📄 Öffne mit Texmaker: {temp_file}")
        
        try:
            subprocess.Popen(['texmaker', temp_file])
            return True
        except:
            return False
    
    def check_messages(self):
        if not os.path.exists(self.db_path):
            return 0
            
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT msgid, message, subject FROM inbox WHERE read = 0")
            messages = cursor.fetchall()
            
            for msgid, message, subject in messages:
                if self.process_message(msgid, message, subject):
                    cursor.execute("UPDATE inbox SET read = 1 WHERE msgid = ?", (msgid,))
                    conn.commit()
            
            conn.close()
            return len(messages)
        except:
            return 0
    
    def run(self):
        print("🚀 BitMessage LaTeX Bridge gestartet")
        print("💡 Drücke Strg+C zum Beenden\n")
        
        try:
            while True:
                count = self.check_messages()
                if count > 0:
                    print(f"✅ {count} Nachrichten verarbeitet")
                time.sleep(10)
        except KeyboardInterrupt:
            print("\n🛑 Bridge beendet")

if __name__ == "__main__":
    LaTeXBridge().run()
