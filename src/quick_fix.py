with open('class_singleWorker.py', 'r') as f:
    lines = f.readlines()

# Finde den Anfang der Hilfsfunktionen
start_idx = -1
for i, line in enumerate(lines):
    if '# Python 3 compatibility helper functions' in line:
        start_idx = i
        break

if start_idx == -1:
    print("Could not find helper functions. Creating new file...")
    exit(1)

# Finde das Ende der Hilfsfunktionen (vor der nächsten Methodendefinition)
end_idx = start_idx
for i in range(start_idx + 1, len(lines)):
    if lines[i].strip().startswith('def ') and lines[i].strip().endswith('(self):'):
        # Wir haben die nächste Methode gefunden
        break
    end_idx = i

# Korrigiere die Einrückung von Zeile start_idx bis end_idx
for i in range(start_idx, end_idx + 1):
    if lines[i].strip() == 'def safe_bytes(self, value, encoding="utf-8"):':
        # Diese Zeile sollte 4 Leerzeichen Einrückung haben
        lines[i] = '    def safe_bytes(self, value, encoding="utf-8"):\n'
    elif lines[i].strip() == 'def safe_sql_query(self, query, *args):':
        lines[i] = '    def safe_sql_query(self, query, *args):\n'
    elif lines[i].strip() == '"""Safe SQL query wrapper."""':
        lines[i] = '        """Safe SQL query wrapper."""\n'
    elif lines[i].strip() == 'try:':
        lines[i] = '        try:\n'
    elif lines[i].strip() == 'import sqlite3':
        lines[i] = '            import sqlite3\n'
    elif lines[i].strip() == 'from helper_sql import sqlQuery':
        lines[i] = '            from helper_sql import sqlQuery\n'
    elif lines[i].strip() == 'safe_args = []':
        lines[i] = '            safe_args = []\n'
    elif i > 0 and lines[i-1].strip() == 'safe_args = []':
        # Die nächste Zeile nach safe_args = []
        if 'for arg in args:' in lines[i]:
            lines[i] = '            for arg in args:\n'

# Speichere korrigierte Datei
with open('class_singleWorker_fixed.py', 'w') as f:
    f.writelines(lines)

print("Fixed indentation. Saved as class_singleWorker_fixed.py")
