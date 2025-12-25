"""
Skript zum Debuggen von INSERT/UPDATE in sent-Tabelle
Füge dies in den PyBitMessage-Code ein, um zu sehen, wo fehlerhafte Daten eingefügt werden.
"""

import traceback
import sys

class DebugCursor:
    """Wrapper für SQLite-Cursor zum Debuggen"""
    
    def __init__(self, cursor):
        self.cursor = cursor
    
    def execute(self, sql, params=None):
        if 'sent' in sql.lower() and ('insert' in sql.lower() or 'update' in sql.lower()):
            print("\n" + "="*80)
            print("DEBUG: Operation auf sent-Tabelle erkannt")
            print(f"SQL: {sql}")
            print(f"Parameter: {params}")
            print("Stack Trace:")
            for line in traceback.format_stack()[:-1]:
                if 'sqlite3' not in line and 'debug_sent' not in line:
                    print(line.strip())
            print("="*80)
        
        if params:
            return self.cursor.execute(sql, params)
        else:
            return self.cursor.execute(sql)
    
    def __getattr__(self, name):
        return getattr(self.cursor, name)

# Anwendung im Code:
# Ersetze: cursor = conn.cursor()
# Durch:   cursor = DebugCursor(conn.cursor())
