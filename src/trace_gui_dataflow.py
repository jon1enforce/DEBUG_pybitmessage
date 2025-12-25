"""
Trace the data flow from database to GUI
"""

import sys
import os
sys.path.insert(0, '/home/jon/DEBUG_pybitmessage/src')

# Monkey-patch sqlQuery to debug
import helper_sql

original_sqlQuery = helper_sql.sqlQuery

def debug_sqlQuery(sql, *args):
    if 'sent' in sql.lower():
        print("\n" + "="*80)
        print("DEBUG: GUI is querying sent table")
        print(f"SQL: {sql}")
        print(f"Args: {args}")
        
        # Get original result
        result = original_sqlQuery(sql, *args)
        
        print(f"Result type: {type(result)}")
        print(f"Result length: {len(result) if result else 0}")
        if result and len(result) > 0:
            print(f"First row: {result[0]}")
            print(f"Types in first row: {[type(cell).__name__ for cell in result[0]]}")
        
        print("="*80)
        return result
    
    return original_sqlQuery(sql, *args)

helper_sql.sqlQuery = debug_sqlQuery

# Jetzt GUI-Module importieren, um zu sehen, was passiert
print("Tracing GUI data flow...")
print("Now try to open PyBitMessage GUI and click on sent tab")
print("The debug output will show what queries are executed.")

# Test: Simuliere eine GUI-Abfrage
print("\n" + "="*80)
print("Simulating a GUI query for sent messages:")
print("="*80)

# Import account module which might have getSentMessages
try:
    import bitmessageqt.account as account
    
    # Prüfe, ob es eine getSentMessages Methode gibt
    if hasattr(account, 'getSentMessages'):
        print("Found getSentMessages method")
        
        # Test-Aufruf
        import sqlite3
        from dbcompat import dbstr
        
        conn = sqlite3.connect('messages.dat')
        cursor = conn.cursor()
        
        # Simuliere die Abfrage aus account.py
        cursor.execute(
            '''SELECT toaddress, fromaddress, subject, status, lastactiontime, 
                      ackdata, msgid, retrynumber, folder, encodingtype 
               FROM sent WHERE folder=? ORDER BY senttime DESC''', 
            ('sent',)
        )
        
        rows = cursor.fetchall()
        print(f"Query returned {len(rows)} rows")
        
        if rows:
            print("\nFirst row data:")
            columns = ['toaddress', 'fromaddress', 'subject', 'status', 
                      'lastactiontime', 'ackdata', 'msgid', 'retrynumber', 
                      'folder', 'encodingtype']
            
            for i, (col_name, value) in enumerate(zip(columns, rows[0])):
                print(f"  {col_name}: {repr(value)} (type: {type(value).__name__})")
        
        conn.close()
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*80)
print("Next steps:")
print("1. Start PyBitMessage with this script loaded")
print("2. Click on sent tab in GUI")
print("3. Check debug output for queries")
print("="*80)
