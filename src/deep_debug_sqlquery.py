"""
Deep debug of sqlQuery function
"""

import sys
import os
sys.path.insert(0, '/home/jon/DEBUG_pybitmessage/src')

# Importiere und debugge helper_sql
import helper_sql
import inspect

print("Debugging helper_sql module:")
print("="*80)

# 1. Zeige die sqlQuery Funktion
print("\n1. sqlQuery function source:")
try:
    source = inspect.getsource(helper_sql.sqlQuery)
    print(source[:500] + "..." if len(source) > 500 else source)
except:
    print("Cannot get source")

# 2. Teste sqlQuery direkt
print("\n" + "="*80)
print("2. Testing sqlQuery directly:")
print("="*80)

# Erstelle eine Test-Datenbank-Verbindung
import sqlite3

# Test mit verschiedenen Parametern
test_queries = [
    ("Simple SELECT", "SELECT toaddress, subject, status FROM sent", None),
    ("SELECT with WHERE", "SELECT toaddress, subject, status FROM sent WHERE folder = ?", ('sent',)),
    ("SELECT all", "SELECT * FROM sent", None),
]

for desc, sql, params in test_queries:
    print(f"\n{desc}:")
    print(f"  SQL: {sql}")
    print(f"  Params: {params}")
    
    try:
        if params:
            result = helper_sql.sqlQuery(sql, *params)
        else:
            result = helper_sql.sqlQuery(sql)
        
        print(f"  Result type: {type(result)}")
        print(f"  Result: {result}")
        
        if isinstance(result, list):
            print(f"  Length: {len(result)}")
            if len(result) > 0:
                print(f"  First row type: {type(result[0])}")
                if isinstance(result[0], (list, tuple)):
                    print(f"  First row values: {result[0]}")
                    for i, val in enumerate(result[0]):
                        print(f"    [{i}]: {repr(val)} (type: {type(val).__name__})")
                
    except Exception as e:
        print(f"  ERROR: {e}")
        import traceback
        traceback.print_exc()

# 3. Prüfe die Datenbank-Verbindung in helper_sql
print("\n" + "="*80)
print("3. Checking database connection in helper_sql:")
print("="*80)

# Versuche die interne sqlSubmit Funktion zu finden
if hasattr(helper_sql, 'sqlSubmit'):
    print("Found sqlSubmit function")
    
    # Teste sqlSubmit
    try:
        # sqlSubmit gibt normalerweise cursor zurück
        cursor = helper_sql.sqlSubmit("SELECT toaddress FROM sent")
        if cursor:
            result = cursor.fetchall()
            print(f"sqlSubmit result: {result}")
    except Exception as e:
        print(f"sqlSubmit error: {e}")

# 4. Direkter Vergleich
print("\n" + "="*80)
print("4. Direct database access for comparison:")
print("="*80)

conn = sqlite3.connect('messages.dat')
cursor = conn.cursor()

# Prüfe ob die Tabelle existiert
cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='sent'")
table_exists = cursor.fetchone()
print(f"Table 'sent' exists: {table_exists}")

# Zähle die Einträge
cursor.execute("SELECT COUNT(*) FROM sent")
count = cursor.fetchone()[0]
print(f"Number of rows in sent: {count}")

# Hole alle Daten
cursor.execute("SELECT toaddress, subject, status FROM sent")
rows = cursor.fetchall()
print(f"\nDirect query returns {len(rows)} rows:")
for i, row in enumerate(rows):
    print(f"  Row {i}: {row}")

conn.close()
