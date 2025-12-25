"""
Check the actual data types in the database
"""

import sqlite3
import binascii

conn = sqlite3.connect('messages.dat')
cursor = conn.cursor()

# WICHTIG: Setze text_factory auf str um Bytes zu vermeiden
conn.text_factory = str

print("Checking actual data in sent table:")
print("="*80)

# 1. Prüfe die Datentypen aller Spalten
cursor.execute("PRAGMA table_info(sent)")
columns = cursor.fetchall()
print("\nTable structure:")
for col in columns:
    print(f"  {col[0]}: {col[1]} ({col[2]})")

# 2. Prüfe die tatsächlichen Werte und Typen
print("\n\nActual data with types:")
print("-" * 80)

cursor.execute("SELECT rowid, * FROM sent")
rows = cursor.fetchall()

for row in rows:
    rowid = row[0]
    print(f"\nRow ID: {rowid}")
    print("-" * 40)
    
    for i, (col_info, value) in enumerate(zip(columns, row[1:]), 1):  # Skip rowid
        col_name = col_info[1]
        col_type = col_info[2].upper()
        
        print(f"{col_name} ({col_type}): ", end="")
        
        if value is None:
            print("NULL")
        elif col_type == 'BLOB':
            if isinstance(value, bytes):
                hex_val = binascii.hexlify(value).decode('ascii')
                print(f"BLOB (OK), length: {len(value)}, hex: {hex_val[:32]}...")
            else:
                print(f"NOT BYTES! Type: {type(value).__name__}, Value: {repr(value)[:50]}")
        elif col_type == 'TEXT':
            if isinstance(value, str):
                print(f"TEXT (OK): {repr(value)[:100]}")
            elif isinstance(value, bytes):
                print(f"TEXT AS BYTES! (PROBLEM): {repr(value)[:100]}")
                # Versuche zu dekodieren
                try:
                    decoded = value.decode('utf-8', 'replace')
                    print(f"  Decoded as UTF-8: {repr(decoded)}")
                except:
                    print(f"  Cannot decode as UTF-8")
            else:
                print(f"UNEXPECTED: Type: {type(value).__name__}, Value: {repr(value)[:100]}")
        else:  # INTEGER
            print(f"{type(value).__name__}: {value}")

# 3. Teste eine Query wie die GUI sie machen würde
print("\n" + "="*80)
print("Testing GUI-style query:")
print("="*80)

# Versuche verschiedene text_factory Einstellungen
for text_factory_name, text_factory in [("str", str), ("bytes", bytes)]:
    print(f"\nWith text_factory = {text_factory_name}:")
    conn.text_factory = text_factory
    
    cursor.execute("SELECT toaddress, subject, status FROM sent WHERE folder = 'sent'")
    rows = cursor.fetchall()
    
    for i, row in enumerate(rows):
        print(f"  Row {i}:")
        for j, value in enumerate(row):
            col_name = ['toaddress', 'subject', 'status'][j]
            print(f"    {col_name}: {repr(value)} (type: {type(value).__name__})")

# 4. Prüfe ob es ein Problem mit der GUI-Verbindung gibt
print("\n" + "="*80)
print("Checking database connection issues:")
print("="*80)

# Die GUI verwendet vielleicht helper_sql.sqlQuery
try:
    import sys
    sys.path.insert(0, '/home/jon/DEBUG_pybitmessage/src')
    from helper_sql import sqlQuery
    
    print("\nUsing helper_sql.sqlQuery (what GUI uses):")
    result = sqlQuery("SELECT toaddress, subject, status FROM sent WHERE folder = 'sent'")
    print(f"Result type: {type(result)}")
    if result:
        print(f"First row: {result[0]}")
        print(f"Types: {[type(cell).__name__ for cell in result[0]]}")
        
except Exception as e:
    print(f"Error with helper_sql: {e}")
    import traceback
    traceback.print_exc()

conn.close()

print("\n" + "="*80)
print("ANALYSIS:")
print("1. If TEXT fields show as 'TEXT AS BYTES', that's the problem")
print("2. The GUI might be using a different text_factory setting")
print("="*80)
