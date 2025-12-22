#!/usr/bin/env python3
"""
DIAGNOSE: Warum schlägt INSERT in sent Tabelle fehl?
"""
import sys
import os
import sqlite3
import traceback

sys.path.append('.')

def diagnose_dbstr():
    """Finde und teste dbstr Funktion"""
    print("=== dbstr DIAGNOSE ===")
    
    # Versuche verschiedene Import-Pfade
    dbstr_func = None
    for module in ['dbcompat', 'helper_msgcoding', 'shared']:
        try:
            exec(f"from {module} import dbstr")
            dbstr_func = eval(f"dbstr")
            print(f"✓ dbstr gefunden in {module}")
            break
        except ImportError:
            continue
    
    if not dbstr_func:
        print("✗ dbstr NICHT gefunden! Das ist das Problem!")
        
        # Manuell suchen
        import ast
        for root, dirs, files in os.walk("."):
            for file in files:
                if file.endswith(".py"):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r') as f:
                            content = f.read()
                            if "def dbstr" in content:
                                print(f"  Mögliche Definition in: {path}")
                                # Parse die Funktion
                                tree = ast.parse(content)
                                for node in ast.walk(tree):
                                    if isinstance(node, ast.FunctionDef) and node.name == 'dbstr':
                                        print(f"  Funktion gefunden!")
                                        # Zeige ersten paar Zeilen
                                        print(f"  {ast.get_source_segment(content, node)}")
                    except:
                        pass
        return None
    
    # Teste dbstr mit verschiedenen Inputs
    print("\n=== dbstr TESTS ===")
    test_cases = [
        ("String", "msgqueued"),
        ("Bytes UTF-8", b"msgqueued"),
        ("Bytes mit Null", b"msg\x00queued"),
        ("Integer", 123),
        ("None", None),
    ]
    
    for name, value in test_cases:
        try:
            result = dbstr_func(value)
            print(f"✓ dbstr({name}: {repr(value)}) -> {type(result).__name__}: {repr(result)[:50]}")
        except Exception as e:
            print(f"✗ dbstr({name}: {repr(value)}) FEHLER: {e}")
    
    return dbstr_func

def diagnose_sqlite():
    """Teste direkte SQLite INSERTs"""
    print("\n=== SQLite DIAGNOSE ===")
    
    # Erstelle Test-Datenbank
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    
    # Erstelle sent Tabelle (wie im echten Schema)
    cursor.execute('''
        CREATE TABLE sent (
            msgid BLOB, 
            toaddress TEXT, 
            toripe BLOB, 
            fromaddress TEXT, 
            subject TEXT, 
            message TEXT, 
            ackdata BLOB,
            senttime INTEGER, 
            lastactiontime INTEGER, 
            sleeptill INTEGER, 
            status TEXT, 
            retrynumber INTEGER, 
            folder TEXT, 
            encodingtype INTEGER, 
            ttl INTEGER
        )
    ''')
    
    # Teste verschiedene INSERTs
    test_data = [
        ("Test 1: Alles Strings", [
            b'msgid123', 'to@addr', b'ripe123', 'from@addr',
            'Subject', 'Message text', b'ack123',
            1234567890, 1234567890, 0, 'msgqueued', 0, 'sent', 2, 216000
        ]),
        ("Test 2: Status als Bytes", [
            b'msgid456', 'to@addr', b'ripe456', 'from@addr',
            'Subject', 'Message text', b'ack456',
            1234567890, 1234567890, 0, b'msgqueued', 0, 'sent', 2, 216000  # <- Problem!
        ]),
    ]
    
    for test_name, data in test_data:
        try:
            cursor.execute('INSERT INTO sent VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', data)
            print(f"✓ {test_name}: ERFOLG")
        except sqlite3.InterfaceError as e:
            print(f"✗ {test_name}: InterfaceError - {e}")
        except Exception as e:
            print(f"✗ {test_name}: {type(e).__name__} - {e}")
    
    conn.close()

def check_existing_data():
    """Prüfe existierende Daten in der echten Datenbank"""
    print("\n=== EXISTIERENDE DATEN PRÜFEN ===")
    
    db_path = os.path.expanduser('~/.config/PyBitmessage/messages.dat')
    if not os.path.exists(db_path):
        print(f"Datenbank nicht gefunden: {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Zähle Einträge in sent
    cursor.execute("SELECT COUNT(*) FROM sent")
    count = cursor.fetchone()[0]
    print(f"Einträge in 'sent' Tabelle: {count}")
    
    # Prüfe Datentypen
    cursor.execute("SELECT status, typeof(status) FROM sent LIMIT 5")
    rows = cursor.fetchall()
    print(f"\nErste 5 status Werte und ihre Typen:")
    for status, type_name in rows:
        print(f"  Status: {repr(status)[:30]} ({type_name})")
    
    # Suche nach fehlerhaften Einträgen
    cursor.execute("SELECT COUNT(*) FROM sent WHERE typeof(status) = 'blob'")
    blob_count = cursor.fetchone()[0]
    print(f"\nStatus als BLOB (Problem!): {blob_count}")
    
    if blob_count > 0:
        print("  ✗ PROBLEM: Einige status Werte sind BLOBs (Bytes) statt TEXT!")
        cursor.execute("SELECT rowid, status FROM sent WHERE typeof(status) = 'blob' LIMIT 3")
        for rowid, status in cursor.fetchall():
            print(f"    Row {rowid}: {repr(status)[:50]}")
    
    conn.close()

if __name__ == "__main__":
    print("PyBitmessage Datenbank-Diagnose")
    print("=" * 50)
    
    dbstr_func = diagnose_dbstr()
    diagnose_sqlite()
    check_existing_data()
    
    print("\n" + "=" * 50)
    print("EMPFEHLUNGEN:")
    
    if dbstr_func:
        print("1. dbstr existiert, aber möglicherweise funktioniert sie nicht richtig mit Bytes")
        print("2. Prüfe ob 'status' manchmal als Bytes übergeben wird")
    else:
        print("1. KRITISCH: dbstr Funktion fehlt komplett!")
        print("2. Erstelle dbstr Funktion in dbcompat.py oder helper_msgcoding.py")
    
    print("3. Korrigiere helper_sent.py: status muss durch dbstr() gehen")
    print("4. Korrigiere account.py: 'msgqueued' muss durch dbstr() gehen")
