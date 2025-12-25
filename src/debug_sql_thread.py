"""
Debug the sqlThread to see if it's running
"""

import sys
import os
import time
import threading
sys.path.insert(0, '/home/jon/DEBUG_pybitmessage/src')

# Importiere die Queues aus helper_sql
from helper_sql import sqlSubmitQueue, sqlReturnQueue, sql_available, sql_ready

print("Debugging SQL Thread system:")
print("="*80)

print(f"sql_available: {sql_available}")
print(f"sql_ready.is_set(): {sql_ready.is_set() if hasattr(sql_ready, 'is_set') else 'N/A'}")

# Prüfe die Queues
print(f"\nsqlSubmitQueue size: {sqlSubmitQueue.qsize()}")
print(f"sqlReturnQueue size: {sqlReturnQueue.qsize()}")

# Versuche den sqlThread manuell zu starten
print("\n" + "="*80)
print("Trying to access SQL thread directly:")
print("="*80)

try:
    # Importiere threads module
    import threads
    
    # Suche nach sqlThread
    for attr_name in dir(threads):
        if 'sql' in attr_name.lower() or 'SQL' in attr_name:
            attr = getattr(threads, attr_name)
            print(f"Found in threads: {attr_name} = {attr}")
            
except Exception as e:
    print(f"Error importing threads: {e}")
    import traceback
    traceback.print_exc()

# Direkter Test: Versuche eine Query manuell
print("\n" + "="*80)
print("Direct queue test:")
print("="*80)

# Setze sql_available auf True für Test
import helper_sql
helper_sql.sql_available = True

# Test 1: Einfache Query direkt in Queue
try:
    # Versuche eine Query zu senden
    test_sql = "SELECT toaddress, subject, status FROM sent"
    print(f"Sending query: {test_sql}")
    
    # Clear queues first
    while not sqlSubmitQueue.empty():
        sqlSubmitQueue.get_nowait()
    while not sqlReturnQueue.empty():
        sqlReturnQueue.get_nowait()
    
    # Sende Query
    sqlSubmitQueue.put(test_sql, timeout=2)
    sqlSubmitQueue.put((), timeout=2)  # Leere args
    
    print("Query sent to queue")
    print(f"Queue size now: {sqlSubmitQueue.qsize()}")
    
    # Warte auf Antwort (mit Timeout)
    try:
        response = sqlReturnQueue.get(timeout=5)
        print(f"Got response: {response}")
    except:
        print("No response from sqlReturnQueue (timeout)")
        
except Exception as e:
    print(f"Queue test error: {e}")

# Test 2: Direkter Datenbankzugriff
print("\n" + "="*80)
print("Direct database access (bypassing queues):")
print("="*80)

import sqlite3

def direct_sql_query(sql, params=None):
    """Direkter Datenbankzugriff um zu prüfen ob es funktioniert"""
    db_path = 'messages.dat'
    try:
        conn = sqlite3.connect(db_path)
        conn.text_factory = str
        cursor = conn.cursor()
        
        if params:
            cursor.execute(sql, params)
        else:
            cursor.execute(sql)
        
        result = cursor.fetchall()
        conn.close()
        return result
    except Exception as e:
        return f"Error: {e}"

# Teste direkten Zugriff
test_queries = [
    ("SELECT COUNT(*) FROM sent", None),
    ("SELECT toaddress, subject FROM sent", None),
    ("SELECT name FROM sqlite_master WHERE type='table'", None),
]

for sql, params in test_queries:
    print(f"\nQuery: {sql}")
    result = direct_sql_query(sql, params)
    print(f"Result: {result}")
