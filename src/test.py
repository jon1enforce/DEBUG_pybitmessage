#!/usr/bin/env python3
import sqlite3
import os
import sys

def check_all_issues():
    db_path = 'messages.dat'
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("=== DEBUG REPORT ===")
    
    # 1. Check sent table content
    print("\n1. SENT TABLE ANALYSIS:")
    cursor.execute("SELECT COUNT(*) FROM sent")
    total = cursor.fetchone()[0]
    print(f"   Total records in 'sent': {total}")
    
    cursor.execute("SELECT DISTINCT status, COUNT(*) FROM sent GROUP BY status")
    status_counts = cursor.fetchall()
    print("   Status distribution:")
    for status, count in status_counts:
        print(f"     {status}: {count}")
    
    # 2. Check for queued messages
    print("\n2. QUEUED MESSAGES CHECK:")
    cursor.execute('''SELECT COUNT(*) FROM sent 
                      WHERE (status='msgqueued' OR status='forcepow') 
                      AND folder='sent' ''')
    queued = cursor.fetchone()[0]
    print(f"   Queued messages: {queued}")
    
    if queued > 0:
        cursor.execute('''SELECT * FROM sent 
                          WHERE (status='msgqueued' OR status='forcepow') 
                          AND folder='sent' LIMIT 1''')
        row = cursor.fetchone()
        print(f"   Sample queued message has {len(row)} columns")
    
    # 3. Check connection issues in logs
    print("\n3. DATABASE CONNECTIONS:")
    cursor.execute("PRAGMA database_list")
    dbs = cursor.fetchall()
    for db in dbs:
        print(f"   Database: {db[1]} (file: {db[2]})")
    
    # 4. Check for locks
    print("\n4. LOCKS:")
    cursor.execute("PRAGMA locking_mode")
    print(f"   Locking mode: {cursor.fetchone()[0]}")
    
    # 5. Check the exact problematic query
    print("\n5. PROBLEMATIC QUERY TEST:")
    try:
        cursor.execute('''SELECT toaddress, fromaddress, subject, message, 
                                 ackdata, status, ttl, retrynumber, encodingtype 
                          FROM sent 
                          WHERE (status='msgqueued' or status='forcepow') 
                          AND folder='sent' LIMIT 1''')
        result = cursor.fetchone()
        if result:
            print(f"   ✓ Query successful, returned {len(result)} columns")
        else:
            print("   ✗ Query returned no results (THIS IS THE PROBLEM)")
            
            # Check why - maybe different status values
            cursor.execute("SELECT DISTINCT status FROM sent WHERE folder='sent'")
            actual_statuses = [s[0] for s in cursor.fetchall()]
            print(f"   Actual status values: {actual_statuses}")
    except Exception as e:
        print(f"   ✗ Query failed: {e}")
    
    # 6. Check worker processes
    print("\n6. SYSTEM CHECK:")
    print(f"   Current directory: {os.getcwd()}")
    print(f"   Database size: {os.path.getsize(db_path)} bytes")
    
    conn.close()
    
    print("\n=== RECOMMENDATIONS ===")
    if queued == 0:
        print("1. No queued messages found. This might be normal if you have no pending messages.")
        print("2. Check if messages should have status 'msgqueued' or something else.")
    else:
        print(f"1. Found {queued} queued messages but query returns empty.")
        print("2. The SQL query might have a different column order than expected.")

if __name__ == "__main__":
    check_all_issues()
