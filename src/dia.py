#!/usr/bin/env python3
import sqlite3
import os
import sys
import time

def diagnose_database():
    db_path = os.path.expanduser('~/.config/PyBitmessage/messages.dat')
    
    if not os.path.exists(db_path):
        print(f"Database not found at {db_path}")
        return False
    
    print(f"Database size: {os.path.getsize(db_path) / 1024 / 1024:.2f} MB")
    
    # Try to connect with different modes
    for mode in ['ro', 'rw', 'rwc']:
        try:
            print(f"\nTrying mode '{mode}'...")
            conn = sqlite3.connect(f"file:{db_path}?mode={mode}", uri=True, timeout=30)
            cursor = conn.cursor()
            
            # Check basic tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            print(f"Found {len(tables)} tables")
            
            # Check sent table specifically
            if any('sent' in t[0].lower() for t in tables):
                cursor.execute("SELECT COUNT(*) FROM sent")
                count = cursor.fetchone()[0]
                print(f"Sent table has {count} rows")
                
                # Check status distribution
                cursor.execute("SELECT status, COUNT(*) FROM sent GROUP BY status")
                for status, cnt in cursor.fetchall():
                    print(f"  Status '{status}': {cnt} messages")
            
            conn.close()
            print(f"✓ Mode '{mode}' successful")
            
        except Exception as e:
            print(f"✗ Mode '{mode}' failed: {e}")
    
    return True

if __name__ == "__main__":
    print("=== PyBitmessage Database Diagnose ===")
    diagnose_database()
