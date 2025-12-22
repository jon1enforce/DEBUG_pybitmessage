#!/usr/bin/env python3
"""
Test SQL compatibility for Python 3
"""

import os
import sys
import re

print("=== PYTHON 3 SQL COMPATIBILITY TEST ===\n")

# Test 1: Check class_sqlThread.py
print("1. Checking class_sqlThread.py...")
try:
    with open('class_sqlThread.py', 'r') as f:
        sql_content = f.read()
    
    issues = []
    
    # Check text_factory
    if 'self.conn.text_factory = str' in sql_content:
        issues.append("❌ text_factory = str (should be bytes)")
        print("   Found: text_factory = str")
    elif 'self.conn.text_factory = bytes' in sql_content:
        print("   ✅ text_factory = bytes")
    else:
        issues.append("❌ No text_factory setting found")
        print("   No text_factory setting")
    
    # Check buffer() vs memoryview()
    buffer_count = sql_content.count('buffer(')
    memoryview_count = sql_content.count('memoryview(')
    
    if buffer_count > 0:
        issues.append(f"❌ Found {buffer_count} buffer() calls (Python 2 only)")
        print(f"   Found {buffer_count} buffer() calls")
    if memoryview_count > 0:
        print(f"   ✅ Found {memoryview_count} memoryview() calls")
    
    # Check for decode/encode issues
    if '.decode(' in sql_content:
        decode_lines = [i+1 for i, line in enumerate(sql_content.split('\n')) if '.decode(' in line]
        issues.append(f"❌ Found .decode() calls on lines: {decode_lines}")
        print(f"   Found .decode() calls on lines: {decode_lines}")
    
    if '.encode(' in sql_content:
        encode_lines = [i+1 for i, line in enumerate(sql_content.split('\n')) if '.encode(' in line]
        issues.append(f"❌ Found .encode() calls on lines: {encode_lines}")
        print(f"   Found .encode() calls on lines: {encode_lines}")
    
    if issues:
        print(f"\n   ❌ Found {len(issues)} issues in class_sqlThread.py")
        for issue in issues:
            print(f"      {issue}")
    else:
        print("   ✅ class_sqlThread.py looks good!")
        
except Exception as e:
    print(f"   ❌ Error reading file: {e}")

print("\n" + "="*50 + "\n")

# Test 2: Check helper_sql.py
print("2. Checking helper_sql.py...")
try:
    with open('helper_sql.py', 'r') as f:
        helper_content = f.read()
    
    issues = []
    
    # Check for decode/encode
    if '.decode(' in helper_content:
        decode_lines = [i+1 for i, line in enumerate(helper_content.split('\n')) if '.decode(' in line]
        issues.append(f"❌ Found .decode() calls on lines: {decode_lines}")
        print(f"   Found .decode() calls on lines: {decode_lines}")
    
    if '.encode(' in helper_content:
        encode_lines = [i+1 for i, line in enumerate(helper_content.split('\n')) if '.encode(' in line]
        issues.append(f"❌ Found .encode() calls on lines: {encode_lines}")
        print(f"   Found .encode() calls on lines: {encode_lines}")
    
    # Check for sqlite3.Binary usage
    if 'sqlite3.Binary' in helper_content:
        print("   ✅ Using sqlite3.Binary for bytes")
    else:
        issues.append("❌ Not using sqlite3.Binary")
        print("   Not using sqlite3.Binary")
    
    if issues:
        print(f"\n   ❌ Found {len(issues)} issues in helper_sql.py")
        for issue in issues:
            print(f"      {issue}")
    else:
        print("   ✅ helper_sql.py looks good!")
        
except Exception as e:
    print(f"   ❌ Error reading file: {e}")

print("\n" + "="*50 + "\n")

# Test 3: Check singleWorker.py
print("3. Checking singleWorker.py...")
try:
    with open('class_singleWorker.py', 'r') as f:
        worker_content = f.read()
    
    issues = []
    
    # Count decode calls
    decode_count = worker_content.count('.decode(')
    if decode_count > 0:
        # Find lines with .decode()
        lines = []
        for i, line in enumerate(worker_content.split('\n')):
            if '.decode(' in line and 'safe_decode' not in line:
                lines.append(i+1)
        
        issues.append(f"❌ Found {decode_count} .decode() calls outside safe_decode() on lines: {lines[:10]}")
        print(f"   Found {decode_count} .decode() calls (outside safe_decode)")
    
    # Check if safe_decode is being used
    safe_decode_count = worker_content.count('self.safe_decode(')
    safe_sql_query_count = worker_content.count('self.safe_sql_query(')
    safe_sql_execute_count = worker_content.count('self.safe_sql_execute(')
    
    print(f"   safe_decode() calls: {safe_decode_count}")
    print(f"   safe_sql_query() calls: {safe_sql_query_count}")
    print(f"   safe_sql_execute() calls: {safe_sql_execute_count}")
    
    # Check for direct sqlQuery/sqlExecute calls
    direct_sqlquery = worker_content.count('sqlQuery(')
    direct_sqlexecute = worker_content.count('sqlExecute(')
    
    if direct_sqlquery > safe_sql_query_count:
        issues.append(f"❌ Still using sqlQuery() directly ({direct_sqlquery} times)")
        print(f"   Still using sqlQuery() directly: {direct_sqlquery} times")
    
    if direct_sqlexecute > safe_sql_execute_count:
        issues.append(f"❌ Still using sqlExecute() directly ({direct_sqlexecute} times)")
        print(f"   Still using sqlExecute() directly: {direct_sqlexecute} times")
    
    if issues:
        print(f"\n   ❌ Found {len(issues)} issues in singleWorker.py")
        for issue in issues:
            print(f"      {issue}")
    else:
        print("   ✅ singleWorker.py looks good!")
        
except Exception as e:
    print(f"   ❌ Error reading file: {e}")

print("\n" + "="*50)
print("SUMMARY: Run the fixes below if any issues were found")
print("="*50)
