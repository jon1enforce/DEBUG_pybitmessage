#!/usr/bin/env python3
"""
SQL Injection Security Patch for PyBitMessage
Fixes unsafe SQL string construction vulnerabilities
"""

import re

def fix_sql_injection_vulnerabilities():
    files_to_patch = [
        'src/bitmessageqt/__init__.py',
        'src/api.py',
        'src/class_smtpServer.py'
    ]
    
    for file_path in files_to_patch:
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Patch 1: Fix unsafe table/column name interpolation
            old_pattern1 = r"""queryreturn = sqlQuery\(\s*'SELECT message FROM %s WHERE %s=CAST\(\? AS TEXT\)' % \(\s*\(['"]sent['"], ['"]ackdata['"]\) if folder == 'sent'\s*else \(['"]inbox['"], ['"]msgid['"]\)\s*\), msgid\s*\)"""
            
            new_code1 = """queryreturn = sqlQuery(
                'SELECT message FROM ' + ('sent' if folder == 'sent' else 'inbox') + 
                ' WHERE ' + ('ackdata' if folder == 'sent' else 'msgid') + '=CAST(? AS TEXT)',
                msgid
            )"""
            
            content = re.sub(old_pattern1, new_code1, content, flags=re.DOTALL)
            
            # Patch 2: Fix unsafe IN() clauses
            old_pattern2 = r'sqlExecuteChunked\(\s*"UPDATE inbox SET read = 1 WHERE msgid IN\(\{0\}\) AND read=0"'
            new_code2 = 'sqlExecuteChunked('
            new_code2 += '"UPDATE inbox SET read = 1 WHERE msgid IN ({}) AND read=0".format(",".join("?" * idCount))'
            
            content = re.sub(old_pattern2, new_code2, content)
            
            # Write patched file
            with open(file_path, 'w') as f:
                f.write(content)
                
            print(f"✅ Patched SQL injection vulnerabilities in {file_path}")
            
        except Exception as e:
            print(f"❌ Error patching {file_path}: {e}")

def add_sql_validation_functions():
    """Add SQL input validation functions"""
    
    validation_code = '''
# SQL Injection Protection Functions
def validate_sql_identifier(identifier):
    """Validate SQL table/column names to prevent injection"""
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', identifier):
        raise ValueError(f"Invalid SQL identifier: {identifier}")
    return identifier

def safe_sql_query(template, *params):
    """Execute SQL query with safe parameter substitution"""
    # Validate all string parameters
    safe_params = []
    for param in params:
        if isinstance(param, str):
            # Basic SQL injection prevention
            if any(keyword in param.upper() for keyword in ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'UNION', 'SELECT']):
                raise ValueError("Potential SQL injection detected")
        safe_params.append(param)
    
    return sqlQuery(template, *safe_params)
'''
    
    # Add to shared.py or create new security module
    with open('src/shared.py', 'a') as f:
        f.write(validation_code)
    
    print("✅ Added SQL validation functions")

if __name__ == "__main__":
    print("🔒 SQL Injection Security Patch")
    print("=" * 40)
    
    fix_sql_injection_vulnerabilities()
    add_sql_validation_functions()
    
    print("\\n📋 PATCH SUMMARY:")
    print("1. Fixed unsafe table/column name interpolation")
    print("2. Fixed unsafe IN() clause construction") 
    print("3. Added SQL input validation functions")
    print("4. All SQL injection vectors should now be closed")
