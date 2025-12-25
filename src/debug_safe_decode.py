"""
Debug the safe_decode function
"""

import sys
sys.path.insert(0, '/home/jon/DEBUG_pybitmessage/src')

try:
    from helper_sql import safe_decode
    print("Testing safe_decode function:")
    print("=" * 60)
    
    test_cases = [
        b'msgqueued',
        b'awaitingpubkey',
        b'Test subject',
        b'sent',
        b'',
        'already a string',  # String statt Bytes
        None,
        b'\xff\xfe\x00\x01'  # Ungültiges UTF-8
    ]
    
    for test in test_cases:
        print(f"\nsafe_decode({repr(test)}):")
        try:
            result = safe_decode(test, "utf-8", "replace")
            print(f"  Result: {repr(result)}")
            print(f"  Type: {type(result).__name__}")
        except Exception as e:
            print(f"  Error: {e}")
            
except ImportError as e:
    print(f"Cannot import safe_decode: {e}")
    
    # Versuche es direkt zu finden
    import os
    helper_sql_path = '/home/jon/DEBUG_pybitmessage/src/helper_sql.py'
    if os.path.exists(helper_sql_path):
        print(f"\nLooking for safe_decode in helper_sql.py:")
        with open(helper_sql_path, 'r') as f:
            content = f.read()
            if 'def safe_decode' in content:
                # Zeige die Funktion
                lines = content.split('\n')
                in_function = False
                for line in lines:
                    if 'def safe_decode' in line:
                        in_function = True
                    if in_function:
                        print(line)
                        if line.strip() == '' and not line.startswith('    '):
                            in_function = False
            else:
                print("safe_decode function not found in helper_sql.py")
