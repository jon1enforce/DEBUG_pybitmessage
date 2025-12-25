"""
Test the GUI issue directly
"""

import sys
import os
sys.path.insert(0, '/home/jon/DEBUG_pybitmessage/src')

# 1. Teste helper_sql direkt
print("Testing helper_sql module:")
print("="*80)

try:
    from helper_sql import sqlQuery
    
    # Test query
    result = sqlQuery("SELECT toaddress, subject, status FROM sent")
    print(f"sqlQuery returned: {type(result)}")
    if result:
        print(f"Number of rows: {len(result)}")
        print(f"First row: {result[0]}")
        
        # Detailierte Analyse
        print("\nDetailed analysis of first row:")
        for i, value in enumerate(result[0]):
            col_name = ['toaddress', 'subject', 'status'][i]
            print(f"  {col_name}: {repr(value)} (type: {type(value).__name__})")
            
            # Wenn es Bytes sind, versuche zu dekodieren
            if isinstance(value, bytes):
                try:
                    decoded = value.decode('utf-8')
                    print(f"    Decoded: {repr(decoded)}")
                except:
                    print(f"    Cannot decode as UTF-8")
    
except Exception as e:
    print(f"Error with helper_sql: {e}")
    import traceback
    traceback.print_exc()

# 2. Finde heraus, wo die GUI die Daten abruft
print("\n" + "="*80)
print("Looking for GUI data fetching code:")
print("="*80)

# Suche nach relevanten GUI-Dateien
gui_files = []
for root, dirs, files in os.walk('/home/jon/DEBUG_pybitmessage/src/bitmessageqt'):
    for file in files:
        if file.endswith('.py'):
            gui_files.append(os.path.join(root, file))

# Suche nach sent-related Code
sent_patterns = [
    'getSentMessages',
    'sent.*model',
    'sent.*view',
    'SELECT.*FROM sent',
    'sent.*table'
]

for gui_file in gui_files:
    try:
        with open(gui_file, 'r') as f:
            content = f.read()
            
        for pattern in sent_patterns:
            if pattern.lower() in content.lower():
                print(f"\nFound '{pattern}' in {os.path.basename(gui_file)}:")
                # Zeige relevante Zeilen
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if pattern.lower() in line.lower():
                        context_start = max(0, i-2)
                        context_end = min(len(lines), i+3)
                        print(f"  Lines {context_start+1}-{context_end+1}:")
                        for j in range(context_start, context_end):
                            prefix = '>>> ' if j == i else '    '
                            print(f"{prefix}{lines[j]}")
                        break
                break
    except:
        pass

# 3. Teste die tatsächliche GUI-Funktion
print("\n" + "="*80)
print("Testing actual GUI function if it exists:")
print("="*80)

try:
    # Versuche das account Modul zu importieren
    import bitmessageqt.account as account
    
    # Suche nach Methoden, die sent messages holen
    for attr_name in dir(account):
        if 'sent' in attr_name.lower() or 'message' in attr_name.lower():
            attr = getattr(account, attr_name)
            if callable(attr):
                print(f"Found callable: {attr_name}")
                
                # Wenn es eine Methode ist, die keine Parameter braucht
                if attr_name == 'getSentMessages':
                    try:
                        # Erstelle ein Mock-Objekt wenn nötig
                        class MockAccount:
                            address = None
                        
                        result = attr(MockAccount())
                        print(f"  getSentMessages returned: {type(result)}")
                        if result:
                            print(f"  Length: {len(result)}")
                            if len(result) > 0:
                                print(f"  First item: {result[0]}")
                    except Exception as e:
                        print(f"  Error calling {attr_name}: {e}")
                        
except Exception as e:
    print(f"Error importing GUI modules: {e}")
