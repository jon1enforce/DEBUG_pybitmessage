#!/usr/bin/env python3
# fix_all_decodes.py

import os
import re
import sys

def safe_decode_replacement(match):
    """Convert .decode() call to safe_decode() call"""
    var_name = match.group(1)
    args = match.group(2) if match.group(2) else ""
    
    if args:
        # Entferne führende/trailing quotes und Kommas
        args = args.strip()
        if args.startswith('"') or args.startswith("'"):
            args = args[1:-1]
        
        if ',' in args:
            # Mehrere Argumente
            parts = [p.strip() for p in args.split(',', 1)]
            if len(parts) == 2:
                return f"safe_decode({var_name}, {parts[0]}, {parts[1]})"
            else:
                return f"safe_decode({var_name}, {parts[0]})"
        else:
            return f"safe_decode({var_name}, {args})"
    else:
        return f"safe_decode({var_name})"

def fix_decode_calls_in_file(filepath):
    """Replace .decode() calls with safe_decode()"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original = content
    
    # Pattern 1: .decode()
    content = re.sub(r'(\w+)\.decode\(\)', r'safe_decode(\1)', content)
    
    # Pattern 2: .decode('utf-8')
    content = re.sub(r'(\w+)\.decode\(["\']utf-8["\']\)', r'safe_decode(\1, "utf-8")', content)
    
    # Pattern 3: .decode('utf-8', 'replace')
    content = re.sub(r'(\w+)\.decode\(["\']utf-8["\']\s*,\s*["\'](\w+)["\']\)', 
                     r'safe_decode(\1, "utf-8", "\2")', content)
    
    # Pattern 4: .decode('utf-8', "replace")
    content = re.sub(r'(\w+)\.decode\(["\']utf-8["\']\s*,\s*["\'](\w+)["\']\)', 
                     r'safe_decode(\1, "utf-8", "\2")', content)
    
    # Pattern 5: .decode('latin-1', 'replace')
    content = re.sub(r'(\w+)\.decode\(["\']latin-1["\']\s*,\s*["\'](\w+)["\']\)', 
                     r'safe_decode(\1, "latin-1", "\2")', content)
    
    # Pattern 6: .decode('ascii')
    content = re.sub(r'(\w+)\.decode\(["\']ascii["\']\)', r'safe_decode(\1, "ascii")', content)
    
    if content != original:
        # Prüfe ob safe_decode importiert werden muss
        if 'from helper_sql import safe_decode' not in content:
            # Finde den richtigen Platz für den Import
            lines = content.split('\n')
            
            # Suche nach anderen Imports
            import_found = False
            for i, line in enumerate(lines):
                if line.startswith('import ') or line.startswith('from '):
                    import_found = True
                    # Füge nach dem letzten Import hinzu
                    last_import_line = i
            
            if import_found:
                lines.insert(last_import_line + 1, 'from helper_sql import safe_decode')
            else:
                # Am Anfang einfügen
                lines.insert(0, 'from helper_sql import safe_decode')
            
            content = '\n'.join(lines)
        
        # Datei schreiben
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f"Fixed: {filepath}")
        return True
    
    return False

def main():
    src_dir = '/home/jon/DEBUG_pybitmessage/src'
    
    # Wichtige Dateien zuerst
    priority_files = [
        'shared.py',
        'api.py', 
        'helper_sql.py',
        'class_singleWorker.py',
        'bitmessageqt/__init__.py',
        'network/bmproto.py',
        'messagetypes/message.py',
        'helper_msgcoding.py'
    ]
    
    print("Fixing .decode() calls in priority files...")
    
    for filename in priority_files:
        filepath = os.path.join(src_dir, filename)
        if os.path.exists(filepath):
            try:
                if fix_decode_calls_in_file(filepath):
                    print(f"  ✓ Fixed: {filename}")
                else:
                    print(f"  ✓ No changes needed: {filename}")
            except Exception as e:
                print(f"  ✗ Error fixing {filename}: {e}")
    
    print("\nScanning for other files with .decode() calls...")
    
    # Alle anderen Dateien
    for root, dirs, files in os.walk(src_dir):
        # Überspringe backup und test Dateien
        if 'tests' in root or '__pycache__' in root:
            continue
            
        for file in files:
            if file.endswith('.py') and not file.endswith('.bak'):
                filepath = os.path.join(root, file)
                
                # Prüfe ob Datei bereits behandelt wurde
                if filepath in [os.path.join(src_dir, f) for f in priority_files]:
                    continue
                
                # Prüfe ob .decode() enthalten ist
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        if '.decode(' in f.read():
                            if fix_decode_calls_in_file(filepath):
                                print(f"  Fixed: {filepath}")
                except Exception as e:
                    print(f"  Error reading {filepath}: {e}")

if __name__ == '__main__':
    main()
