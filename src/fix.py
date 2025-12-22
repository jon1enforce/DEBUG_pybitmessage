#!/usr/bin/env python3
# fix_remaining_problems.py

import os
import re

def fix_remaining():
    src_dir = '/home/jon/DEBUG_pybitmessage/src'
    
    problems = [
        # Datei, Zeile, Suchmuster, Ersatz
        ('network/bmproto.py', 553,
         r'self\.safe_decode\(userAgent',
         r'safe_decode(self.userAgent'),
        
        ('pyelliptic/openssl.py', 1075,
         r'result\.safe_decode\(stdout\)',
         r'safe_decode(result.stdout)'),
        
        ('pyelliptic/openssl.py', 1111,
         r'result\.safe_decode\(stdout\)',
         r'safe_decode(result.stdout)'),
        
        ('bitmessageqt/networkstatus.py', 192,
         r'c\.safe_decode\(userAgent',
         r'safe_decode(c.userAgent'),
        
        ('pyelliptic/openssl.py', 1004,
         r'safe_decode\(version\) if hasattr\(version, \'decode\'\)',
         r'version if isinstance(version, str) else safe_decode(version)'),
    ]
    
    for filename, line_num, pattern, replacement in problems:
        filepath = os.path.join(src_dir, filename)
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                lines = f.readlines()
            
            if 0 < line_num <= len(lines):
                line = lines[line_num-1]
                if re.search(pattern, line):
                    new_line = re.sub(pattern, replacement, line)
                    lines[line_num-1] = new_line
                    
                    with open(filepath, 'w') as f:
                        f.writelines(lines)
                    
                    print(f"Fixed {filename}:{line_num}")
                    print(f"  Was: {line.strip()}")
                    print(f"  Now: {new_line.strip()}")
                else:
                    print(f"Pattern not found in {filename}:{line_num}")
                    print(f"  Line: {line.strip()}")

if __name__ == '__main__':
    fix_remaining()
