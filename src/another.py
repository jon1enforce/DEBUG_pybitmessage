#!/usr/bin/env python3
"""
Test-Script um nach der bekannten RCE-Lücke zu suchen
"""
import ast
import sys

def check_unsafe_deserialization(filepath):
    """Prüft auf unsichere Deserialisierungs-Patterns"""
    with open(filepath, 'r') as f:
        content = f.read()
    
    issues = []
    
    # Pickle patterns
    if 'pickle.loads' in content:
        issues.append("pickle.loads gefunden - mögliche RCE-Lücke")
    
    if 'cPickle.loads' in content:
        issues.append("cPickle.loads gefunden - mögliche RCE-Lücke")
    
    # Marshal patterns  
    if 'marshal.loads' in content:
        issues.append("marshal.loads gefunden - unsicher für fremde Daten")
    
    # YAML patterns
    if 'yaml.load' in content and 'Loader' not in content:
        issues.append("yaml.load ohne SafeLoader gefunden - mögliche RCE")
    
    # eval/exec mit Netzwerkdaten
    if 'eval(' in content and ('recv' in content or 'network' in content):
        issues.append("eval() mit Netzwerkdaten - hochriskant")
    
    return issues

# Hauptprüfung
if __name__ == "__main__":
    import glob
    
    python_files = glob.glob("pybitmessage/**/*.py", recursive=True)
    
    for filepath in python_files:
        issues = check_unsafe_deserialization(filepath)
        if issues:
            print(f"\n⚠️  {filepath}:")
            for issue in issues:
                print(f"   - {issue}")
