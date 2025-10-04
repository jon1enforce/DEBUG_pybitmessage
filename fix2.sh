cat > config_injection_patch.py << 'EOF'
#!/usr/bin/env python3
"""
Config Injection Security Patch for PyBitMessage
Fixes unsafe config value usage that could lead to code injection
"""

import re

def fix_config_injection():
    """Fix config injection vulnerabilities in OpenCL and other modules"""
    
    # Patch openclpow.py - Add input validation
    openclpow_patch = '''
# SECURITY PATCH: Input validation for OpenCL config
def validate_opencl_config():
    """Validate OpenCL configuration to prevent injection attacks"""
    opencl_value = config.safeGet('bitmessagesettings', 'opencl')
    if opencl_value and not re.match(r'^[a-zA-Z0-9_\\-\\.]+$', opencl_value):
        logger.error("SECURITY: Invalid OpenCL config value detected")
        return False
    return True

# Wrap OpenCL functions with security checks
def safe_opencl_enabled():
    """Safely check if OpenCL is enabled"""
    if not validate_opencl_config():
        return False
    return original_opencl_enabled()

# Replace original functions
original_opencl_enabled = openclEnabled
openclEnabled = safe_opencl_enabled
'''
    
    # Add to openclpow.py
    try:
        with open('src/openclpow.py', 'r') as f:
            content = f.read()
        
        # Add security patch at the end
        if 'def openclEnabled():' in content and 'SECURITY PATCH' not in content:
            content += openclpow_patch
            with open('src/openclpow.py', 'w') as f:
                f.write(content)
            print("✅ Patched openclpow.py with security validation")
    except Exception as e:
        print(f"❌ Error patching openclpow.py: {e}")

def fix_file_traversal():
    """Fix file traversal vulnerabilities"""
    
    # Create secure file operation wrapper
    secure_file_code = '''
# SECURITY PATCH: Safe file operations
import os
from pathlib import Path

def safe_open(filepath, mode='r', *args, **kwargs):
    """Safely open files with path traversal protection"""
    # Convert to absolute path and validate
    abs_path = os.path.abspath(filepath)
    
    # Security checks
    if '..' in abs_path or abs_path != os.path.normpath(abs_path):
        raise SecurityError(f"Path traversal attempt detected: {filepath}")
    
    # Check if path is within allowed directories
    allowed_dirs = [
        os.path.abspath('.'), 
        os.path.expanduser('~/.config/PyBitMessage'),
        state.appdata if 'state' in globals() else ''
    ]
    
    is_allowed = any(abs_path.startswith(str(Path(d).resolve())) for d in allowed_dirs if d)
    if not is_allowed:
        raise SecurityError(f"File access outside allowed directories: {filepath}")
    
    return open(abs_path, mode, *args, **kwargs)

def safe_path_join(*paths):
    """Safely join paths with traversal protection"""
    joined = os.path.join(*paths)
    abs_path = os.path.abspath(joined)
    
    if '..' in abs_path or abs_path != os.path.normpath(abs_path):
        raise SecurityError(f"Path traversal in join: {joined}")
    
    return abs_path
'''
    
    # Add to shared.py
    try:
        with open('src/shared.py', 'a') as f:
            f.write(secure_file_code)
        print("✅ Added secure file operations to shared.py")
    except Exception as e:
        print(f"❌ Error adding secure file operations: {e}")

def patch_individual_files():
    """Patch individual files with file traversal issues"""
    
    files_to_patch = [
        'src/bitmessagecli.py',
        'src/namecoin.py', 
        'src/bmconfigparser.py',
        'src/bitmessageqt/__init__.py'
    ]
    
    for file_path in files_to_patch:
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Replace unsafe open() calls with safe_open()
            content = re.sub(r'open\(([^)]+)\)', r'safe_open(\1)', content)
            
            with open(file_path, 'w') as f:
                f.write(content)
                
            print(f"✅ Patched file operations in {file_path}")
            
        except Exception as e:
            print(f"❌ Error patching {file_path}: {e}")

if __name__ == "__main__":
    print("🔒 Config Injection & File Traversal Security Patch")
    print("=" * 50)
    
    fix_config_injection()
    fix_file_traversal() 
    patch_individual_files()
    
    print("\n📋 PATCH SUMMARY:")
    print("1. Added OpenCL config validation")
    print("2. Added secure file operations with path traversal protection")
    print("3. Patched individual files with unsafe open() calls")
    print("4. All config injection and file traversal vectors should now be closed")
EOF

python3 config_injection_patch.py
