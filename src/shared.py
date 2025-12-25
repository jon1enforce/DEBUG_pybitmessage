"""
Shared functions with enhanced debugging

.. deprecated:: 0.6.3
  Should be moved to different places and this file removed,
  but it needs refactoring.
"""
from __future__ import division

import sys
import logging
import hashlib
import os
import stat
import subprocess  # nosec B404
from binascii import hexlify
from six.moves.reprlib import repr

# Setup debug logging
logging.basicConfig(
    level=logging.DEBUG,
    format='DEBUG: %(asctime)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

logger.debug("Initializing shared module")

# Project imports.
import highlevelcrypto
import state
from addresses import decodeAddress, encodeVarint
from bmconfigparser import config
from debug import logger as debug_logger
from helper_sql import sqlQuery
from dbcompat import dbstr

logger.debug("Imported all required modules")

# Global dictionaries
myECCryptorObjects = {}
MyECSubscriptionCryptorObjects = {}
myAddressesByHash = {}
myAddressesByTag = {}
broadcastSendersForWhichImWatching = {}

logger.debug("Initialized global dictionaries")

def isAddressInMyAddressBook(address):
    """Check if address exists in addressbook with debug logging"""
    logger.debug("Checking if address exists in addressbook: %s", address)
    queryreturn = sqlQuery(
        '''select TRUE from addressbook where address=?''',
        dbstr(address))
    result = queryreturn != []
    logger.debug("Address %s %s in addressbook", address, "exists" if result else "does not exist")
    return result

def isAddressInMySubscriptionsList(address):
    """Check if address exists in subscriptions with debug logging"""
    logger.debug("Checking if address exists in subscriptions: %s", address)
    queryreturn = sqlQuery(
        '''select TRUE from subscriptions where address=?''',
        dbstr(address))
    result = queryreturn != []
    logger.debug("Address %s %s in subscriptions", address, "exists" if result else "does not exist")
    return result

def isAddressInMyAddressBookSubscriptionsListOrWhitelist(address):
    """Check address presence in multiple lists with debug logging"""
    logger.debug("Checking address presence in multiple lists: %s", address)
    
    if isAddressInMyAddressBook(address):
        logger.debug("Address found in addressbook")
        return True

    logger.debug("Checking whitelist for address")
    queryreturn = sqlQuery(
        '''SELECT address FROM whitelist where address=?'''
        ''' and enabled = '1' ''',
        dbstr(address))
    if queryreturn != []:
        logger.debug("Address found in whitelist")
        return True

    logger.debug("Checking subscriptions for address")
    queryreturn = sqlQuery(
        '''select address from subscriptions where address=?'''
        ''' and enabled = '1' ''',
        dbstr(address))
    result = queryreturn != []
    logger.debug("Address %s %s in enabled subscriptions", address, "exists" if result else "does not exist")
    return result

def reloadMyAddressHashes():
    """Reload address hashes with detailed debugging"""
    logger.debug("Reloading address hashes from keys.dat")
    
    # Clear existing data
    myECCryptorObjects.clear()
    myAddressesByHash.clear()
    myAddressesByTag.clear()
    logger.debug("Cleared existing address hash data")

    # Check file permissions
    keyfile = os.path.join(state.appdata, 'keys.dat')
    keyfileSecure = checkSensitiveFilePermissions(keyfile)
    hasEnabledKeys = False
    logger.debug("Keys.dat permissions secure: %s", keyfileSecure)

    # Process each address
    for addressInKeysFile in config.addresses():
        if not config.getboolean(addressInKeysFile, 'enabled'):
            logger.debug("Skipping disabled address: %s", addressInKeysFile)
            continue

        hasEnabledKeys = True
        logger.debug("Processing enabled address: %s", addressInKeysFile)

        try:
            addressVersionNumber, streamNumber, hashobj = decodeAddress(
                addressInKeysFile)[1:]
            logger.debug("Decoded address: version=%s, stream=%s", 
                        addressVersionNumber, streamNumber)
            
            if addressVersionNumber not in (2, 3, 4):
                logger.error(
                    'Cannot handle address version %s for address %s',
                    addressVersionNumber, addressInKeysFile)
                continue

            # Process private key
            privEncryptionKey = hexlify(
                highlevelcrypto.decodeWalletImportFormat(config.get(
                    addressInKeysFile, 'privencryptionkey').encode()
                ))
            logger.debug("Decoded private key for address")

            if len(privEncryptionKey) == 64:
                myECCryptorObjects[hashobj] = \
                    highlevelcrypto.makeCryptor(privEncryptionKey)
                myAddressesByHash[bytes(hashobj)] = addressInKeysFile
                tag = highlevelcrypto.double_sha512(
                    encodeVarint(addressVersionNumber)
                    + encodeVarint(streamNumber) + hashobj)[32:]
                myAddressesByTag[bytes(tag)] = addressInKeysFile
                logger.debug("Added cryptor objects for address")
        except ValueError:
            logger.error(
                'Failed to decode private key for address %s',
                addressInKeysFile)
            continue
        except Exception as e:
            logger.error(
                'Unexpected error processing address %s: %s',
                addressInKeysFile, str(e))
            continue

    # Fix permissions if needed
    if not keyfileSecure:
        logger.debug("Attempting to fix keyfile permissions")
        fixSensitiveFilePermissions(keyfile, hasEnabledKeys)
    else:
        logger.debug("Keyfile permissions are secure")

# In shared.py oder helper_generic.py
def safe_decode(value, encoding='utf-8', errors='ignore'):
    """
    Safely decode bytes to string. If it's already a string, return it.
    """
    if value is None:
        return ''
    elif isinstance(value, bytes):
        try:
            return value.decode(encoding, errors)
        except:
            # Fallback
            try:
                return value.decode('latin-1', errors)
            except:
                return str(value)[:100]
    elif isinstance(value, str):
        return value
    else:
        return str(value)
def reloadBroadcastSendersForWhichImWatching():
    """Reload broadcast senders with detailed debugging"""
    logger.debug("Reloading broadcast senders")
    
    broadcastSendersForWhichImWatching.clear()
    MyECSubscriptionCryptorObjects.clear()
    logger.debug("Cleared existing broadcast sender data")

    queryreturn = sqlQuery('SELECT address FROM subscriptions where enabled=1')
    logger.debug("Found %d enabled subscriptions", len(queryreturn))
    
    for row in queryreturn:
        if len(row) == 1:
            address = row[0]
        else:
            # Debug-Ausgabe um zu sehen, was wirklich zurückkommt
            logger.error("Unexpected row format in reloadBroadcastSendersForWhichImWatching: %s", row)
            continue  # oder handle es anders
        
        address = safe_decode(address, "utf-8", "replace")
        logger.debug("Processing subscription: %s", address)
        
        try:
            addressVersionNumber, streamNumber, hashobj = decodeAddress(address)[1:]
            logger.debug("Decoded subscription address: version=%s", addressVersionNumber)
            
            if addressVersionNumber == 2:
                broadcastSendersForWhichImWatching[hashobj] = 0
                logger.debug("Added version 2 address to broadcast senders")

            # Create cryptor objects
            if addressVersionNumber <= 3:
                privEncryptionKey = hashlib.sha512(
                    encodeVarint(addressVersionNumber)
                    + encodeVarint(streamNumber) + hashobj
                ).digest()[:32]
                MyECSubscriptionCryptorObjects[bytes(hashobj)] = \
                    highlevelcrypto.makeCryptor(hexlify(privEncryptionKey))
                logger.debug("Created cryptor for version <= 3 address")
            else:
                doubleHashOfAddressData = highlevelcrypto.double_sha512(
                    encodeVarint(addressVersionNumber)
                    + encodeVarint(streamNumber) + hashobj
                )
                tag = doubleHashOfAddressData[32:]
                privEncryptionKey = doubleHashOfAddressData[:32]
                MyECSubscriptionCryptorObjects[bytes(tag)] = \
                    highlevelcrypto.makeCryptor(hexlify(privEncryptionKey))
                logger.debug("Created cryptor for version > 3 address")
        except Exception as e:
            logger.error("Error processing subscription %s: %s", address, str(e))
            continue

def fixPotentiallyInvalidUTF8Data(text):
    """Sanitize UTF-8 data with debug logging"""
    logger.debug("Checking text for valid UTF-8 encoding")
    try:
        safe_decode(text, "utf-8")
        logger.debug("Text is valid UTF-8")
        return text
    except UnicodeDecodeError:
        logger.debug("Text contains invalid UTF-8, applying replacement")
        return 'Part of the message is corrupt. The message cannot be' \
            ' displayed the normal way.\n\n' + safe_decode(text, "utf-8", "replace")

def checkSensitiveFilePermissions(filename):
    """Check file permissions with debug logging"""
    logger.debug("Checking permissions for file: %s", filename)
    
    if sys.platform == 'win32':
        logger.debug("Windows platform - skipping permission check")
        return True
    elif sys.platform[:7] == 'freebsd' or sys.platform[:7] == 'openbsd':
        logger.debug("FreeBSD platform - checking permissions")
        present_permissions = os.stat(filename)[0]
        disallowed_permissions = stat.S_IRWXG | stat.S_IRWXO
        result = present_permissions & disallowed_permissions == 0
        logger.debug("FreeBSD permissions check result: %s", result)
        return result

    # Try multiple stat locations with fallback
    stat_paths = ['/usr/bin/stat', '/bin/stat', 'stat']
    
    for stat_path in stat_paths:
        try:
            logger.debug("Trying stat at: %s", stat_path)
            fstype = subprocess.check_output(
                [stat_path, '-f', '-c', '%T', filename],
                stderr=subprocess.STDOUT
            )  # nosec B603
            
            if b'fuseblk' in fstype:
                logger.info(
                    'Skipping permissions check for fuseblk filesystem: %s',
                    filename)
                return True
            break  # Success, exit loop
        except FileNotFoundError as e:
            if stat_path == stat_paths[-1]:  # Last option failed
                logger.error('Could not find stat command at any location: %s',
                           ', '.join(stat_paths))
                raise
            else:
                logger.debug('stat not found at %s, trying next location...', 
                           stat_path)
                continue
        except Exception as e:
            # If it's the last path, re-raise the exception
            if stat_path == stat_paths[-1]:
                logger.error('Could not determine filesystem type for %s: %s',
                           filename, str(e))
                raise
            else:
                logger.debug('Error with stat at %s: %s, trying next...',
                           stat_path, str(e))
                continue

    present_permissions = os.stat(filename)[0]
    disallowed_permissions = stat.S_IRWXG | stat.S_IRWXO
    result = present_permissions & disallowed_permissions == 0
    logger.debug("File permissions check result: %s", result)
    return result

def fixSensitiveFilePermissions(filename, hasEnabledKeys):
    """Fix file permissions with debug logging"""
    logger.debug("Attempting to fix permissions for file: %s", filename)
    
    if hasEnabledKeys:
        logger.warning(
            'Insecure permissions on keyfile with enabled keys - paranoid users'
            ' should stop using them')
    else:
        logger.warning('Insecure permissions on keyfile without enabled keys')

    try:
        present_permissions = os.stat(filename)[0]
        disallowed_permissions = stat.S_IRWXG | stat.S_IRWXO
        allowed_permissions = ((1 << 32) - 1) ^ disallowed_permissions
        new_permissions = (allowed_permissions & present_permissions)
        os.chmod(filename, new_permissions)
        logger.info('Successfully fixed keyfile permissions')
    except Exception as e:
        logger.error('Failed to fix keyfile permissions: %s', str(e))
        raise

logger.debug("shared module initialization complete")

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

# SECURITY PATCH: Safe file operations
import os
from pathlib import Path
from helper_sql import safe_decode

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

# SECURITY PATCH: Memory safety for network operations
def safe_struct_unpack(fmt, data):
    """Safely unpack struct data with bounds checking"""
    expected_size = struct.calcsize(fmt)
    if len(data) < expected_size:
        raise ValueError(f"Buffer underflow: expected {expected_size} bytes, got {len(data)}")
    return struct.unpack(fmt, data[:expected_size])

def safe_bytearray_slice(data, start, end=None):
    """Safely slice bytearray with bounds checking"""
    if start < 0 or start >= len(data):
        raise ValueError(f"Start index out of bounds: {start}")
    if end is not None and (end < 0 or end > len(data) or end < start):
        raise ValueError(f"End index out of bounds: {end}")
    return data[start:end] if end else data[start:]
