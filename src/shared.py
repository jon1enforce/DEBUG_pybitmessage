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

def reloadBroadcastSendersForWhichImWatching():
    """Reload broadcast senders with detailed debugging"""
    logger.debug("Reloading broadcast senders")
    
    broadcastSendersForWhichImWatching.clear()
    MyECSubscriptionCryptorObjects.clear()
    logger.debug("Cleared existing broadcast sender data")

    queryreturn = sqlQuery('SELECT address FROM subscriptions where enabled=1')
    logger.debug("Found %d enabled subscriptions", len(queryreturn))
    
    for row in queryreturn:
        address, = row
        address = address.decode("utf-8", "replace")
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
        text.decode('utf-8')
        logger.debug("Text is valid UTF-8")
        return text
    except UnicodeDecodeError:
        logger.debug("Text contains invalid UTF-8, applying replacement")
        return 'Part of the message is corrupt. The message cannot be' \
            ' displayed the normal way.\n\n' + text.decode("utf-8", "replace")

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

    try:
        fstype = subprocess.check_output(
            ['/usr/bin/stat', '-f', '-c', '%T', filename],
            stderr=subprocess.STDOUT
        )  # nosec B603
        if b'fuseblk' in fstype:
            logger.info(
                'Skipping permissions check for fuseblk filesystem: %s',
                filename)
            return True
    except Exception as e:
        logger.error('Could not determine filesystem type for %s: %s',
                   filename, str(e))

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
