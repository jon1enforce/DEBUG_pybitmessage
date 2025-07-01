"""
Calculates bitcoin and testnet address from pubkey
"""

import hashlib
import logging

from debug import logger
from pyelliptic import arithmetic

logger = logging.getLogger('default')

def calculateBitcoinAddressFromPubkey(pubkey):
    """Calculate bitcoin address from given pubkey (65 bytes long hex string)"""
    logger.debug("DEBUG: Entering calculateBitcoinAddressFromPubkey()")
    logger.debug("DEBUG: Input pubkey length: %d", len(pubkey))
    
    if len(pubkey) != 65:
        logger.error('DEBUG: Invalid pubkey length: %i bytes (expected 65)', len(pubkey))
        return "error"

    logger.debug("DEBUG: Calculating SHA-256 hash of pubkey")
    sha = hashlib.new('sha256')
    sha.update(pubkey)
    sha_digest = sha.digest()
    logger.debug("DEBUG: SHA-256 digest: %s", sha_digest.hex())

    logger.debug("DEBUG: Calculating RIPEMD-160 hash of SHA-256 digest")
    ripe = hashlib.new('ripemd160')
    ripe.update(sha_digest)
    ripe_digest = ripe.digest()
    logger.debug("DEBUG: RIPEMD-160 digest: %s", ripe_digest.hex())

    ripeWithProdnetPrefix = b'\x00' + ripe_digest
    logger.debug("DEBUG: Added production network prefix: %s", ripeWithProdnetPrefix.hex())

    logger.debug("DEBUG: Calculating checksum (double SHA-256)")
    checksum = hashlib.sha256(hashlib.sha256(
        ripeWithProdnetPrefix).digest()).digest()[:4]
    logger.debug("DEBUG: Checksum: %s", checksum.hex())

    binaryBitcoinAddress = ripeWithProdnetPrefix + checksum
    logger.debug("DEBUG: Binary Bitcoin address: %s", binaryBitcoinAddress.hex())

    logger.debug("DEBUG: Counting leading zero bytes")
    numberOfZeroBytesOnBinaryBitcoinAddress = 0
    while binaryBitcoinAddress[0] == 0:
        numberOfZeroBytesOnBinaryBitcoinAddress += 1
        binaryBitcoinAddress = binaryBitcoinAddress[1:]
    logger.debug("DEBUG: Found %d leading zero bytes", numberOfZeroBytesOnBinaryBitcoinAddress)

    logger.debug("DEBUG: Converting to base58")
    base58encoded = arithmetic.changebase(binaryBitcoinAddress, 256, 58)
    logger.debug("DEBUG: Base58 encoded: %s", base58encoded)

    result = b"1" * numberOfZeroBytesOnBinaryBitcoinAddress + base58encoded
    logger.debug("DEBUG: Final Bitcoin address: %s", result)
    logger.debug("DEBUG: Exiting calculateBitcoinAddressFromPubkey()")
    return result


def calculateTestnetAddressFromPubkey(pubkey):
    """This function expects that pubkey begin with the testnet prefix"""
    logger.debug("DEBUG: Entering calculateTestnetAddressFromPubkey()")
    logger.debug("DEBUG: Input pubkey length: %d", len(pubkey))
    
    if len(pubkey) != 65:
        logger.error('DEBUG: Invalid pubkey length: %i bytes (expected 65)', len(pubkey))
        return "error"

    logger.debug("DEBUG: Calculating SHA-256 hash of pubkey")
    sha = hashlib.new('sha256')
    sha.update(pubkey)
    sha_digest = sha.digest()
    logger.debug("DEBUG: SHA-256 digest: %s", sha_digest.hex())

    logger.debug("DEBUG: Calculating RIPEMD-160 hash of SHA-256 digest")
    ripe = hashlib.new('ripemd160')
    ripe.update(sha_digest)
    ripe_digest = ripe.digest()
    logger.debug("DEBUG: RIPEMD-160 digest: %s", ripe_digest.hex())

    ripeWithProdnetPrefix = b'\x6F' + ripe_digest
    logger.debug("DEBUG: Added testnet prefix: %s", ripeWithProdnetPrefix.hex())

    logger.debug("DEBUG: Calculating checksum (double SHA-256)")
    checksum = hashlib.sha256(hashlib.sha256(
        ripeWithProdnetPrefix).digest()).digest()[:4]
    logger.debug("DEBUG: Checksum: %s", checksum.hex())

    binaryBitcoinAddress = ripeWithProdnetPrefix + checksum
    logger.debug("DEBUG: Binary testnet address: %s", binaryBitcoinAddress.hex())

    logger.debug("DEBUG: Counting leading zero bytes")
    numberOfZeroBytesOnBinaryBitcoinAddress = 0
    while binaryBitcoinAddress[0] == 0:
        numberOfZeroBytesOnBinaryBitcoinAddress += 1
        binaryBitcoinAddress = binaryBitcoinAddress[1:]
    logger.debug("DEBUG: Found %d leading zero bytes", numberOfZeroBytesOnBinaryBitcoinAddress)

    logger.debug("DEBUG: Converting to base58")
    base58encoded = arithmetic.changebase(binaryBitcoinAddress, 256, 58)
    logger.debug("DEBUG: Base58 encoded: %s", base58encoded)

    result = b"1" * numberOfZeroBytesOnBinaryBitcoinAddress + base58encoded
    logger.debug("DEBUG: Final testnet address: %s", result)
    logger.debug("DEBUG: Exiting calculateTestnetAddressFromPubkey()")
    return result
