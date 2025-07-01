"""
This module is for generating ack payload
"""

import logging
from binascii import hexlify
from struct import pack

import helper_random
import highlevelcrypto
from addresses import encodeVarint

logger = logging.getLogger('default')

def genAckPayload(streamNumber=1, stealthLevel=0):
    """
    Generate and return payload obj.

    This function generates payload objects for message acknowledgements
    Several stealth levels are available depending on the privacy needs;
    a higher level means better stealth, but also higher cost (size+POW)

       - level 0: a random 32-byte sequence with a message header appended
       - level 1: a getpubkey request for a (random) dummy key hash
       - level 2: a standard message, encrypted to a random pubkey
    """
    logger.debug("DEBUG: Entering genAckPayload()")
    logger.debug("DEBUG: Parameters - streamNumber: %d, stealthLevel: %d", streamNumber, stealthLevel)
    
    if stealthLevel == 2:  # Generate privacy-enhanced payload
        logger.debug("DEBUG: Generating stealth level 2 payload")
        # Generate a dummy privkey and derive the pubkey
        random_bytes = highlevelcrypto.randomBytes(32)
        logger.debug("DEBUG: Generated random private key bytes")
        
        dummyPubKeyHex = highlevelcrypto.privToPub(hexlify(random_bytes))
        logger.debug("DEBUG: Derived public key: %s...", dummyPubKeyHex[:20])
        
        # Generate a dummy message of random length
        msg_length = helper_random.randomrandrange(234, 801)
        logger.debug("DEBUG: Generating random message of length %d", msg_length)
        dummyMessage = highlevelcrypto.randomBytes(msg_length)
        
        # Encrypt the message using standard BM encryption (ECIES)
        logger.debug("DEBUG: Encrypting dummy message")
        ackdata = highlevelcrypto.encrypt(dummyMessage, dummyPubKeyHex)
        acktype = 2  # message
        version = 1
        logger.debug("DEBUG: Created encrypted payload, length: %d", len(ackdata))

    elif stealthLevel == 1:  # Basic privacy payload (random getpubkey)
        logger.debug("DEBUG: Generating stealth level 1 payload")
        ackdata = highlevelcrypto.randomBytes(32)
        acktype = 0  # getpubkey
        version = 4
        logger.debug("DEBUG: Created random getpubkey payload")

    else:            # Minimum viable payload (non stealth)
        logger.debug("DEBUG: Generating stealth level 0 payload")
        ackdata = highlevelcrypto.randomBytes(32)
        acktype = 2  # message
        version = 1
        logger.debug("DEBUG: Created basic random payload")

    logger.debug("DEBUG: Building final ack object")
    ackobject = pack('>I', acktype) + encodeVarint(
        version) + encodeVarint(streamNumber) + ackdata
    logger.debug("DEBUG: Final ack object length: %d", len(ackobject))
    
    return ackobject
