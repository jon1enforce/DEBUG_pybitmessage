"""
Insert value into addressbook
"""

import logging
from bmconfigparser import config
from helper_sql import sqlExecute
from dbcompat import dbstr

logger = logging.getLogger('default')

def insert(address, label):
    """perform insert into addressbook"""
    logger.debug("DEBUG: Entering addressbook.insert()")
    logger.debug("DEBUG: Parameters - address: %s, label: %s", address, label)
    
    if address not in config.addresses():
        logger.debug("DEBUG: Address not in config, attempting insert")
        result = sqlExecute('''INSERT INTO addressbook VALUES (?,?)''', dbstr(label), dbstr(address)) == 1
        logger.debug("DEBUG: Insert operation %s", "successful" if result else "failed")
        return result
    
    logger.debug("DEBUG: Address already exists in config, skipping insert")
    return False
