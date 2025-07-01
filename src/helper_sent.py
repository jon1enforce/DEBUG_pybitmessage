"""
Insert values into sent table
"""

import time
import uuid
import sqlite3
import logging
from addresses import decodeAddress
from bmconfigparser import config
from helper_ackPayload import genAckPayload
from helper_sql import sqlExecute, sqlQuery
from dbcompat import dbstr

logger = logging.getLogger('default')

# pylint: disable=too-many-arguments
def insert(msgid=None, toAddress='[Broadcast subscribers]', fromAddress=None, subject=None,
           message=None, status='msgqueued', ripe=None, ackdata=None, sentTime=None,
           lastActionTime=None, sleeptill=0, retryNumber=0, encoding=2, ttl=None, folder='sent'):
    """Perform an insert into the `sent` table"""
    # pylint: disable=unused-variable
    # pylint: disable-msg=too-many-locals
    logger.debug("DEBUG: Entering insert() with parameters: "
                "msgid=%s, toAddress=%s, fromAddress=%s, subject=%s, "
                "status=%s, ripe=%s, ackdata=%s, sentTime=%s, "
                "lastActionTime=%s, sleeptill=%d, retryNumber=%d, "
                "encoding=%d, ttl=%s, folder=%s",
                msgid, toAddress, fromAddress, subject, 
                status, ripe, ackdata, sentTime,
                lastActionTime, sleeptill, retryNumber,
                encoding, ttl, folder)

    valid_addr = True
    if not ripe or not ackdata:
        logger.debug("DEBUG: Missing ripe or ackdata, decoding address")
        addr = fromAddress if toAddress == '[Broadcast subscribers]' else toAddress
        logger.debug("DEBUG: Address to decode: %s", addr)
        
        new_status, addressVersionNumber, streamNumber, new_ripe = decodeAddress(addr)
        valid_addr = True if new_status == 'success' else False
        logger.debug("DEBUG: Address decode status: %s, version: %d, stream: %d, ripe: %s",
                   new_status, addressVersionNumber, streamNumber, new_ripe)
        
        if not ripe:
            logger.debug("DEBUG: Setting ripe from decoded address")
            ripe = new_ripe

        if not ackdata:
            logger.debug("DEBUG: Generating new ackdata")
            stealthLevel = config.safeGetInt(
                'bitmessagesettings', 'ackstealthlevel')
            logger.debug("DEBUG: Using stealth level: %d", stealthLevel)
            new_ackdata = genAckPayload(streamNumber, stealthLevel)
            ackdata = new_ackdata
            logger.debug("DEBUG: Generated ackdata: %s", ackdata)
    
    if valid_addr:
        msgid = msgid if msgid else uuid.uuid4().bytes
        logger.debug("DEBUG: Using msgid: %s", msgid)
        
        sentTime = sentTime if sentTime else int(time.time())
        lastActionTime = lastActionTime if lastActionTime else int(time.time())
        logger.debug("DEBUG: Set timestamps - sent: %d, lastAction: %d", 
                    sentTime, lastActionTime)

        ttl = ttl if ttl else config.getint('bitmessagesettings', 'ttl')
        logger.debug("DEBUG: Using TTL: %d", ttl)

        t = (sqlite3.Binary(msgid), dbstr(toAddress), sqlite3.Binary(ripe), 
             dbstr(fromAddress), dbstr(subject), dbstr(message), sqlite3.Binary(ackdata),
             sentTime, lastActionTime, sleeptill, dbstr(status), retryNumber, dbstr(folder),
             encoding, ttl)
        logger.debug("DEBUG: Prepared tuple for insertion: %s", t)

        logger.debug("DEBUG: Executing SQL insert")
        sqlExecute('''INSERT INTO sent VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''', *t)
        logger.debug("DEBUG: Insert completed, returning ackdata")
        return ackdata
    else:
        logger.debug("DEBUG: Invalid address, returning None")
        return None


def delete(ack_data):
    """Perform Delete query"""
    logger.debug("DEBUG: Entering delete() with ack_data: %s", ack_data)
    
    logger.debug("DEBUG: Attempting delete with binary ack_data")
    rowcount = sqlExecute("DELETE FROM sent WHERE ackdata = ?", sqlite3.Binary(ack_data))
    logger.debug("DEBUG: Delete with binary affected %d rows", rowcount)
    
    if rowcount < 1:
        logger.debug("DEBUG: No rows deleted, trying with text cast")
        sqlExecute("DELETE FROM sent WHERE ackdata = CAST(? AS TEXT)", ack_data)
        logger.debug("DEBUG: Delete with text cast executed")


def retrieve_message_details(ack_data):
    """Retrieving Message details"""
    logger.debug("DEBUG: Entering retrieve_message_details() with ack_data: %s", ack_data)
    
    logger.debug("DEBUG: Attempting query with binary ack_data")
    data = sqlQuery(
        "select toaddress, fromaddress, subject, message, received from inbox where msgid = ?", 
        sqlite3.Binary(ack_data)
    )
    logger.debug("DEBUG: Query with binary returned %d rows", len(data))
    
    if len(data) < 1:
        logger.debug("DEBUG: No results, trying with text cast")
        data = sqlQuery(
            "select toaddress, fromaddress, subject, message, received from inbox where msgid = CAST(? AS TEXT)", 
            ack_data
        )
        logger.debug("DEBUG: Query with text cast returned %d rows", len(data))
    
    logger.debug("DEBUG: Returning retrieved data: %s", data)
    return data


def trash(ackdata):
    """Mark a message in the `sent` as `trash`"""
    logger.debug("DEBUG: Entering trash() with ackdata: %s", ackdata)
    
    logger.debug("DEBUG: Attempting update with binary ackdata")
    rowcount = sqlExecute(
        '''UPDATE sent SET folder='trash' WHERE ackdata=?''', 
        sqlite3.Binary(ackdata)
    )
    logger.debug("DEBUG: Update with binary affected %d rows", rowcount)
    
    if rowcount < 1:
        logger.debug("DEBUG: No rows updated, trying with text cast")
        rowcount = sqlExecute(
            '''UPDATE sent SET folder='trash' WHERE ackdata=CAST(? AS TEXT)''', 
            ackdata
        )
        logger.debug("DEBUG: Update with text cast affected %d rows", rowcount)
    
    logger.debug("DEBUG: Returning rowcount: %d", rowcount)
    return rowcount
