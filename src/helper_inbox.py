"""Helper Inbox performs inbox messages related operations"""

import sqlite3
import logging

import queues
from helper_sql import sqlExecute, sqlQuery
from dbcompat import dbstr

logger = logging.getLogger('default')


def insert(t):
    """Perform an insert into the "inbox" table"""
    logger.debug("DEBUG: Entering insert() with tuple length: %d", len(t))
    logger.debug("DEBUG: Input tuple: %s", str(t[:3]) + "..." if len(t) > 3 else str(t))
    
    u = [sqlite3.Binary(t[0]), dbstr(t[1]), dbstr(t[2]), dbstr(t[3]), 
         dbstr(t[4]), dbstr(t[5]), dbstr(t[6]), t[7], t[8], sqlite3.Binary(t[9])]
    logger.debug("DEBUG: Prepared SQL parameters: %s", str(u[:3]) + "..." if len(u) > 3 else str(u))
    
    logger.debug("DEBUG: Executing SQL insert")
    sqlExecute('''INSERT INTO inbox VALUES (?,?,?,?,?,?,?,?,?,?)''', *u)
    logger.debug("DEBUG: Insert completed successfully")
    
    # shouldn't emit changedInboxUnread and displayNewInboxMessage
    # at the same time
    # queues.UISignalQueue.put(('changedInboxUnread', None))


def trash(msgid):
    """Mark a message in the `inbox` as `trash`"""
    logger.debug("DEBUG: Entering trash() with msgid: %s", msgid)
    
    logger.debug("DEBUG: Attempting update with binary msgid")
    rowcount = sqlExecute('''UPDATE inbox SET folder='trash' WHERE msgid=?''', sqlite3.Binary(msgid))
    logger.debug("DEBUG: Update with binary affected %d rows", rowcount)
    
    if rowcount < 1:
        logger.debug("DEBUG: No rows updated, trying with text cast")
        sqlExecute('''UPDATE inbox SET folder='trash' WHERE msgid=CAST(? AS TEXT)''', msgid)
    
    logger.debug("DEBUG: Sending UI signal to remove inbox row")
    queues.UISignalQueue.put(('removeInboxRowByMsgid', msgid))
    logger.debug("DEBUG: trash() completed")


def delete(ack_data):
    """Permanent delete message from trash"""
    logger.debug("DEBUG: Entering delete() with ack_data: %s", ack_data)
    
    logger.debug("DEBUG: Attempting delete with binary ack_data")
    rowcount = sqlExecute("DELETE FROM inbox WHERE msgid = ?", sqlite3.Binary(ack_data))
    logger.debug("DEBUG: Delete with binary affected %d rows", rowcount)
    
    if rowcount < 1:
        logger.debug("DEBUG: No rows deleted, trying with text cast")
        sqlExecute("DELETE FROM inbox WHERE msgid = CAST(? AS TEXT)", ack_data)
    
    logger.debug("DEBUG: delete() completed")


def undeleteMessage(msgid):
    """Undelte the message"""
    logger.debug("DEBUG: Entering undeleteMessage() with msgid: %s", msgid)
    
    logger.debug("DEBUG: Attempting update with binary msgid")
    rowcount = sqlExecute('''UPDATE inbox SET folder='inbox' WHERE msgid=?''', sqlite3.Binary(msgid))
    logger.debug("DEBUG: Update with binary affected %d rows", rowcount)
    
    if rowcount < 1:
        logger.debug("DEBUG: No rows updated, trying with text cast")
        sqlExecute('''UPDATE inbox SET folder='inbox' WHERE msgid=CAST(? AS TEXT)''', msgid)
    
    logger.debug("DEBUG: undeleteMessage() completed")


def isMessageAlreadyInInbox(sigHash):
    """Check for previous instances of this message"""
    logger.debug("DEBUG: Entering isMessageAlreadyInInbox() with sigHash: %s", sigHash)
    
    logger.debug("DEBUG: Querying with binary sigHash")
    queryReturn = sqlQuery(
        '''SELECT COUNT(*) FROM inbox WHERE sighash=?''', sqlite3.Binary(sigHash))
    logger.debug("DEBUG: Query with binary returned %d results", len(queryReturn))
    
    if len(queryReturn) < 1:
        logger.debug("DEBUG: No results, trying with text cast")
        queryReturn = sqlQuery(
            '''SELECT COUNT(*) FROM inbox WHERE sighash=CAST(? AS TEXT)''', sigHash)
        logger.debug("DEBUG: Query with text cast returned %d results", len(queryReturn))
    
    result = queryReturn[0][0] != 0
    logger.debug("DEBUG: Message already in inbox: %s", result)
    return result
