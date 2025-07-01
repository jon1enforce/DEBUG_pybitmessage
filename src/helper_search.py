"""
Additional SQL helper for searching messages.
Used by :mod:`.bitmessageqt`.
"""

import logging
from helper_sql import sqlQuery
from tr import _translate
from dbcompat import dbstr

logger = logging.getLogger('default')

def search_sql(
    xAddress='toaddress', account=None, folder='inbox', where=None,
    what=None, unreadOnly=False
):
    """
    Search for messages from given account and folder having search term
    in one of it's fields.

    :param str xAddress: address field checked
      ('fromaddress', 'toaddress' or 'both')
    :param account: the account which is checked
    :type account: :class:`.bitmessageqt.account.BMAccount`
      instance
    :param str folder: the folder which is checked
    :param str where: message field which is checked ('toaddress',
      'fromaddress', 'subject' or 'message'), by default check any field
    :param str what: the search term
    :param bool unreadOnly: if True, search only for unread messages
    :return: all messages where <where> field contains <what>
    :rtype: list[list]
    """
    # pylint: disable=too-many-arguments, too-many-branches
    logger.debug("DEBUG: Entering search_sql() with parameters: "
                "xAddress=%s, account=%s, folder=%s, where=%s, "
                "what=%s, unreadOnly=%s",
                xAddress, account, folder, where, what, unreadOnly)

    if what:
        logger.debug("DEBUG: Processing search term: %s", what)
        what = '%' + what + '%'
        if where == _translate("MainWindow", "To"):
            where = 'toaddress'
            logger.debug("DEBUG: Searching in 'toaddress' field")
        elif where == _translate("MainWindow", "From"):
            where = 'fromaddress'
            logger.debug("DEBUG: Searching in 'fromaddress' field")
        elif where == _translate("MainWindow", "Subject"):
            where = 'subject'
            logger.debug("DEBUG: Searching in 'subject' field")
        elif where == _translate("MainWindow", "Message"):
            where = 'message'
            logger.debug("DEBUG: Searching in 'message' field")
        else:
            where = 'toaddress || fromaddress || subject || message'
            logger.debug("DEBUG: Searching in all fields")

    sqlStatementBase = 'SELECT toaddress, fromaddress, subject, ' + (
        'status, ackdata, lastactiontime FROM sent ' if folder == 'sent'
        else 'folder, msgid, received, read FROM inbox '
    )
    logger.debug("DEBUG: Base SQL statement: %s", sqlStatementBase)

    sqlStatementParts = []
    sqlArguments = []
    
    if account is not None:
        logger.debug("DEBUG: Account filter active for: %s", account)
        if xAddress == 'both':
            logger.debug("DEBUG: Checking both address fields")
            sqlStatementParts.append('(fromaddress = ? OR toaddress = ?)')
            sqlArguments.append(dbstr(account))
            sqlArguments.append(dbstr(account))
        else:
            logger.debug("DEBUG: Checking %s field", xAddress)
            sqlStatementParts.append(xAddress + ' = ? ')
            sqlArguments.append(dbstr(account))
    
    if folder is not None:
        if folder == 'new':
            logger.debug("DEBUG: 'new' folder converted to 'inbox' with unreadOnly")
            folder = 'inbox'
            unreadOnly = True
        sqlStatementParts.append('folder = ? ')
        sqlArguments.append(dbstr(folder))
        logger.debug("DEBUG: Added folder filter: %s", folder)
    else:
        logger.debug("DEBUG: Excluding trash folder")
        sqlStatementParts.append('folder != ?')
        sqlArguments.append(dbstr('trash'))
    
    if what:
        logger.debug("DEBUG: Adding search term filter for: %s", what)
        sqlStatementParts.append('%s LIKE ?' % (where))
        sqlArguments.append(dbstr(what))
    
    if unreadOnly:
        logger.debug("DEBUG: Filtering unread messages only")
        sqlStatementParts.append('read = 0')
    
    if sqlStatementParts:
        sqlStatementBase += 'WHERE ' + ' AND '.join(sqlStatementParts)
        logger.debug("DEBUG: Final WHERE clause: %s", ' AND '.join(sqlStatementParts))
    
    if folder == 'sent':
        sqlStatementBase += ' ORDER BY lastactiontime'
        logger.debug("DEBUG: Added ORDER BY for sent folder")
    
    logger.debug("DEBUG: Final SQL query: %s", sqlStatementBase)
    logger.debug("DEBUG: SQL arguments: %s", sqlArguments)
    
    result = sqlQuery(sqlStatementBase, sqlArguments)
    logger.debug("DEBUG: Query returned %d results", len(result))
    return result


def check_match(
        toAddress, fromAddress, subject, message, where=None, what=None):
    """
    Check if a single message matches a filter (used when new messages
    are added to messagelists)
    """
    # pylint: disable=too-many-arguments
    logger.debug("DEBUG: Entering check_match() with parameters: "
                "toAddress=%s, fromAddress=%s, subject=%s, "
                "where=%s, what=%s",
                toAddress, fromAddress, subject, where, what)

    if not what:
        logger.debug("DEBUG: No search term, returning True")
        return True

    search_term = what.lower()
    logger.debug("DEBUG: Search term (lowercase): %s", search_term)

    if where in (
        _translate("MainWindow", "To"), _translate("MainWindow", "All")
    ):
        logger.debug("DEBUG: Checking 'To' address")
        if search_term not in toAddress.lower():
            logger.debug("DEBUG: No match in 'To' address")
            return False
    elif where in (
        _translate("MainWindow", "From"), _translate("MainWindow", "All")
    ):
        logger.debug("DEBUG: Checking 'From' address")
        if search_term not in fromAddress.lower():
            logger.debug("DEBUG: No match in 'From' address")
            return False
    elif where in (
        _translate("MainWindow", "Subject"),
        _translate("MainWindow", "All")
    ):
        logger.debug("DEBUG: Checking subject")
        if search_term not in subject.lower():
            logger.debug("DEBUG: No match in subject")
            return False
    elif where in (
        _translate("MainWindow", "Message"),
        _translate("MainWindow", "All")
    ):
        logger.debug("DEBUG: Checking message body")
        if search_term not in message.lower():
            logger.debug("DEBUG: No match in message body")
            return False
    
    logger.debug("DEBUG: Search term found, returning True")
    return True
