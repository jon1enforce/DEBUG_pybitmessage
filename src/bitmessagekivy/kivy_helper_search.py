"""
Sql queries for bitmessagekivy
"""
import logging
from pybitmessage.helper_sql import sqlQuery
from dbcompat import dbstr

logger = logging.getLogger('default')

def search_sql(
        xAddress="toaddress", account=None, folder="inbox", where=None,
        what=None, unreadOnly=False, start_indx=0, end_indx=20):
    # pylint: disable=too-many-arguments, too-many-branches
    """Method helping for searching mails"""
    logger.debug("DEBUG: Starting search_sql with parameters: "
               "xAddress=%s, account=%s, folder=%s, where=%s, "
               "what=%s, unreadOnly=%s, start_indx=%s, end_indx=%s",
               xAddress, account, folder, where, what, unreadOnly, start_indx, end_indx)

    # Process 'what' parameter
    if what is not None and what != "":
        what = "%" + what + "%"
        logger.debug("DEBUG: Processed search term: %s", what)
    else:
        what = None
        logger.debug("DEBUG: No search term provided")

    # Determine base SQL statement based on folder
    if folder in ("sent", "draft"):
        sqlStatementBase = (
            '''SELECT toaddress, fromaddress, subject, message, status,'''
            ''' ackdata, senttime FROM sent '''
        )
        logger.debug("DEBUG: Using sent/draft table query")
    elif folder == "addressbook":
        sqlStatementBase = '''SELECT label, address From addressbook '''
        logger.debug("DEBUG: Using addressbook table query")
    else:
        sqlStatementBase = (
            '''SELECT folder, msgid, toaddress, message, fromaddress,'''
            ''' subject, received, read FROM inbox '''
        )
        logger.debug("DEBUG: Using inbox table query")

    sqlStatementParts = []
    sqlArguments = []
    logger.debug("DEBUG: Initialized SQL components")

    # Handle account filtering
    if account is not None:
        if xAddress == 'both':
            sqlStatementParts.append("(fromaddress = ? OR toaddress = ?)")
            sqlArguments.append(dbstr(account))
            sqlArguments.append(dbstr(account))
            logger.debug("DEBUG: Added account filter (both addresses) for: %s", account)
        else:
            sqlStatementParts.append(xAddress + " = ? ")
            sqlArguments.append(dbstr(account))
            logger.debug("DEBUG: Added account filter (%s) for: %s", xAddress, account)

    # Handle folder filtering
    if folder != "addressbook":
        if folder is not None:
            if folder == "new":
                folder = "inbox"
                unreadOnly = True
                logger.debug("DEBUG: Converted 'new' folder to 'inbox' with unreadOnly=True")
            sqlStatementParts.append("folder = ? ")
            sqlArguments.append(dbstr(folder))
            logger.debug("DEBUG: Added folder filter: %s", folder)
        else:
            sqlStatementParts.append("folder != ?")
            sqlArguments.append(dbstr("trash"))
            logger.debug("DEBUG: Excluded trash folder")

    # Handle search term filtering
    if what is not None:
        filter_col = ""
        for colmns in where:
            if len(where) > 1:
                if where[0] == colmns:
                    filter_col = "(%s LIKE ?" % (colmns)
                else:
                    filter_col += " or %s LIKE ? )" % (colmns)
            else:
                filter_col = "%s LIKE ?" % (colmns)
            sqlArguments.append(dbstr(what))
            logger.debug("DEBUG: Added search filter for column: %s", colmns)
        sqlStatementParts.append(filter_col)

    # Handle unread only filter
    if unreadOnly:
        sqlStatementParts.append("read = 0")
        logger.debug("DEBUG: Added unread only filter")

    # Combine all SQL parts
    if sqlStatementParts:
        sqlStatementBase += "WHERE " + " AND ".join(sqlStatementParts)
        logger.debug("DEBUG: Combined WHERE clause: %s", " AND ".join(sqlStatementParts))

    # Add ordering and limits
    if folder in ("sent", "draft"):
        sqlStatementBase += \
            "ORDER BY senttime DESC limit {0}, {1}".format(
                start_indx, end_indx)
        logger.debug("DEBUG: Added senttime ordering and limit %s-%s", start_indx, end_indx)
    elif folder == "inbox":
        sqlStatementBase += \
            "ORDER BY received DESC limit {0}, {1}".format(
                start_indx, end_indx)
        logger.debug("DEBUG: Added received ordering and limit %s-%s", start_indx, end_indx)

    logger.debug("DEBUG: Final SQL query: %s", sqlStatementBase)
    logger.debug("DEBUG: SQL arguments: %s", sqlArguments)

    try:
        result = sqlQuery(sqlStatementBase, sqlArguments)
        logger.debug("DEBUG: Query executed successfully, returned %s rows", len(result))
        return result
    except Exception as e:
        logger.error("DEBUG: Error executing SQL query: %s", str(e))
        raise
