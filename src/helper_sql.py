"""
SQL-related functions defined here are really pass the queries (or other SQL
commands) to :class:`.threads.sqlThread` through `sqlSubmitQueue` queue and check
or return the result got from `sqlReturnQueue`.

This is done that way because :mod:`sqlite3` is so thread-unsafe that they
won't even let you call it from different threads using your own locks.
SQLite objects can only be used from one thread.

.. note:: This actually only applies for certain deployments, and/or
   really old version of sqlite. I haven't actually seen it anywhere.
   Current versions do have support for threading and multiprocessing.
   I don't see an urgent reason to refactor this, but it should be noted
   in the comment that the problem is mostly not valid. Sadly, last time
   I checked, there is no reliable way to check whether the library is
   or isn't thread-safe.
"""

import threading
import logging
from six.moves import queue

logger = logging.getLogger('default')

sqlSubmitQueue = queue.Queue()
"""the queue for SQL"""
sqlReturnQueue = queue.Queue()
"""the queue for results"""
sql_lock = threading.Lock()
""" lock to prevent queueing a new request until the previous response
    is available """
sql_available = False
"""set to True by `.threads.sqlThread` immediately upon start"""
sql_ready = threading.Event()
"""set by `.threads.sqlThread` when ready for processing (after
   initialization is done)"""
sql_timeout = 60
"""timeout for waiting for sql_ready in seconds"""


def sqlQuery(sql_statement, *args):
    """
    Query sqlite and return results

    :param str sql_statement: SQL statement string
    :param list args: SQL query parameters
    :rtype: list
    """
    assert sql_available
    if not sql_lock.acquire(timeout=30):  # Added timeout
        logger.error('Could not acquire SQL lock after 30 seconds')
        return []  # Return empty list instead of hanging
    
    try:
        sqlSubmitQueue.put(sql_statement, timeout=10)  # Added timeout

        if args == ():
            sqlSubmitQueue.put('', timeout=10)
        elif isinstance(args[0], (list, tuple)):
            sqlSubmitQueue.put(args[0], timeout=10)
        else:
            sqlSubmitQueue.put(args, timeout=10)
        
        # Get result with timeout
        try:
            queryreturn, _ = sqlReturnQueue.get(timeout=30)
        except queue.Empty:
            logger.error('SQL query timed out after 30 seconds')
            return []
            
        return queryreturn
    except queue.Full:
        logger.error('SQL submit queue is full')
        return []
    finally:
        sql_lock.release()


def sqlExecuteChunked(sql_statement, as_text, idCount, *args):
    """Execute chunked SQL statement to avoid argument limit"""
    # SQLITE_MAX_VARIABLE_NUMBER,
    # unfortunately getting/setting isn't exposed to python
    assert sql_available
    sqlExecuteChunked.chunkSize = 999

    if idCount == 0 or idCount > len(args):
        return 0

    if not sql_lock.acquire(timeout=30):  # Added timeout
        logger.error('Could not acquire SQL lock for chunked execute')
        return 0

    total_row_count = 0
    try:
        for i in range(
                len(args) - idCount, len(args),
                sqlExecuteChunked.chunkSize - (len(args) - idCount)
        ):
            chunk_slice = args[
                i:i + sqlExecuteChunked.chunkSize - (len(args) - idCount)
            ]
            if as_text:
                q = ""
                n = len(chunk_slice)
                for i in range(n):
                    q += "CAST(? AS TEXT)"
                    if i != n - 1:
                        q += ","
                sqlSubmitQueue.put(sql_statement.format(q), timeout=10)
            else:
                sqlSubmitQueue.put(
                    sql_statement.format(','.join('?' * len(chunk_slice))),
                    timeout=10
                )
            # first static args, and then iterative chunk
            sqlSubmitQueue.put(
                args[0:len(args) - idCount] + chunk_slice,
                timeout=10
            )
            try:
                ret_val = sqlReturnQueue.get(timeout=30)
                total_row_count += ret_val[1]
            except queue.Empty:
                logger.error('SQL chunked execute timed out')
                break
        sqlSubmitQueue.put('commit', timeout=10)
    except queue.Full:
        logger.error('SQL submit queue is full during chunked execute')
    finally:
        sql_lock.release()
    return total_row_count


def sqlExecute(sql_statement, *args):
    """Execute SQL statement (optionally with arguments)"""
    assert sql_available
    if not sql_lock.acquire(timeout=30):  # Added timeout
        logger.error('Could not acquire SQL lock for execute')
        return 0
    
    try:
        sqlSubmitQueue.put(sql_statement, timeout=10)

        if args == ():
            sqlSubmitQueue.put('', timeout=10)
        else:
            sqlSubmitQueue.put(args, timeout=10)
            
        try:
            _, rowcount = sqlReturnQueue.get(timeout=30)
        except queue.Empty:
            logger.error('SQL execute timed out after 30 seconds')
            rowcount = 0
            
        sqlSubmitQueue.put('commit', timeout=10)
        return rowcount
    except queue.Full:
        logger.error('SQL submit queue is full')
        return 0
    finally:
        sql_lock.release()


def sqlExecuteScript(sql_statement):
    """Execute SQL script statement"""

    statements = sql_statement.split(";")
    with SqlBulkExecute() as sql:
        for q in statements:
            sql.execute("{}".format(q))


def sqlStoredProcedure(procName):
    """Schedule procName to be run"""
    assert sql_available
    if not sql_lock.acquire(timeout=30):  # Added timeout
        logger.error('Could not acquire SQL lock for stored procedure')
        return
    
    try:
        sqlSubmitQueue.put(procName, timeout=10)
        if procName == "exit":
            sqlSubmitQueue.put("terminate", timeout=10)
    except queue.Full:
        logger.error('SQL submit queue is full for stored procedure')
    finally:
        sql_lock.release()


class SqlBulkExecute(object):
    """This is used when you have to execute the same statement in a cycle."""

    def __enter__(self):
        if not sql_lock.acquire(timeout=30):  # Added timeout
            logger.error('Could not acquire SQL lock for bulk execute')
            raise Exception('Could not acquire SQL lock')
        return self

    def __exit__(self, exc_type, value, traceback):
        try:
            sqlSubmitQueue.put('commit', timeout=10)
        except queue.Full:
            logger.error('Could not commit bulk transaction')
        finally:
            sql_lock.release()

    @staticmethod
    def execute(sql_statement, *args):
        """Used for statements that do not return results."""
        assert sql_available
        try:
            sqlSubmitQueue.put(sql_statement, timeout=10)

            if args == ():
                sqlSubmitQueue.put('', timeout=10)
            else:
                sqlSubmitQueue.put(args, timeout=10)
                
            try:
                sqlReturnQueue.get(timeout=30)
            except queue.Empty:
                logger.error('SQL bulk execute timed out')
        except queue.Full:
            logger.error('SQL submit queue is full during bulk execute')
