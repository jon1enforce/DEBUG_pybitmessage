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
    logger.debug("DEBUG: Entering sqlQuery() with statement: %s, args: %s", 
                sql_statement, args)
    assert sql_available
    logger.debug("DEBUG: SQL is available, acquiring lock")
    
    sql_lock.acquire()
    logger.debug("DEBUG: Lock acquired, putting statement in submit queue")
    sqlSubmitQueue.put(sql_statement)

    if args == ():
        logger.debug("DEBUG: No args provided, putting empty string")
        sqlSubmitQueue.put('')
    elif isinstance(args[0], (list, tuple)):
        logger.debug("DEBUG: Args is list/tuple, putting as is")
        sqlSubmitQueue.put(args[0])
    else:
        logger.debug("DEBUG: Putting args directly")
        sqlSubmitQueue.put(args)
        
    logger.debug("DEBUG: Waiting for return from sqlReturnQueue")
    queryreturn, _ = sqlReturnQueue.get()
    logger.debug("DEBUG: Got return value, releasing lock")
    sql_lock.release()

    logger.debug("DEBUG: Returning query result: %s", queryreturn)
    return queryreturn


def sqlExecuteChunked(sql_statement, as_text, idCount, *args):
    """Execute chunked SQL statement to avoid argument limit"""
    logger.debug("DEBUG: Entering sqlExecuteChunked() with statement: %s, "
                "as_text: %s, idCount: %d, args: %s",
                sql_statement, as_text, idCount, args)
    
    # SQLITE_MAX_VARIABLE_NUMBER,
    # unfortunately getting/setting isn't exposed to python
    assert sql_available
    logger.debug("DEBUG: SQL is available")
    
    sqlExecuteChunked.chunkSize = 999
    logger.debug("DEBUG: Chunk size set to %d", sqlExecuteChunked.chunkSize)

    if idCount == 0 or idCount > len(args):
        logger.debug("DEBUG: idCount invalid (%d), returning 0", idCount)
        return 0

    total_row_count = 0
    with sql_lock:
        logger.debug("DEBUG: Lock acquired for chunked execution")
        for i in range(
                len(args) - idCount, len(args),
                sqlExecuteChunked.chunkSize - (len(args) - idCount)
        ):
            chunk_slice = args[
                i:i + sqlExecuteChunked.chunkSize - (len(args) - idCount)
            ]
            logger.debug("DEBUG: Processing chunk slice: %s", chunk_slice)
            
            if as_text:
                q = ""
                n = len(chunk_slice)
                for i in range(n):
                    q += "CAST(? AS TEXT)"
                    if i != n - 1:
                        q += ","
                logger.debug("DEBUG: Formatting as text: %s", q)
                sqlSubmitQueue.put(sql_statement.format(q))
            else:
                formatted = ','.join('?' * len(chunk_slice))
                logger.debug("DEBUG: Formatting with placeholders: %s", formatted)
                sqlSubmitQueue.put(sql_statement.format(formatted))
                
            # first static args, and then iterative chunk
            combined_args = args[0:len(args) - idCount] + chunk_slice
            logger.debug("DEBUG: Putting combined args: %s", combined_args)
            sqlSubmitQueue.put(combined_args)
            
            ret_val = sqlReturnQueue.get()
            logger.debug("DEBUG: Got return value: %s", ret_val)
            total_row_count += ret_val[1]
            
        logger.debug("DEBUG: Putting commit to submit queue")
        sqlSubmitQueue.put('commit')
        
    logger.debug("DEBUG: Returning total row count: %d", total_row_count)
    return total_row_count


def sqlExecute(sql_statement, *args):
    """Execute SQL statement (optionally with arguments)"""
    logger.debug("DEBUG: Entering sqlExecute() with statement: %s, args: %s", 
                sql_statement, args)
    
    assert sql_available
    logger.debug("DEBUG: SQL is available, acquiring lock")
    
    sql_lock.acquire()
    logger.debug("DEBUG: Lock acquired, putting statement in submit queue")
    sqlSubmitQueue.put(sql_statement)

    if args == ():
        logger.debug("DEBUG: No args provided, putting empty string")
        sqlSubmitQueue.put('')
    else:
        logger.debug("DEBUG: Putting args in submit queue")
        sqlSubmitQueue.put(args)
        
    logger.debug("DEBUG: Waiting for return from sqlReturnQueue")
    _, rowcount = sqlReturnQueue.get()
    logger.debug("DEBUG: Got rowcount: %d, putting commit", rowcount)
    sqlSubmitQueue.put('commit')
    logger.debug("DEBUG: Releasing lock")
    sql_lock.release()
    
    logger.debug("DEBUG: Returning rowcount: %d", rowcount)
    return rowcount


def sqlExecuteScript(sql_statement):
    """Execute SQL script statement"""
    logger.debug("DEBUG: Entering sqlExecuteScript() with statement: %s", 
                sql_statement)
    
    statements = sql_statement.split(";")
    logger.debug("DEBUG: Split into %d statements", len(statements))
    
    with SqlBulkExecute() as sql:
        for i, q in enumerate(statements):
            logger.debug("DEBUG: Executing statement %d: %s", i, q)
            sql.execute("{}".format(q))
    
    logger.debug("DEBUG: Exiting sqlExecuteScript()")


def sqlStoredProcedure(procName):
    """Schedule procName to be run"""
    logger.debug("DEBUG: Entering sqlStoredProcedure() with procName: %s", 
                procName)
    
    assert sql_available
    logger.debug("DEBUG: SQL is available, acquiring lock")
    
    sql_lock.acquire()
    logger.debug("DEBUG: Lock acquired, putting procName in submit queue")
    sqlSubmitQueue.put(procName)
    
    if procName == "exit":
        logger.debug("DEBUG: Exit procedure detected")
        sqlSubmitQueue.task_done()
        sqlSubmitQueue.put("terminate")
        
    logger.debug("DEBUG: Releasing lock")
    sql_lock.release()
    logger.debug("DEBUG: Exiting sqlStoredProcedure()")


class SqlBulkExecute(object):
    """This is used when you have to execute the same statement in a cycle."""

    def __enter__(self):
        logger.debug("DEBUG: SqlBulkExecute.__enter__()")
        sql_lock.acquire()
        logger.debug("DEBUG: Lock acquired in __enter__")
        return self

    def __exit__(self, exc_type, value, traceback):
        logger.debug("DEBUG: SqlBulkExecute.__exit__()")
        logger.debug("DEBUG: Putting commit in submit queue")
        sqlSubmitQueue.put('commit')
        logger.debug("DEBUG: Releasing lock in __exit__")
        sql_lock.release()

    @staticmethod
    def execute(sql_statement, *args):
        """Used for statements that do not return results."""
        logger.debug("DEBUG: SqlBulkExecute.execute() with statement: %s, args: %s",
                    sql_statement, args)
        
        assert sql_available
        logger.debug("DEBUG: SQL is available, putting statement in submit queue")
        sqlSubmitQueue.put(sql_statement)

        if args == ():
            logger.debug("DEBUG: No args provided, putting empty string")
            sqlSubmitQueue.put('')
        else:
            logger.debug("DEBUG: Putting args in submit queue")
            sqlSubmitQueue.put(args)
            
        logger.debug("DEBUG: Waiting for return from sqlReturnQueue")
        sqlReturnQueue.get()
        logger.debug("DEBUG: Got return from sqlReturnQueue")
