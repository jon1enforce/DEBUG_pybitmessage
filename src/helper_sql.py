"""
SQL-related functions defined here are really pass the queries (or other SQL
commands) to :class:`.threads.sqlThread` through `sqlSubmitQueue` queue and check
or return the result got from `sqlReturnQueue`.

EMERGENCY PATCH: LOCKING REMOVED TO PREVENT DEADLOCKS
"""

import threading
import logging
import time
from six.moves import queue

logger = logging.getLogger('default')

sqlSubmitQueue = queue.Queue()
"""the queue for SQL"""
sqlReturnQueue = queue.Queue()
"""the queue for results"""
sql_lock = threading.Lock()
""" lock to prevent queueing a new request until the previous response
    is available - DISABLED IN EMERGENCY PATCH """
sql_available = False
"""set to True by `.threads.sqlThread` immediately upon start"""
sql_ready = threading.Event()
"""set by `.threads.sqlThread` when ready for processing (after
   initialization is done)"""
sql_timeout = 60
"""timeout for waiting for sql_ready in seconds"""


def sqlQuery(sql_statement, *args):
    """
    Query sqlite and return results - EMERGENCY VERSION WITHOUT LOCKING
    """
    global sql_available
    
    if not sql_available:
        # logger.debug("SQL not available in sqlQuery")
        return []
    
    try:
        # NO LOCKING - direct queue access
        sqlSubmitQueue.put(sql_statement, timeout=2)
        
        if args == ():
            sqlSubmitQueue.put('', timeout=2)
        elif isinstance(args[0], (list, tuple)):
            sqlSubmitQueue.put(args[0], timeout=2)
        else:
            sqlSubmitQueue.put(args, timeout=2)
        
        try:
            queryreturn, _ = sqlReturnQueue.get(timeout=10)
            return queryreturn
        except queue.Empty:
            # logger.warning(f"SQL query timeout: {sql_statement[:50]}...")
            return []
            
    except queue.Full:
        # logger.warning("SQL submit queue full")
        return []
    except Exception:
        return []


def sqlExecuteChunked(sql_statement, as_text, idCount, *args):
    """Execute chunked SQL statement - EMERGENCY VERSION WITHOUT LOCKING"""
    global sql_available
    
    if not sql_available:
        return 0
        
    sqlExecuteChunked.chunkSize = 999

    if idCount == 0 or idCount > len(args):
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
                sqlSubmitQueue.put(sql_statement.format(q), timeout=2)
            else:
                sqlSubmitQueue.put(
                    sql_statement.format(','.join('?' * len(chunk_slice))),
                    timeout=2
                )
            # first static args, and then iterative chunk
            sqlSubmitQueue.put(
                args[0:len(args) - idCount] + chunk_slice,
                timeout=2
            )
            try:
                ret_val = sqlReturnQueue.get(timeout=10)
                total_row_count += ret_val[1]
            except queue.Empty:
                break
        sqlSubmitQueue.put('commit', timeout=2)
    except Exception:
        pass
    
    return total_row_count


def sqlExecute(sql_statement, *args):
    """Execute SQL statement - EMERGENCY VERSION WITHOUT LOCKING"""
    global sql_available
    
    if not sql_available:
        return 0
    
    try:
        sqlSubmitQueue.put(sql_statement, timeout=2)

        if args == ():
            sqlSubmitQueue.put('', timeout=2)
        else:
            sqlSubmitQueue.put(args, timeout=2)
            
        try:
            _, rowcount = sqlReturnQueue.get(timeout=10)
        except queue.Empty:
            rowcount = 0
            
        sqlSubmitQueue.put('commit', timeout=2)
        return rowcount
    except Exception:
        return 0


def sqlExecuteScript(sql_statement):
    """Execute SQL script statement - EMERGENCY VERSION"""
    global sql_available
    
    if not sql_available:
        return

    statements = sql_statement.split(";")
    for q in statements:
        if q.strip():
            sqlExecute(q)


def sqlStoredProcedure(procName):
    """Schedule procName to be run - EMERGENCY VERSION"""
    global sql_available
    
    if not sql_available:
        return
    
    try:
        sqlSubmitQueue.put(procName, timeout=2)
        if procName == "exit":
            sqlSubmitQueue.put("terminate", timeout=2)
    except Exception:
        pass


class SqlBulkExecute(object):
    """This is used when you have to execute the same statement in a cycle."""

    def __enter__(self):
        global sql_available
        
        if not sql_available:
            raise Exception('SQL not available')
            
        # NO LOCKING
        return self

    def __exit__(self, exc_type, value, traceback):
        try:
            sqlSubmitQueue.put('commit', timeout=2)
        except Exception:
            pass

    @staticmethod
    def execute(sql_statement, *args):
        """Used for statements that do not return results."""
        global sql_available
        
        if not sql_available:
            return
            
        try:
            sqlSubmitQueue.put(sql_statement, timeout=2)

            if args == ():
                sqlSubmitQueue.put('', timeout=2)
            else:
                sqlSubmitQueue.put(args, timeout=2)
                
            try:
                sqlReturnQueue.get(timeout=10)
            except queue.Empty:
                pass
        except Exception:
            pass
