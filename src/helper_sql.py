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
import time
import logging
from six.moves import queue

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

# Shutdown detection
try:
    import state
    HAS_STATE = True
except ImportError:
    HAS_STATE = False

def _is_shutting_down():
    """Check if system is shutting down"""
    try:
        if HAS_STATE and hasattr(state, 'shutdown'):
            return state.shutdown > 0
    except Exception:
        pass
    return False

def sqlQuery(sql_statement, *args):
    """
    Query sqlite and return results

    :param str sql_statement: SQL statement string
    :param list args: SQL query parameters
    :rtype: list
    """
    if not sql_available:
        return []
    
    # During shutdown, return empty
    if _is_shutting_down():
        return []
    
    try:
        if not sql_lock.acquire(timeout=2.0):  # 2 second timeout
            logging.debug(f"SQL lock timeout for query: {sql_statement[:50]}...")
            return []
        
        try:
            sqlSubmitQueue.put(sql_statement)

            if args == ():
                sqlSubmitQueue.put('')
            elif isinstance(args[0], (list, tuple)):
                sqlSubmitQueue.put(args[0])
            else:
                sqlSubmitQueue.put(args)
            
            # Timeout for response
            try:
                queryreturn, _ = sqlReturnQueue.get(timeout=10.0)
                return queryreturn
            except queue.Empty:
                logging.debug(f"SQL query timeout: {sql_statement[:50]}...")
                return []
        finally:
            sql_lock.release()
            
    except Exception as e:
        logging.debug(f"SQL query error: {e}")
        return []


def sqlExecuteChunked(sql_statement, as_text, idCount, *args):
    """Execute chunked SQL statement to avoid argument limit"""
    if not sql_available or _is_shutting_down():
        return 0
    
    # SQLITE_MAX_VARIABLE_NUMBER
    chunkSize = 999

    if idCount == 0 or idCount > len(args):
        return 0

    total_row_count = 0
    
    try:
        if not sql_lock.acquire(timeout=2.0):
            logging.debug("SQL lock timeout for executeChunked")
            return 0
        
        try:
            for i in range(
                    len(args) - idCount, len(args),
                    chunkSize - (len(args) - idCount)
            ):
                chunk_slice = args[
                    i:i + chunkSize - (len(args) - idCount)
                ]
                if as_text:
                    q = ""
                    n = len(chunk_slice)
                    for i in range(n):
                        q += "CAST(? AS TEXT)"
                        if i != n - 1:
                            q += ","
                    sqlSubmitQueue.put(sql_statement.format(q))
                else:
                    sqlSubmitQueue.put(
                        sql_statement.format(','.join('?' * len(chunk_slice)))
                    )
                # first static args, and then iterative chunk
                sqlSubmitQueue.put(
                    args[0:len(args) - idCount] + chunk_slice
                )
                ret_val = sqlReturnQueue.get(timeout=5.0)
                total_row_count += ret_val[1]
            sqlSubmitQueue.put('commit')
        finally:
            sql_lock.release()
    except Exception as e:
        logging.debug(f"SQL executeChunked error: {e}")
    
    return total_row_count


def sqlExecute(sql_statement, *args):
    """Execute SQL statement (optionally with arguments)"""
    if not sql_available or _is_shutting_down():
        return 0
    
    try:
        if not sql_lock.acquire(timeout=2.0):
            logging.debug(f"SQL lock timeout for execute: {sql_statement[:50]}...")
            return 0
        
        try:
            sqlSubmitQueue.put(sql_statement)

            if args == ():
                sqlSubmitQueue.put('')
            else:
                sqlSubmitQueue.put(args)
            
            _, rowcount = sqlReturnQueue.get(timeout=5.0)
            sqlSubmitQueue.put('commit')
            return rowcount
        finally:
            sql_lock.release()
            
    except Exception as e:
        logging.debug(f"SQL execute error: {e}")
        return 0


def sqlExecuteScript(sql_statement):
    """Execute SQL script statement"""
    if not sql_available or _is_shutting_down():
        return

    try:
        with SqlBulkExecute() as sql:
            statements = sql_statement.split(";")
            for q in statements:
                if q.strip():
                    sql.execute("{}".format(q))
    except Exception as e:
        logging.debug(f"SQL executeScript error: {e}")


def sqlStoredProcedure(procName):
    """Schedule procName to be run"""
    if not sql_available or _is_shutting_down():
        return
    
    try:
        if not sql_lock.acquire(timeout=2.0):
            logging.debug(f"SQL lock timeout for procedure: {procName}")
            return
        
        try:
            sqlSubmitQueue.put(procName)
            if procName == "exit":
                sqlSubmitQueue.task_done()
                sqlSubmitQueue.put("terminate")
        finally:
            sql_lock.release()
    except Exception as e:
        logging.debug(f"SQL storedProcedure error: {e}")


class SqlBulkExecute(object):
    """This is used when you have to execute the same statement in a cycle."""
    
    def __init__(self):
        self._lock_acquired = False
    
    def __enter__(self):
        # During shutdown, don't even try
        if _is_shutting_down():
            return self
            
        try:
            self._lock_acquired = sql_lock.acquire(timeout=2.0)
            if not self._lock_acquired:
                if _is_shutting_down():
                    # During shutdown, it's ok to fail
                    return self
                else:
                    raise Exception("SQL bulk execute lock busy (timeout: 2s)")
        except Exception as e:
            if _is_shutting_down():
                # During shutdown, ignore errors
                return self
            raise e
            
        return self
    
    def __exit__(self, exc_type, value, traceback):
        try:
            # Only commit if we have the lock and not shutting down
            if self._lock_acquired and not _is_shutting_down():
                try:
                    sqlSubmitQueue.put('commit')
                except Exception:
                    pass  # Ignore during shutdown
        finally:
            # Only release if we actually acquired it
            if self._lock_acquired:
                try:
                    sql_lock.release()
                except RuntimeError:
                    # Lock might already be released, ignore
                    pass
                self._lock_acquired = False
    
    @staticmethod
    def execute(sql_statement, *args):
        """Used for statements that do not return results."""
        if not sql_available or _is_shutting_down():
            return
            
        try:
            sqlSubmitQueue.put(sql_statement)

            if args == ():
                sqlSubmitQueue.put('')
            else:
                sqlSubmitQueue.put(args)
            
            sqlReturnQueue.get(timeout=5.0)
        except Exception as e:
            if not _is_shutting_down():
                logging.debug(f"SQL bulk execute error: {e}")


# Helper for shutdown
def sqlPrepareShutdown():
    """Prepare SQL for shutdown"""
    try:
        sqlSubmitQueue.put('commit')
    except:
        pass
