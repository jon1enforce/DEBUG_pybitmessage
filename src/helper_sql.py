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
import sqlite3

logger = logging.getLogger('default')

sqlSubmitQueue = queue.Queue()
sqlReturnQueue = queue.Queue()
sql_lock = threading.Lock()
sql_available = False
sql_ready = threading.Event()
sql_timeout = 60


def safe_decode(data, encoding='utf-8', errors='ignore'):
    """
    Sicher von Bytes zu String konvertieren
    """
    if isinstance(data, bytes):
        return data.decode(encoding, errors)
    elif isinstance(data, str):
        return data
    elif data is None:
        return ''
    else:
        return str(data)


def sqlQuery(sql_statement, *args):
    """
    Query sqlite and return results - EMERGENCY VERSION WITHOUT LOCKING
    """
    global sql_available
    
    if not sql_available:
        return []
    
    try:
        # WICHTIG: Keine automatische Konvertierung hier!
        # Der sqlThread kümmert sich um text_factory = str
        # und die aufrufende Funktion muss wissen, was sie erwartet
        
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
            return []
            
    except queue.Full:
        return []
    except Exception as e:
        logger.error("Error in sqlQuery: %s", e)
        return []


def safe_sql_query(sql_statement, *args):
    """
    Sichere Version von sqlQuery für Python 3
    Gibt automatisch dekodierte Strings zurück für Textfelder
    """
    results = sqlQuery(sql_statement, *args)
    
    # Basierend auf der SQL-Anfrage entscheiden, was dekodiert werden soll
    sql_upper = sql_statement.upper()
    
    decoded_results = []
    for row in results:
        if isinstance(row, tuple):
            new_row = []
            for i, item in enumerate(row):
                # Entscheide basierend auf Feldtyp, ob dekodiert werden soll
                if isinstance(item, bytes):
                    # Textfelder dekodieren, Binärfelder nicht
                    if any(field in sql_upper for field in ['TOADDRESS', 'FROMADDRESS', 'SUBJECT', 'MESSAGE', 'LABEL', 'ADDRESS']):
                        # Dies sind wahrscheinlich Textfelder
                        try:
                            new_row.append(safe_decode(item, "utf-8", "ignore"))
                        except:
                            new_row.append(item)
                    elif any(field in sql_upper for field in ['MSGID', 'HASH', 'ACKDATA', 'SIGHASH', 'TAG']):
                        # Dies sind Binärfelder - als Bytes belassen
                        new_row.append(item)
                    else:
                        # Standard: versuche zu dekodieren
                        try:
                            new_row.append(safe_decode(item, "utf-8", "ignore"))
                        except:
                            new_row.append(item)
                else:
                    new_row.append(item)
            decoded_results.append(tuple(new_row))
        else:
            decoded_results.append(row)
    
    return decoded_results


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
    except Exception as e:
        logger.error("Error in sqlExecute: %s", e)
        return 0


def safe_sql_execute(sql_statement, *args):
    """
    Sichere Version von sqlExecute für Python 3
    Konvertiert Strings zu Bytes für Binärfelder
    """
    # Basierend auf der SQL-Anfrage entscheiden, was konvertiert werden soll
    sql_upper = sql_statement.upper()
    
    processed_args = []
    for i, arg in enumerate(args):
        if isinstance(arg, str):
            # Wenn es ein String ist, der in ein Binärfeld eingefügt werden soll
            if any(field in sql_upper for field in ['MSGID', 'HASH', 'ACKDATA', 'SIGHASH', 'TAG', 'TRANSMITDATA', 'PAYLOAD']):
                # In Bytes konvertieren
                processed_args.append(sqlite3.Binary(arg.encode('utf-8')))
            else:
                # Als String belassen
                processed_args.append(arg)
        elif isinstance(arg, bytes):
            # Bytes für Binärfelder
            processed_args.append(sqlite3.Binary(arg))
        else:
            processed_args.append(arg)
    
    return sqlExecute(sql_statement, *processed_args)


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
            
            sqlSubmitQueue.put(
                args[0:len(args) - idCount] + list(chunk_slice),
                timeout=2
            )
            try:
                ret_val = sqlReturnQueue.get(timeout=10)
                total_row_count += ret_val[1]
            except queue.Empty:
                break
        sqlSubmitQueue.put('commit', timeout=2)
    except Exception as e:
        logger.error("Error in sqlExecuteChunked: %s", e)
    
    return total_row_count


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
