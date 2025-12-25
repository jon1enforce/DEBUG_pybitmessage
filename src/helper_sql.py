"""
SQL-related functions defined here are really pass the queries (or other SQL
commands) to :class:`.threads.sqlThread` through `sqlSubmitQueue` queue and check
or return the result got from `sqlReturnQueue`.

EMERGENCY PATCH MIT DEBUGGING UND LOCKING WIEDER AKTIVIERT
"""

import threading
import logging
import time
from six.moves import queue
import sqlite3

logger = logging.getLogger('default')

sqlSubmitQueue = queue.Queue()
sqlReturnQueue = queue.Queue()
sql_lock = threading.Lock()  # LOCKING WIEDER AKTIVIERT
sql_available = False
sql_ready = threading.Event()
sql_timeout = 60

# Debug-Zähler für Queries
_query_counter = 0
_query_counter_lock = threading.Lock()


def _get_query_id():
    """Generiert eine eindeutige Query-ID für Debugging"""
    global _query_counter
    with _query_counter_lock:
        _query_counter += 1
        return f"Q{_query_counter:06d}"


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
    Query sqlite and return results - MIT LOCKING UND DEBUGGING
    """
    global sql_available
    
    if not sql_available:
        logger.warning("SQL not available in sqlQuery")
        return []
    
    query_id = _get_query_id()
    logger.debug("🔍 SQL QUERY START [%s]: %s", query_id, sql_statement[:200])
    if args and args != ((),):
        logger.debug("🔍 SQL PARAMS [%s]: %s", query_id, str(args)[:200])
    
    # LOCKING WIEDER AKTIVIERT - verhindert Race Conditions
    sql_lock.acquire()
    
    try:
        # Send query to SQL thread
        sqlSubmitQueue.put(sql_statement, timeout=5)
        
        if args == ():
            sqlSubmitQueue.put('', timeout=5)
        elif isinstance(args[0], (list, tuple)):
            sqlSubmitQueue.put(args[0], timeout=5)
        else:
            sqlSubmitQueue.put(args, timeout=5)
        
        # Wait for response
        try:
            queryreturn, rowcount = sqlReturnQueue.get(timeout=15)
            
            # DEBUG: Überprüfe das Ergebnis
            logger.debug("🔍 SQL RESULT [%s]: %d rows returned", query_id, len(queryreturn))
            
            if queryreturn:
                first_row_columns = len(queryreturn[0])
                logger.debug("🔍 SQL COLUMNS [%s]: First row has %d columns", 
                           query_id, first_row_columns)
                
                # VERBESSERTE ERKENNUNG: Nur bei spezifischen Queries warnen
                # Liste der Queries, die 10 Spalten erwarten
                ten_column_queries = [
                    'SELECT msgid, toaddress, fromaddress, subject, message, ackdata, status, ttl, retrynumber, encodingtype FROM',
                    'SELECT msgid, toaddress, fromaddress, subject, message, ackdata, status, ttl, retrynumber, encodingtype FROM sent'
                ]
                
                # Liste der Queries, die 2 Spalten erwarten (Status+Count)
                two_column_queries = [
                    'SELECT status, COUNT(*) as count FROM',
                    'SELECT status, COUNT(*) FROM'
                ]
                
                # Liste der Queries, die 1 Spalte erwarten
                one_column_queries = [
                    'SELECT retrynumber FROM',
                    'SELECT COUNT(*) FROM',
                    'SELECT msgid FROM',
                    'SELECT status FROM'
                ]
                
                sql_lower = sql_statement.lower()
                
                # Prüfe nur bei spezifischen 10-Spalten-Queries
                is_ten_column_query = any(query in sql_lower for query in [
                    'msgid, toaddress, fromaddress, subject, message, ackdata, status, ttl, retrynumber, encodingtype'
                ])
                
                if is_ten_column_query and first_row_columns != 10:
                    logger.error("❌ SQL COLUMN MISMATCH [%s]: Expected 10 columns, got %d", 
                               query_id, first_row_columns)
                    logger.error("❌ Query was: %s", sql_statement[:500])
                    logger.error("❌ First row: %s", queryreturn[0])
                
                # Optional: Bei anderen Queries nur info loggen
                elif any(query in sql_lower for query in two_column_queries) and first_row_columns == 2:
                    logger.debug("✅ SQL COLUMNS OK [%s]: Expected 2 columns (status, count), got %d", 
                               query_id, first_row_columns)
                elif any(query in sql_lower for query in one_column_queries) and first_row_columns == 1:
                    logger.debug("✅ SQL COLUMNS OK [%s]: Expected 1 column, got %d", 
                               query_id, first_row_columns)
            
            return queryreturn
            
        except queue.Empty:
            logger.error("⏰ SQL TIMEOUT [%s]: No response from SQL thread", query_id)
            return []
            
    except queue.Full:
        logger.error("🚫 SQL QUEUE FULL [%s]", query_id)
        return []
        
    except Exception as e:
        logger.error("💥 SQL ERROR [%s]: %s", query_id, e)
        import traceback
        logger.error(traceback.format_exc())
        return []
        
    finally:
        # WICHTIG: Lock immer freigeben
        sql_lock.release()
        logger.debug("🔍 SQL QUERY END [%s]", query_id)


def safe_sql_query(sql_statement, *args):
    """
    Sichere Version von sqlQuery für Python 3
    Gibt automatisch dekodierte Strings zurück für Textfelder
    """
    query_id = _get_query_id()
    logger.debug("🔍 SAFE SQL QUERY START [%s]", query_id)
    
    results = sqlQuery(sql_statement, *args)
    
    # Basierend auf der SQL-Anfrage entscheiden, was dekodiert werden soll
    sql_upper = sql_statement.upper()
    
    decoded_results = []
    for row_idx, row in enumerate(results):
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
    
    logger.debug("🔍 SAFE SQL QUERY END [%s]: %d rows decoded", query_id, len(decoded_results))
    return decoded_results


def sqlExecute(sql_statement, *args):
    """Execute SQL statement - MIT LOCKING UND DEBUGGING"""
    global sql_available
    
    if not sql_available:
        logger.warning("SQL not available in sqlExecute")
        return 0
    
    query_id = _get_query_id()
    logger.debug("✏️ SQL EXECUTE START [%s]: %s", query_id, sql_statement[:200])
    if args and args != ((),):
        logger.debug("✏️ SQL PARAMS [%s]: %s", query_id, str(args)[:200])
    
    # LOCKING WIEDER AKTIVIERT
    sql_lock.acquire()
    
    try:
        sqlSubmitQueue.put(sql_statement, timeout=5)

        if args == ():
            sqlSubmitQueue.put('', timeout=5)
        else:
            sqlSubmitQueue.put(args, timeout=5)
            
        try:
            queryreturn, rowcount = sqlReturnQueue.get(timeout=15)
            logger.debug("✏️ SQL EXECUTE RESULT [%s]: %d rows affected", query_id, rowcount)
        except queue.Empty:
            logger.error("⏰ SQL EXECUTE TIMEOUT [%s]", query_id)
            rowcount = 0
            
        # Commit
        sqlSubmitQueue.put('commit', timeout=5)
        return rowcount
        
    except Exception as e:
        logger.error("💥 SQL EXECUTE ERROR [%s]: %s", query_id, e)
        import traceback
        logger.error(traceback.format_exc())
        return 0
        
    finally:
        # WICHTIG: Lock immer freigeben
        sql_lock.release()
        logger.debug("✏️ SQL EXECUTE END [%s]", query_id)


def safe_sql_execute(sql_statement, *args):
    """
    Sichere Version von sqlExecute für Python 3
    Konvertiert Strings zu Bytes für Binärfelder
    """
    query_id = _get_query_id()
    logger.debug("✏️ SAFE SQL EXECUTE START [%s]", query_id)
    
    # Basierend auf der SQL-Anfrage entscheiden, was konvertiert werden soll
    sql_upper = sql_statement.upper()
    
    processed_args = []
    for i, arg in enumerate(args):
        if isinstance(arg, str):
            # Wenn es ein String ist, der in ein Binärfeld eingefügt werden soll
            if any(field in sql_upper for field in ['MSGID', 'HASH', 'ACKDATA', 'SIGHASH', 'TAG', 'TRANSMITDATA', 'PAYLOAD']):
                # In Bytes konvertieren
                processed_args.append(sqlite3.Binary(arg.encode('utf-8')))
                logger.debug("✏️ SAFE SQL [%s]: Converted arg %d to Binary", query_id, i)
            else:
                # Als String belassen
                processed_args.append(arg)
        elif isinstance(arg, bytes):
            # Bytes für Binärfelder
            processed_args.append(sqlite3.Binary(arg))
            logger.debug("✏️ SAFE SQL [%s]: Wrapped arg %d bytes in Binary", query_id, i)
        else:
            processed_args.append(arg)
    
    result = sqlExecute(sql_statement, *processed_args)
    logger.debug("✏️ SAFE SQL EXECUTE END [%s]: %d rows affected", query_id, result)
    return result


def sqlExecuteChunked(sql_statement, as_text, idCount, *args):
    """Execute chunked SQL statement - MIT LOCKING"""
    global sql_available
    
    if not sql_available:
        return 0
        
    sqlExecuteChunked.chunkSize = 999

    if idCount == 0 or idCount > len(args):
        return 0

    total_row_count = 0
    
    # LOCKING für die gesamte chunked Operation
    sql_lock.acquire()
    
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
                sqlSubmitQueue.put(sql_statement.format(q), timeout=5)
            else:
                sqlSubmitQueue.put(
                    sql_statement.format(','.join('?' * len(chunk_slice))),
                    timeout=5
                )
            
            sqlSubmitQueue.put(
                args[0:len(args) - idCount] + list(chunk_slice),
                timeout=5
            )
            try:
                ret_val = sqlReturnQueue.get(timeout=15)
                total_row_count += ret_val[1]
            except queue.Empty:
                break
        sqlSubmitQueue.put('commit', timeout=5)
    except Exception as e:
        logger.error("Error in sqlExecuteChunked: %s", e)
    finally:
        sql_lock.release()
    
    return total_row_count


def sqlExecuteScript(sql_statement):
    """Execute SQL script statement"""
    global sql_available
    
    if not sql_available:
        return

    statements = sql_statement.split(";")
    for q in statements:
        if q.strip():
            sqlExecute(q)


def sqlStoredProcedure(procName):
    """Schedule procName to be run"""
    global sql_available
    
    if not sql_available:
        return
    
    try:
        sqlSubmitQueue.put(procName, timeout=5)
        if procName == "exit":
            sqlSubmitQueue.put("terminate", timeout=5)
    except Exception:
        pass


class SqlBulkExecute(object):
    """This is used when you have to execute the same statement in a cycle."""

    def __enter__(self):
        global sql_available
        
        if not sql_available:
            raise Exception('SQL not available')
            
        # Lock für die gesamte Bulk-Operation
        sql_lock.acquire()
        return self

    def __exit__(self, exc_type, value, traceback):
        try:
            sqlSubmitQueue.put('commit', timeout=5)
        except Exception:
            pass
        finally:
            sql_lock.release()

    @staticmethod
    def execute(sql_statement, *args):
        """Used for statements that do not return results."""
        global sql_available
        
        if not sql_available:
            return
            
        try:
            sqlSubmitQueue.put(sql_statement, timeout=5)

            if args == ():
                sqlSubmitQueue.put('', timeout=5)
            else:
                sqlSubmitQueue.put(args, timeout=5)
                
            try:
                sqlReturnQueue.get(timeout=15)
            except queue.Empty:
                pass
        except Exception:
            pass
