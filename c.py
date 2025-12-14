import sqlite3

def fix_database_status():
    conn = sqlite3.connect('/home/jon/DEBUG_pybitmessage/src/messages.dat')
    cursor = conn.cursor()
    
    # Alle Datensätze mit BLOB status holen
    cursor.execute("SELECT msgid, status FROM sent WHERE typeof(status) = 'blob'")
    rows = cursor.fetchall()
    
    for msgid, status_blob in rows:
        try:
            if isinstance(status_blob, bytes):
                # Versuche UTF-8 Decodierung
                status_str = status_blob.decode('utf-8')
                print(f"MsgID {msgid}: Konvertiere {repr(status_blob)} -> '{status_str}'")
                
                # Update
                cursor.execute("UPDATE sent SET status = ? WHERE msgid = ?", 
                              (status_str, msgid))
            else:
                print(f"MsgID {msgid}: Unerwarteter Typ: {type(status_blob)}")
        except Exception as e:
            print(f"Fehler bei MsgID {msgid}: {e}")
    
    conn.commit()
    conn.close()
    print(f"Korrigiert: {len(rows)} Datensätze")

if __name__ == "__main__":
    fix_database_status()
