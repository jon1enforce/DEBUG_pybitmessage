"""
Debug why address comparison fails
"""

import sys
import os
sys.path.insert(0, '/home/jon/DEBUG_pybitmessage/src')

print("DEBUG: Address Comparison Problem")
print("="*80)

# Test-Adresse
test_address = "BM-2cTe6VTRGAiFhhnKENRWcHpt54izAuwX4Y"
print(f"Test address: {test_address}")
print(f"Length: {len(test_address)}")
print(f"Type: {type(test_address)}")

# Direkter Datenbankzugriff
import sqlite3
db_path = 'messages.dat'

try:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 1. Hole ALLE Adressen aus sent
    print("\n1. All addresses in sent table:")
    cursor.execute("SELECT toaddress, typeof(toaddress) FROM sent")
    all_addresses = cursor.fetchall()
    
    print(f"Total addresses in sent: {len(all_addresses)}")
    
    # 2. Vergleiche jede Adresse genau
    print("\n2. Detailed comparison:")
    
    for i, (addr_in_db, addr_type) in enumerate(all_addresses):
        print(f"\n  Entry {i+1}:")
        print(f"    DB type: {addr_type}")
        
        # Konvertiere je nach Typ
        if isinstance(addr_in_db, bytes):
            print(f"    DB value (bytes): {addr_in_db}")
            print(f"    Hex: {addr_in_db.hex()}")
            
            # Versuche verschiedene Decodierungen
            try:
                as_utf8 = addr_in_db.decode('utf-8')
                print(f"    As UTF-8: '{as_utf8}'")
                print(f"    UTF-8 length: {len(as_utf8)}")
            except:
                print(f"    Cannot decode as UTF-8")
                
            try:
                as_latin1 = addr_in_db.decode('latin-1')
                print(f"    As Latin-1: '{as_latin1}'")
                print(f"    Latin-1 length: {len(as_latin1)}")
            except:
                print(f"    Cannot decode as Latin-1")
                
            # Vergleiche mit Test-Adresse
            try:
                decoded = addr_in_db.decode('utf-8', 'replace')
                if decoded == test_address:
                    print(f"    ✓ MATCH with test address!")
                else:
                    print(f"    ✗ NO MATCH")
                    print(f"    Differences:")
                    print(f"      DB: '{decoded}'")
                    print(f"      Test: '{test_address}'")
                    
                    # Zeiche für Zeichen Vergleich
                    print(f"    Character-by-character:")
                    min_len = min(len(decoded), len(test_address))
                    for j in range(min_len):
                        db_char = decoded[j]
                        test_char = test_address[j]
                        if db_char != test_char:
                            print(f"      Position {j}: DB='{db_char}' (ord={ord(db_char)}), "
                                  f"Test='{test_char}' (ord={ord(test_char)})")
                    
                    if len(decoded) != len(test_address):
                        print(f"    Length mismatch: DB={len(decoded)}, Test={len(test_address)}")
                        
            except Exception as e:
                print(f"    Comparison error: {e}")
                
        elif isinstance(addr_in_db, str):
            print(f"    DB value (string): '{addr_in_db}'")
            print(f"    String length: {len(addr_in_db)}")
            
            # Direkter Vergleich
            if addr_in_db == test_address:
                print(f"    ✓ EXACT MATCH with test address!")
            else:
                print(f"    ✗ NO EXACT MATCH")
                
                # Case-insensitive Vergleich
                if addr_in_db.lower() == test_address.lower():
                    print(f"    ✓ CASE-INSENSITIVE MATCH")
                else:
                    print(f"    ✗ No match even case-insensitive")
                
                # Whitespace Vergleich
                db_stripped = addr_in_db.strip()
                test_stripped = test_address.strip()
                if db_stripped == test_stripped:
                    print(f"    ✓ MATCH after stripping whitespace")
                    print(f"      DB had whitespace: '{addr_in_db}' -> '{db_stripped}'")
                
                # Zeige Unterschiede
                print(f"    Character differences:")
                min_len = min(len(addr_in_db), len(test_address))
                for j in range(min_len):
                    db_char = addr_in_db[j]
                    test_char = test_address[j]
                    if db_char != test_char:
                        print(f"      Position {j}: DB='{db_char}' (ord={ord(db_char)}), "
                              f"Test='{test_char}' (ord={ord(test_char)})")
                
                if len(addr_in_db) != len(test_address):
                    print(f"    Length mismatch: DB={len(addr_in_db)}, Test={len(test_address)}")
        
        else:
            print(f"    Unknown type: {type(addr_in_db)}, value: {addr_in_db}")
    
    # 3. Spezifische Suche nach unserer Test-Adresse
    print("\n3. Searching specifically for our test address:")
    
    # Versuch 1: Exakter Match
    cursor.execute("SELECT toaddress FROM sent WHERE toaddress = ?", (test_address,))
    exact_matches = cursor.fetchall()
    print(f"  Exact match query: {len(exact_matches)} results")
    
    # Versuch 2: Case-insensitive
    cursor.execute("SELECT toaddress FROM sent WHERE LOWER(toaddress) = LOWER(?)", 
                   (test_address,))
    case_insensitive = cursor.fetchall()
    print(f"  Case-insensitive query: {len(case_insensitive)} results")
    
    # Versuch 3: LIKE (flexibler)
    cursor.execute("SELECT toaddress FROM sent WHERE toaddress LIKE ?", 
                   (f"%{test_address}%",))
    like_matches = cursor.fetchall()
    print(f"  LIKE query: {len(like_matches)} results")
    
    # Versuch 4: Manuell durchsuchen
    print(f"  Manual search in all addresses:")
    all_addrs = [row[0] for row in all_addresses]
    for i, addr in enumerate(all_addrs):
        if isinstance(addr, bytes):
            try:
                addr_str = addr.decode('utf-8', 'replace')
                if test_address in addr_str:
                    print(f"    Found at index {i}: '{addr_str}'")
            except:
                pass
        elif isinstance(addr, str):
            if test_address in addr:
                print(f"    Found at index {i}: '{addr}'")
    
    conn.close()
    
except Exception as e:
    print(f"Database error: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*80)
print("RECOMMENDED FIX:")
print("1. Use case-insensitive comparison: addr_in_db.lower() == toAddress.lower()")
print("2. Strip whitespace: addr_in_db.strip() == toAddress.strip()")
print("3. Or use SQL LIKE or LOWER() in the query itself")
print("="*80)
