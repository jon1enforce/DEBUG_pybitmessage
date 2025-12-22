-- SCHRITT 1: Tabellenstruktur prüfen
-- Überprüfen Sie die genaue Struktur Ihrer `messages`/`sent`-Tabelle
DESCRIBE messages; -- oder SHOW CREATE TABLE messages;
-- Achten Sie besonders auf die Spalten, die Nachrichtentext und binäre Daten speichern.

-- SCHRITT 2: Datenqualität prüfen
-- Finden Sie Datensätze, die Probleme verursachen könnten
SELECT id, LENGTH(nachrichten_spalte), 
       HEX(SUBSTRING(nachrichten_spalte, 1, 20)) as erste_bytes
FROM messages 
WHERE nachrichten_spalte IS NOT NULL 
LIMIT 10;
-- Überprüfen Sie, ob die Längen plausibel sind und ob die Hex-Darstellung sinnvoll aussieht.

-- SCHRITT 3: Code-Integration prüfen
-- Prüfen Sie die kritischen Stellen in Ihrem Anwendungscode (Beispiel in Python):
"""
import psycopg2  # oder das DB-Interface Ihrer Wahl
import json

# Stellen Sie sicher, dass die Daten korrekt konvertiert werden
def save_message(message_text):
    # Wenn Sie Byte-Arrays speichern müssen:
    if isinstance(message_text, bytes):
        # Konvertierung zu einem DB-kompatiblen Format
        data = psycopg2.Binary(message_text)
    else:
        data = message_text
    
    # ... Datenbank-Insert-Logik ...
"""
-- SCHRITT 4: Neuen Testdatensatz einfügen
-- Testen Sie mit einem sauberen Datensatz
INSERT INTO messages (nachrichten_spalte) 
VALUES ('Testnachricht mit normalem Text');
-- Überprüfen Sie, ob dieser Datensatz das Problem löst.

-- SCHRITT 5: Probleme isolieren
-- Wenn Schritt 4 funktioniert, suchen Sie speziell nach problematischen Datensätzen
SELECT id, nachrichten_spalte
FROM messages
WHERE nachrichten_spalte LIKE '%\\x%'  -- nach Hex-Strings suchen
   OR nachrichten_spalte LIKE '%[null]%'  -- nach fehlerhaften JSON suchen
   OR nachrichten_spalte !~ '^[A-Za-z0-9äöüßÄÖÜ .,!?-]*$'; -- einfache Zeichenprüfung
