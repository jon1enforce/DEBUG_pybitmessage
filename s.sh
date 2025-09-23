#!/bin/sh

# Log-Datei zurücksetzen
> ~/log.txt

# Zähler für Zeilen
line_count=0

# PyBitmessage starten und Output verarbeiten
python3 pybitmessage/bitmessagemain.py 2>&1 | while IFS= read -r line; do
    if [ $line_count -lt 3000 ]; then
        echo "$line" >> ~/log.txt
        echo "$line"
        line_count=$((line_count + 1))
    else
        echo "Loglimit von 3000 Zeilen erreicht - Programm wird gestoppt"
        pkill -f "python3 pybitmessage/bitmessagemain.py"
        break
    fi
done
