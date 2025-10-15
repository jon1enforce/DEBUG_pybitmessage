#!/bin/bash
cd ~/DEBUG_pybitmessage

echo "🚀 Starte PyBitMessage mit LaTeX Bridge..."

# BitMessage im Hintergrund starten
echo "📡 Starte PyBitMessage..."
python3 pybitmessage/bitmessagemain.py &
BM_PID=$!
echo "PyBitMessage PID: $BM_PID"

# Warten bis BitMessage initialisiert ist
sleep 10

# LaTeX Bridge starten
echo "🔗 Starte LaTeX Bridge..."
python3 bridge.py

# Falls Bridge beendet wird, auch BitMessage beenden
echo "🛑 Beende PyBitMessage..."
kill $BM_PID
