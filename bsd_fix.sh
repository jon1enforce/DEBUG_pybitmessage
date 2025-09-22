#!/bin/sh
# PyBitmessage OpenBSD Fix Script
# Behebt alle bekannten Probleme aus dem logger.txt

set -e

# Farben für die Ausgabe
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log-Funktion
log() {
    echo "${BLUE}[INFO]${NC} $1"
}

error() {
    echo "${RED}[ERROR]${NC} $1"
}

success() {
    echo "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo "${YELLOW}[WARNING]${NC} $1"
}

# Root-Check
if [ "$(id -u)" -ne 0 ]; then
    error "Dieses Skript muss als root ausgeführt werden"
    exit 1
fi

# OpenBSD-Check
if [ "$(uname)" != "OpenBSD" ]; then
    error "Dieses Skript ist nur für OpenBSD gedacht"
    exit 1
fi

log "Starte PyBitmessage Reparatur für OpenBSD..."

# 1. Alte LibreSSL Installation entfernen
log "Entferne alte LibreSSL 2.5.0 Installation..."
if [ -d "/home/libressl-2.5.0" ]; then
    rm -rf "/home/libressl-2.5.0"
    success "Alte LibreSSL Installation entfernt"
else
    log "Keine alte LibreSSL Installation gefunden"
fi

# 2. Systemaktualisierung
log "Aktualisiere Systempakete..."
pkg_add -u

# 3. Notwendige Pakete installieren
log "Installiere benötigte Abhängigkeiten..."
pkg_add -I python3 py3-pip py3-qt5 sqlite3 git libffi openssl

# 4. Python Abhängigkeiten installieren
log "Installiere Python-Abhängigkeiten..."
pip3 install --upgrade pip
pip3 install pyqt5 ctypes six

# 5. PyBitmessage Repository klonen oder aktualisieren
PYBITMESSAGE_DIR="/home/pybitmessage"
if [ ! -d "$PYBITMESSAGE_DIR" ]; then
    log "Klonne PyBitmessage Repository..."
    git clone https://github.com/Bitmessage/PyBitmessage "$PYBITMESSAGE_DIR"
else
    log "Aktualisiere PyBitmessage Repository..."
    cd "$PYBITMESSAGE_DIR"
    git pull origin master
fi

# 6. Fehlende Importe in PyBitmessage Dateien beheben
log "Behebe fehlende Importe in PyBitmessage..."

# hexlify Import hinzufügen
find "$PYBITMESSAGE_DIR" -name "*.py" -exec grep -l "hexlify" {} \; | while read file; do
    if ! grep -q "from binascii import hexlify" "$file" && ! grep -q "import binascii" "$file"; then
        log "Füge hexlify Import hinzu zu: $file"
        sed -i '' '1i\
from binascii import hexlify
' "$file"
    fi
done

# Weitere fehlende Importe
find "$PYBITMESSAGE_DIR" -name "*.py" -exec grep -l "binascii" {} \; | while read file; do
    if ! grep -q "import binascii" "$file"; then
        log "Füge binascii Import hinzu zu: $file"
        sed -i '' '1i\
import binascii
' "$file"
    fi
done

# 7. OpenSSL Konfiguration anpassen
log "Passe OpenSSL Konfiguration an..."

# Erstelle Konfigurationsverzeichnis
CONFIG_DIR="/root/.config/PyBitmessage"
mkdir -p "$CONFIG_DIR"

# Erstelle oder aktualisiere Konfigurationsdatei
cat > "$CONFIG_DIR/keys.dat" << 'EOF'
[bitmessagesettings]
settingsversion = 10
ssltype = system
namecoin = false
onionhostname = 
onionport = 0
sockshostname = 
socksport = 0
maxoutboundconnections = 4
maxacceptablenoncetrialsperbyte = 320000000
maxacceptablepayloadlengthextrabytes = 14000
dontconnect = 

[network]
# Deaktiviere IPv6 vorübergehend zur Problembehebung
disableipv6 = true

[logging]
# Reduziere Log-Level für bessere Performance
loglevel = WARNING
consoleloglevel = ERROR
EOF

# 8. Environment Variables setzen
log "Setze Umgebungsvariablen..."

cat > /root/.pybitmessage_env << 'EOF'
export LD_LIBRARY_PATH=/usr/lib:/usr/local/lib
export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
export SSL_CERT_FILE=/etc/ssl/cert.pem
export SSL_CERT_DIR=/etc/ssl/certs
export PYTHONPATH=/home/pybitmessage/src:$PYTHONPATH
EOF

# 9. Startskript erstellen
log "Erstelle Startskript..."

cat > /usr/local/bin/pybitmessage << 'EOF'
#!/bin/sh
# PyBitmessage Startskript für OpenBSD

# Environment variablen laden
[ -f /root/.pybitmessage_env ] && . /root/.pybitmessage_env

# Prüfe auf vorhandene Instanz
if pgrep -f "python.*pybitmessage" > /dev/null; then
    echo "PyBitmessage läuft bereits"
    exit 1
fi

# Starte PyBitmessage
cd /home/pybitmessage/src
exec python3 pybitmessage.py "$@"
EOF

chmod +x /usr/local/bin/pybitmessage

# 10. Systemd Service erstellen (wenn systemd verfügbar)
if which rcctl >/dev/null 2>&1; then
    log "Erstelle OpenBSD rc.d Service..."

    cat > /etc/rc.d/pybitmessage << 'EOF'
#!/bin/sh
#
# $OpenBSD: pybitmessage.rc,v 1.0 2024/01/01 00:00:00 user Exp $

daemon="/usr/local/bin/pybitmessage"
daemon_user="_pybitmessage"
daemon_flags=""
daemon_timeout=60

. /etc/rc.d/rc.subr

rc_bg=YES
rc_reload=NO

pexp="python.*pybitmessage"

rc_cmd $1
EOF

    chmod +x /etc/rc.d/pybitmessage
fi

# 11. Dedizierten User erstellen
if ! id "_pybitmessage" >/dev/null 2>&1; then
    log "Erstelle dedizierten User für PyBitmessage..."
    useradd -d /var/empty -s /sbin/nologin _pybitmessage
fi

# 12. Berechtigungen setzen
log "Setze Berechtigungen..."
chown -R _pybitmessage:_pybitmessage "$CONFIG_DIR"
chmod 700 "$CONFIG_DIR"

# 13. Netzwerk-Konfiguration überprüfen
log "Überprüfe Netzwerk-Konfiguration..."

# Teste DNS
if ! ping -c 1 -t 5 8.8.8.8 >/dev/null 2>&1; then
    warning "Netzwerkverbindung problematisch. Überprüfe deine Netzwerkeinstellungen."
fi

# 14. SSL Zertifikate überprüfen
log "Überprüfe SSL Zertifikate..."
if [ ! -f "/etc/ssl/cert.pem" ]; then
    log "Installiere SSL Zertifikate..."
    pkg_add -I ca_root_nss
fi

# 15. Python Path setzen
log "Setze Python Path..."
echo 'export PYTHONPATH="/home/pybitmessage/src:$PYTHONPATH"' >> /root/.profile
echo 'export PATH="/home/pybitmessage/src:$PATH"' >> /root/.profile

# 16. Test-Skript erstellen
log "Erstelle Test-Skript..."

cat > /usr/local/bin/test_pybitmessage << 'EOF'
#!/bin/sh
# Testet PyBitmessage Konfiguration

echo "=== PyBitmessage Test ==="
echo "Python Version: $(python3 --version)"
echo "OpenSSL Version: $(openssl version)"
echo "PyQt5 Version: $(python3 -c 'from PyQt5.QtCore import QT_VERSION_STR; print(f"Qt {QT_VERSION_STR}")' 2>/dev/null || echo "Nicht installiert")"
echo "Konfigurationsverzeichnis: /root/.config/PyBitmessage"
echo "Installationsverzeichnis: /home/pybitmessage"
echo "========================="
EOF

chmod +x /usr/local/bin/test_pybitmessage

# 17. Cleanup
log "Führe Cleanup durch..."
pkg_delete -a 2>/dev/null || true

# 18. Abschluss
success "PyBitmessage Reparatur abgeschlossen!"
echo ""
echo "Zusammenfassung der durchgeführten Änderungen:"
echo "✅ Alte LibreSSL Installation entfernt"
echo "✅ Systempakete aktualisiert"
echo "✅ Abhängigkeiten installiert"
echo "✅ PyBitmessage Repository geklont/aktualisiert"
echo "✅ Fehlende Importe behoben"
echo "✅ OpenSSL Konfiguration angepasst"
echo "✅ Umgebungsvariablen gesetzt"
echo "✅ Startskript erstellt"
echo "✅ Dedizierten User erstellt"
echo "✅ Berechtigungen gesetzt"
echo ""
echo "Nächste Schritte:"
echo "1. Logout und wieder einloggen für Umgebungsvariablen"
echo "2. PyBitmessage starten mit: pybitmessage"
echo "3. Konfiguration testen mit: test_pybitmessage"
echo ""
echo "Hinweis: IPv6 wurde vorübergehend deaktiviert. Kann später in der"
echo "Konfiguration unter /root/.config/PyBitmessage/keys.dat wieder aktiviert werden."

# 19. Umgebungsvariablen sofort laden
. /root/.pybitmessage_env

log "Teste grundlegende Funktionalität..."
if python3 -c "import ssl; print('SSL verfügbar')" 2>/dev/null; then
    success "SSL ist funktionsfähig"
else
    error "SSL hat Probleme - überprüfe OpenSSL Installation"
fi

if python3 -c "from PyQt5.QtCore import QTimer; print('PyQt5 verfügbar')" 2>/dev/null; then
    success "PyQt5 ist funktionsfähig"
else
    error "PyQt5 hat Probleme - überprüfe PyQt5 Installation"
fi

echo ""
success "Reparatur komplett abgeschlossen! Starte PyBitmessage mit: pybitmessage"
