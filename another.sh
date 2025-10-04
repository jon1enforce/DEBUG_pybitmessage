# Untersuche die gefundenen Dateien im Detail
echo "=== API.py ==="
grep -n -A5 -B5 "pickle\|marshal\|yaml" pybitmessage/api.py

echo "=== knownnodes.py ==="  
grep -n -A5 -B5 "pickle\|marshal\|yaml" pybitmessage/network/knownnodes.py

echo "=== tests/core.py ==="
grep -n -A5 -B5 "pickle\|marshal\|yaml" pybitmessage/tests/core.py

# Prüfe ob unsafe Deserialisierung verwendet wird
grep -n "pickle.loads\|marshal.loads\|yaml.load(" pybitmessage/api.py pybitmessage/network/knownnodes.py pybitmessage/tests/core.py

# Prüfe die Import-Statements
grep -n "import pickle\|import marshal\|import yaml" pybitmessage/api.py pybitmessage/network/knownnodes.py pybitmessage/tests/core.py
