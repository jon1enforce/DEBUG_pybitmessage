# Auf unsichere Deserialisierung prüfen
grep -r "pickle.loads" pybitmessage/
grep -r "marshal.loads" pybitmessage/
grep -r "yaml.load" pybitmessage/
grep -r "eval(" pybitmessage/
grep -r "exec(" pybitmessage/

# Auf unsichere Netzwerk-APIs prüfen
grep -r "socket." pybitmessage/
grep -r "subprocess" pybitmessage/
grep -r "os.system" pybitmessage/
