# DEBUG version of pybitmessage
source: https://github.com/kashikoibumi/PyBitmessage
# LibreSSL PATCH!
look https://github.com/jon1enforce/libressl  
PATH:  
    elif sys.platform.startswith('openbsd'):  
        ....libdir.append("/home/libressl-4.1.0/build/crypto/libcrypto.so")  
        ....libdir.append("/home/libressl-4.1.0/build/ssl/libssl.so")
# Security PATCH!
json indead of pickle  
whitelist  
hardened protocol.py  
