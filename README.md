# DEBUG version of pybitmessage
source: https://github.com/kashikoibumi/PyBitmessage
# OpenBSD instructions
look https://github.com/jon1enforce/libressl-2.5.0  
PATH:  
    elif sys.platform.startswith('openbsd'):  
        ....libdir.append("/home/libressl-2.5.0/build/crypto/libcrypto.so")  
        ....libdir.append("/home/libressl-2.5.0/build/ssl/libssl.so")
# NOTE
now the main branch is stable by default for linux  
openbsd is test -branch! Not stable now.
