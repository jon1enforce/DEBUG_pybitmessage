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
whitelisted commands/message-types  
hardened protocol and sql  
+++  
compare with the source to see the changelog.  
+++  
References:  
https://www.cve.org/CVERecord?id=CVE-2018-1000070  
https://nvd.nist.gov/vuln/detail/CVE-2018-1000070
# LaTEX Bridge and Install:  
+++   setup   +++  
python3 setup.py build  
python3 setup.py install  
+++   start normal   +++  
sh py3start.sh  
+++   start Latex bridge  +++  
apt install texmaker  
sh py3start_bridge.sh  
