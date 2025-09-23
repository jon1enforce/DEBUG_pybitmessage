# DEBUG version of pybitmessage
source: https://github.com/kashikoibumi/PyBitmessage
# LIBRESSL instructions (PATCHED!)
look https://github.com/jon1enforce/libressl
mkdir build  
cd build  
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON  
make 
make install  
PATH:  
    
    ....libdir.append("/home/libressl-4.1.0/build/crypto/libcrypto.so")  
    ....libdir.append("/home/libressl-4.1.0/build/ssl/libssl.so")
    #command line
    start with:  
    sh py3start.sh 2>&1 | split -l 1000 - ~/log
