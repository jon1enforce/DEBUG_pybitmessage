#!/bin/sh
cd /home

wget "ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-4.1.0.tar.gz"
tar -xzf libressl-4.1.0.tar.gz
cd /home/libressl-4.1.0
mkdir -p build
cd build

# CMake mit SHARED Libraries
cmake .. \
  -DCMAKE_INSTALL_PREFIX=/home/install \
  -DBUILD_SHARED_LIBS=ON \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DCMAKE_C_FLAGS="-fPIC" \
  -DLIBRESSL_APPS=OFF \
  -DLIBRESSL_TESTS=OFF

# Dann kompilieren
make -j$(nproc)

# Installieren
make install
