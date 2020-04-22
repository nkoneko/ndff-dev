#!/bin/sh

if [ -f "/usr/local/lib/libndpi.so" ]; then
  :
else
  cd /opt/nDPI
  ./autogen.sh
  ./configure CFLAGS=-g
  make -j4
  make install
fi

cd /opt/ndff
meson /tmp/ndff-build
cd /tmp/ndff-build
while find /opt/ndff -type f -name "*.c" -o -name "*.cpp" | xargs inotifywait --exclude '.*/\.git/.*' -e modify;
do
  ninja test
done
