#!/bin/sh

meson /tmp/ndff-build
cd /tmp/ndff-build
while find /opt/ndff -type f -name "*.c" -o -name "*.cpp" | xargs inotifywait --exclude '.*/\.git/.*' -e modify;
do
  ninja test
done
