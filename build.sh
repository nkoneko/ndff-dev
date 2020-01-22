#!/bin/sh

meson /tmp/ndff-build
cd /tmp/ndff-build
ninja
ninja test
