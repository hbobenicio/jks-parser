#!/bin/bash
set -eu -o pipefail

CC="${CC:-clang}"
PKG_CONFIG_DEPS="openssl"

CFLAGS+=" -std=c18 -Wall -Wextra -Wpedantic -Wno-vla -Wswitch-enum"
CFLAGS+=" -O0 -g -fsanitize=address,undefined -fno-omit-frame-pointer"
# CFLAGS+=" -O3 -march=native -flto=thin -D_FORTIFY_SOURCE=3"
CFLAGS+=" `pkg-config --cflags $PKG_CONFIG_DEPS`"

LIBS+=" `pkg-config --libs $PKG_CONFIG_DEPS`"

set -x
"$CC" $CFLAGS -o tests tests.c $LIBS
{ set +x; } 2> /dev/null
