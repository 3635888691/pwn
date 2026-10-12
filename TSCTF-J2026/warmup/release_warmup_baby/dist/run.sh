#!/bin/sh
set -eu
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$DIR/lib/ld-linux-x86-64.so.2" --library-path "$DIR/lib" "$DIR/pwn" "$@"
