#!/bin/sh
# Builds and runs the host tests. Uses the system libsodium shared object
# directly: Debian ships the runtime without headers, and lc_crypto.c declares
# the two symbols it needs, so no -dev package is required.
set -e
cd "$(dirname "$0")/.."
OUT=${TMPDIR:-/tmp}/lc_test_core
gcc -std=c99 -Wall -Wextra -Wshadow -O2 -g \
    -fsanitize=address,undefined \
    test/test_core.c src/scale.c src/trie.c src/grandpa.c src/lc_reader.c src/lc_crypto.c src/fmt.c \
    -l:libsodium.so.23 -o "$OUT"
exec "$OUT"
