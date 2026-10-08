#!/bin/sh
# Same verifier and negative tests as mainnet, using the Products Devnet capture.
set -e
cd "$(dirname "$0")/.."
OUT=${TMPDIR:-/tmp}/lc_test_devnet
gcc -std=c99 -Wall -Wextra -Wshadow -O2 -g \
    -fsanitize=address,undefined \
    '-DLC_FIXTURE_HEADER="fixtures/devnet/fixtures.h"' \
    '-DLC_FIXTURE_DIR="test/fixtures/devnet"' \
    test/test_core.c src/scale.c src/trie.c src/grandpa.c src/lc_reader.c src/lc_crypto.c src/fmt.c \
    -l:libsodium.so.23 -o "$OUT"
exec "$OUT"
