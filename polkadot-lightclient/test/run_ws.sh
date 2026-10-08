#!/bin/sh
# Checks the WebSocket framing on the host. No board, no network, no libsodium:
# src/ws_frame.c deliberately knows nothing about sockets, so the whole of it
# can be driven from byte arrays. Runs in well under a second.
#
#   sh test/run_ws.sh
set -e
cd "$(dirname "$0")/.."
OUT=${TMPDIR:-/tmp}/lc_test_ws
gcc -std=gnu99 -Wall -Wextra -Wshadow -O1 -g \
    test/test_ws.c src/ws_frame.c \
    -o "$OUT"
exec "$OUT"
