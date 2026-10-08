#!/bin/sh
# Builds and runs the ed25519 batch-verification tests on the host.
#
# Needs no libsodium and no board: the ref10 code is vendored in
# lib/ed25519_fast and test/host/ supplies the handful of libsodium symbols it
# calls. Under a second, which is the whole point.
#
# Tunables can be overridden from the environment, e.g.
#   W=7 CHUNK=256 sh test/run_ed.sh
set -e
cd "$(dirname "$0")/.."
OUT=${TMPDIR:-/tmp}/lc_test_ed25519
: "${W:=6}"
: "${CHUNK:=128}"
# -Wno-unused-function: including the ref10 headers pulls in every fe25519_*
# helper as a static, most of which any one file does not call.
# The two remaining -Wshadow reports are upstream ref10's own, left alone so the
# vendored files stay byte-identical to the release they came from.
gcc -std=gnu99 -Wall -Wextra -Wshadow -O2 -g \
    -Wno-unused-function \
    -DLC_BATCH_W="$W" -DLC_BATCH_CHUNK="$CHUNK" \
    -Itest/fixtures -Ilib/ed25519_fast/src \
    test/test_ed25519.c lib/ed25519_fast/src/ed25519_fast.c \
    test/host/sodium_shim.c test/host/ref_verify.c \
    -o "$OUT"
exec "$OUT"
