#!/bin/sh
# Checks the precomputed authority tables on the host.
#
# Needs no libsodium and no board: ref10 is vendored in lib/ed25519_fast and
# test/host/ supplies the few libsodium symbols it calls, so the reference and
# the candidate are both built from source here. Takes a few seconds, most of
# it compiling the 1.3 MB generated table.
#
#   sh test/run_pre.sh
set -e
cd "$(dirname "$0")/.."
OUT=${TMPDIR:-/tmp}/lc_test_precomp
# -DLC_ED25519_PRECOMP is what makes src/checkpoint_precomp.c non-empty; it is
# the same flag env:esp32dev builds the firmware with.
# -Wno-unused-function: the ref10 headers bring in every fe25519_* helper as a
# static, most of which any one file does not call.
gcc -std=gnu99 -Wall -Wextra -Wshadow -O1 -g \
    -Wno-unused-function \
    -DLC_ED25519_PRECOMP \
    -Itest/fixtures -Ilib/ed25519_fast/src \
    test/test_precomp.c src/checkpoint_precomp.c \
    lib/ed25519_fast/src/ed25519_fast.c \
    test/host/sodium_shim.c test/host/ref_verify.c \
    -o "$OUT"
exec "$OUT"
