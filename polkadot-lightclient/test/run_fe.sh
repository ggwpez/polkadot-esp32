#!/bin/sh
# Checks the fe25519_mul generator's term table against ref10, on the host.
#
#   sh test/run_fe.sh
#
# Needs no board and no libsodium: it generates the model from
# tools/gen_fe25519_mul.py and compares it with the vendored ref10 header.
set -e
cd "$(dirname "$0")/.."
OUT=${TMPDIR:-/tmp}/lc_test_fe_model
MODEL=${TMPDIR:-/tmp}/lc_fe_model.c

python3 tools/gen_fe25519_mul.py --c > "$MODEL"
# -Wno-unused-function: the ref10 header brings in every fe25519_* helper as a
# static and this file calls one of them.
gcc -std=gnu99 -Wall -Wextra -O2 -Wno-unused-function \
    -Ilib/ed25519_fast/src \
    test/test_fe_model.c "$MODEL" -o "$OUT"
exec "$OUT"
