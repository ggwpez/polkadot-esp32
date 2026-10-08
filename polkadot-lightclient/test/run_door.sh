#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p ../.local-backups/door/tmp
OUT=../.local-backups/door/tmp/test_door
gcc -std=c99 -Wall -Wextra -Werror -g -fsanitize=address,undefined \
    test/test_door.c src/door_policy.c -o "$OUT"
exec "$OUT"
