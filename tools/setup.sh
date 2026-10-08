#!/bin/sh
# Offline dependency installation; toolchains are prerequisites (see README).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
: "${PYTHON:=python3.11}"
"$PYTHON" -m venv .venv
.venv/bin/python -m pip install --no-index --find-links vendor/python --require-hashes -r requirements.lock
for project in door-app door-contract door-app/publish; do
    npm ci --prefix "$project" --offline --ignore-scripts --no-audit --no-fund
done
printf '%s\n' 'Dependencies ready. See README.md for toolchains and build commands.'
