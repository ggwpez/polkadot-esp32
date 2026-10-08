#!/bin/sh
set -eu
APP=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
npm ci --prefix "$APP/publish" --offline --ignore-scripts --no-audit --no-fund
