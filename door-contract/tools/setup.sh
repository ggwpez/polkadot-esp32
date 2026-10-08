#!/bin/sh
# Install application dependencies from the project-local, locked bundle.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
exec sh "$ROOT/tools/setup.sh"
