#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"
for test in run_door run_ws run run_devnet run_ed run_pre run_fe; do
    sh "polkadot-lightclient/test/$test.sh"
done
.venv/bin/python door-contract/tools/test_tools.py
python3 -m unittest discover -s polkadot-lightclient/tools/render -p 'test_*.py'
npm --prefix door-app run test:protocol
npm --prefix door-app run test:wallet
(cd door-contract && CARGO_NET_OFFLINE=true npm test)
