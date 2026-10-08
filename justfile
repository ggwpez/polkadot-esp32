set positional-arguments
set working-directory := "."

setup:
    sh tools/setup.sh

firmware:
    .venv/bin/pio run -d polkadot-lightclient -e esp32dev

app:
    npm --prefix door-app run build

contract:
    cd door-contract && CARGO_NET_OFFLINE=true npm run build

test:
    sh tools/test.sh

# Install the pinned local emulator (toolchain download, once per machine).
qemu-install:
    python3 tools/install-qemu.py

# Build and run the ESP32 verifier and door-policy regressions without networking.
qemu *args:
    python3 "{{justfile_directory()}}/tools/qemu.py" "$@"

render instructions *args:
    python3 "{{justfile_directory()}}/polkadot-lightclient/tools/render/render.py" "$@"
