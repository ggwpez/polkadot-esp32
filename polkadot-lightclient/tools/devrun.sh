#!/bin/sh
# Build, flash and capture one benchmark environment in a single command.
#
#   tools/devrun.sh batchbench_o2q
#
# The RFC2217 bridge does not support monitor-driven modem-control reset, so the
# reset and the capture have to share one connection - which also means the
# board must not be reset again while this is reading. Stops on "=== done ===".
#
# Override the port with LC_PORT, and the read window with LC_TIMEOUT seconds.
set -e
cd "$(dirname "$0")/.."
ENV=${1:?usage: tools/devrun.sh <platformio-env>}
PORT=${LC_PORT:-rfc2217://host.internal:4000?ign_set_control}
WINDOW=${LC_TIMEOUT:-1500}

pio run -e "$ENV"
pio run -e "$ENV" -t upload --upload-port "$PORT"

# Use the bundled project's offline-installed pyserial by default.
: "${LC_PY:=../.venv/bin/python}"
if ! "$LC_PY" -c 'import serial' 2>/dev/null; then
    echo "devrun: run ../tools/setup.sh or set LC_PY to a Python with pyserial" >&2
    exit 1
fi

exec "$LC_PY" -u -c '
import serial, sys, time
port, window = sys.argv[1], float(sys.argv[2])
s = serial.serial_for_url(port, baudrate=115200, timeout=.5)
s.dtr = False; s.rts = True; time.sleep(.6); s.rts = False
end = time.time() + window
while time.time() < end:
    b = s.read(4096)
    if b:
        sys.stdout.buffer.write(b); sys.stdout.buffer.flush()
        if b"=== done ===" in b:
            break
s.close()
' "$PORT" "$WINDOW"
