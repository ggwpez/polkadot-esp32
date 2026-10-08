#!/usr/bin/env python3
"""Build and run ESP32 regression firmware locally, with networking disabled."""
import argparse
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
FIRMWARE = ROOT / "polkadot-lightclient"
PASS = b"QEMU_TESTS_PASSED"
FAIL = (b"QEMU_TESTS_FAILED", b"Guru Meditation", b"assert failed", b"abort() was called")


def executable(override, local, name):
    path = override or (str(local) if local.is_file() else shutil.which(name))
    if not path:
        raise SystemExit(f"Missing {name}; see README.md for toolchain setup")
    return path


def flash_image(build):
    # Matches the esp32dev bootloader and the checked-in partitions.csv.
    image = bytearray(b"\xff" * (4 * 1024 * 1024))
    for offset, name, limit in ((0x1000, "bootloader.bin", 0x8000),
                                (0x8000, "partitions.bin", 0x9000),
                                (0x10000, "firmware.bin", 0x310000)):
        data = (build / name).read_bytes()
        if offset + len(data) > limit:
            raise ValueError(f"{name} exceeds its flash region")
        image[offset:offset + len(data)] = data
    path = build / "qemu-flash.bin"
    path.write_bytes(image)
    return path


def simulate(qemu, flash, timeout, log):
    # Snapshot discards guest writes. No NIC, host filesystem passthrough,
    # cloud service, physical device or local credentials are used.
    command = [qemu, "-machine", "esp32", "-display", "none", "-monitor", "none",
               "-serial", "stdio", "-nic", "none", "-snapshot",
               "-drive", f"file={flash},if=mtd,format=raw"]
    with log.open("wb") as output, subprocess.Popen(
        # Keep stdin open: QEMU's stdio UART stops delivering output after EOF.
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE
    ) as process:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        tail = b""
        try:
            while time.monotonic() < deadline:
                if not selector.select(timeout=min(0.25, max(0, deadline - time.monotonic()))):
                    continue
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    raise RuntimeError("QEMU exited before the test completion marker")
                output.write(chunk)
                output.flush()
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
                tail = (tail + chunk)[-131072:]
                if any(marker in tail for marker in FAIL):
                    raise RuntimeError("ESP32 regression firmware failed")
                if PASS in tail:
                    return
            raise RuntimeError(f"QEMU exceeded {timeout:g}s without passing")
        finally:
            selector.close()
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-build", action="store_true", help="reuse the qemu environment build")
    parser.add_argument("--timeout", type=float, default=180, help="wall-clock limit in seconds")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    qemu = executable(os.environ.get("QEMU"), ROOT / ".tools/qemu/bin/qemu-system-xtensa", "qemu-system-xtensa")
    if not args.no_build:
        pio = executable(os.environ.get("PIO"), ROOT / ".venv/bin/pio", "pio")
        subprocess.run([pio, "run", "-d", str(FIRMWARE), "-e", "qemu"], check=True)
    build = FIRMWARE / ".pio/build/qemu"
    flash = flash_image(build)
    log = build / "qemu-serial.log"
    print(f"Running local QEMU; serial log: {log}", flush=True)
    simulate(qemu, flash, args.timeout, log)
    print("\nLocal ESP32 QEMU tests passed.")


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error))
