#!/usr/bin/env python3
"""Install the pinned Espressif emulator separately from vendored source deps."""
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main():
    release = json.loads((ROOT / "tools/qemu-release.json").read_text())
    arch = {"arm64": "aarch64", "AMD64": "x86_64"}.get(platform.machine(), platform.machine())
    system = {"Linux": "linux-gnu", "Darwin": "apple-darwin"}.get(platform.system())
    if not system:
        raise SystemExit("Installer supports Linux/macOS. See tools/qemu-release.json for other builds.")
    suffix = f"-{arch}-{system}.tar.xz"
    asset = next((a for a in release["assets"] if a["name"].endswith(suffix)), None)
    if not asset:
        raise SystemExit(f"No pinned QEMU build for {arch}-{system}")
    target = ROOT / ".tools"
    target.mkdir(exist_ok=True)
    binary = target / "qemu/bin/qemu-system-xtensa"
    if binary.exists():
        raise SystemExit(f"Already installed: {binary}. Remove .tools/qemu to reinstall.")
    print(f"Downloading Espressif QEMU {release['release']} ({arch}-{system})", flush=True)
    with tempfile.TemporaryDirectory(dir=target) as tmp:
        archive = Path(tmp) / asset["name"]
        urllib.request.urlretrieve(asset["url"], archive)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != asset["sha256"]:
            raise SystemExit("QEMU archive checksum mismatch")
        with tarfile.open(archive) as bundle:
            bundle.extractall(target, filter="data")
    print(f"Installed {binary}", flush=True)
    subprocess.run([str(binary), "--version"], check=True)


if __name__ == "__main__":
    main()
