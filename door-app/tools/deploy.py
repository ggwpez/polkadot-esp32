#!/usr/bin/env python3
"""Publish with DOOR_MNEMONIC; never echo the signing key."""
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / 'door-app'
PAD = APP / 'publish/node_modules/.bin/pad'
mnemonic = os.environ.get('DOOR_MNEMONIC')
if not mnemonic:
    sys.exit('Set DOOR_MNEMONIC to your publishing account before deploying.')
if not PAD.exists():
    sys.exit('Install the publishing tools; see door-app/README.md.')
(ROOT / '.local-backups/door').mkdir(parents=True, exist_ok=True)
process = subprocess.Popen([str(PAD), str(APP / 'dist'), 'example-door.dot',
    '--env', 'devnet',
    '--js-merkle', '--mnemonic', mnemonic],
    cwd=APP, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
with (ROOT / '.local-backups/door/app-deploy.log').open('w') as log:
    for line in process.stdout:
        clean = line.replace(mnemonic, '[REDACTED]')
        log.write(clean)
        log.flush()
        print(clean, end='', flush=True)
sys.exit(process.wait())
