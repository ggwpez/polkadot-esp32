# Door sensor

An RFID door demo built with an ESP32 and a Polkadot light client. Choose which
keys are allowed in the Door Keys web app, then scan a tag. The ESP32 verifies
the on-chain policy before showing the door as open for five seconds.

**This is a demo:** the door is shown on an OLED screen; no physical lock is
connected. RFID tag IDs can be cloned, so this is not a secure access system.

## What's inside

- [Firmware](polkadot-lightclient/README.md): ESP32 code and proof verification.
- [Contracts](door-contract/README.md): on-chain access rules and deployment tools.
- [Door Keys app](door-app/README.md): enable or disable Alice and Bob's keys.
- [Display demos](demos/README.md): render the OLED animation as a video.

## Build and test

Start with the [setup guide](SETUP.md) to install the toolchains and download
the locked dependencies. Setup uses local dependency archives, so a fresh clone
needs those downloads first. The documented Python setup targets Linux ARM64
with Python 3.11; see the guide for other hosts.

Once prepared, run from this directory:

```sh
sh tools/setup.sh
.venv/bin/pio run -d polkadot-lightclient -e esp32dev
npm --prefix door-app run build
(cd door-contract && CARGO_NET_OFFLINE=true npm run build)
sh tools/test.sh
```

With `just` installed, the same commands are available as `just setup`,
`just firmware`, `just app`, `just contract`, and `just test`.

To test firmware without a board, follow the [QEMU setup](SETUP.md#local-esp32-emulation-with-qemu).
To preview the screen, run `just render demos/door.jsonl` (requires a C++ compiler
and FFmpeg).

## Configure your own deployment

The checked-in addresses and tag IDs are placeholders. Follow the
[deployment checklist](SETUP.md#configure-your-own-deployment) to set your Wi-Fi,
enroll your tags, deploy a contract, and provision the device. Keep credentials
and generated firmware binaries private.

Hardware: ESP32, SSD1306 OLED, and MFRC522 RFID reader, all at 3.3 V.

| Module | Wiring (ESP32 GPIO) |
| --- | --- |
| SSD1306 | SDA 25, SCL 26 |
| MFRC522 | SS 5, SCK 18, MOSI 23, MISO 19, RST 22 |

The device starts closed and closes on invalid proofs, Wi-Fi loss, or an expired
policy. Live use needs network access and a current trusted checkpoint.
