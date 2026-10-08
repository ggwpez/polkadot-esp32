# Polkadot light client on ESP32

Verify on-chain state directly on an ESP32 microcontroller. The light client
checks GRANDPA finality signatures and follows storage proofs from the relay
chain to Asset Hub, so it can verify values without trusting the RPC server.
It starts from a trusted checkpoint, which must be refreshed when the authority
set changes. The included configuration targets Paseo Asset Hub (Products devnet).

An RFID door demo shows what you can build with it: a web app sets the allowed
keys in a smart contract, and the ESP32 verifies that policy before accepting a
tag. The door is displayed on an OLED screen; no physical lock is connected.

## What's inside

- [Light client](polkadot-lightclient/README.md): ESP32 firmware, finality verification, and storage proofs.
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
sh tools/test.sh

# Optional: build the door demo's app and contract
npm --prefix door-app run build
(cd door-contract && CARGO_NET_OFFLINE=true npm run build)
```

With `just` installed, the same commands are available as `just setup`,
`just firmware`, `just app`, `just contract`, and `just test`.

To test firmware without a board, follow the [QEMU setup](SETUP.md#local-esp32-emulation-with-qemu).
To preview the screen, run `just render demos/door.jsonl` (requires a C++ compiler
and FFmpeg).

## Configure your own deployment

To run the RFID door example, use the hardware below. The checked-in contract
addresses and tag IDs are placeholders. Follow the
[deployment checklist](SETUP.md#configure-your-own-deployment) to set your Wi-Fi,
enroll your tags, deploy a contract, and provision the device. Keep credentials
and generated firmware binaries private.

Hardware: ESP32, SSD1306 OLED, and MFRC522 RFID reader, all at 3.3 V.

| Module | Wiring (ESP32 GPIO) |
| --- | --- |
| SSD1306 | SDA 25, SCL 26 |
| MFRC522 | SS 5, SCK 18, MOSI 23, MISO 19, RST 22 |

The demo closes on invalid proofs, Wi-Fi loss, or an expired policy. RFID tag
IDs can be cloned, so this example is not a secure access system.
