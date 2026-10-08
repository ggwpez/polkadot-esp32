# Door sensor

Self-contained source project for the proof-verified RFID door demo. Copy this
whole directory to work independently of the hardware repository. It includes
the ESP32 firmware and full Polkadot light client, Rust contracts, Door Keys web
app, publishing/admin tools, display renderer, captured proofs, and lockfiles
with scripts to vendor their dependencies. The device currently opens an OLED
mock; it has no lock actuator.

## Layout

- `polkadot-lightclient/`: firmware, verifier, checkpoints, host tests and renderer.
- `door-contract/`: contracts, deployment records and administration tools.
- `door-app/`: web app and publishing tools.
- `demos/`: display timelines.
- `vendor/`, `door-contract/vendor/`: vendored dependency trees, generated
  locally by the setup and refresh steps below and not tracked by git.
- `vendor/npm-sources.json`: upstream URLs for the npm archives in the locks.
- `polkadot-lightclient/lib/`: ref10, MFRC522 1.4.12, SSD1306 2.5.17,
  Adafruit GFX 1.12.6 and BusIO 1.17.4, with upstream license files.

Inside the generated `vendor/` tree: `vendor/npm-tarballs/` holds the exact npm
archives for all three package locks, including optional platform packages, and
lock entries reference these local files; `vendor/python/` holds hash-locked
Python distributions, including PlatformIO Core. Native wheels target **Linux
aarch64, CPython 3.11**; other hosts need matching wheels built/downloaded for
the versions in `requirements.lock` and new hashes. `door-contract/vendor/` is
the complete Cargo.lock source closure, including the git SDK, and
`.cargo/config.toml` replaces registry/git sources with that directory.

Upstream source URLs for npm archives are retained in `vendor/npm-sources.json`;
licenses and source files remain inside the original package archives. Cargo
records checksums per crate. Python hashes are in `requirements.lock`.

## Toolchains (not bundled)

Install these separately before building. Offline dependency installation does
not imply that a machine without compilers can build offline.

| Component | Required tooling |
| --- | --- |
| Web app and npm tooling | Node.js 22+ (validated with 26.7.0), npm |
| Python tooling | CPython 3.11 with venv/pip; bundled native wheels require Linux ARM64 |
| ESP32 | PlatformIO Core 6.1.19, Espressif32 7.0.1, Arduino-ESP32 package `3.20017.241212+sha.dcc1105b`, Xtensa GCC `8.4.0+2021r2-patch5`, esptool package `2.41100.0` |
| Rust contracts | rustup, `nightly-2026-08-20` with rust-src/rustfmt, cargo-pvm-contract from revision `ba2966a9e47f1503606754061af338d353f809bf` |
| Host C tests | GCC with ASan/UBSan; external libsodium dependency described below |
| Display rendering | C++ compiler; FFmpeg for MP4 output |

**External library dependency:** the host C tests and Python proof-verification
tool link to the system `libsodium.so.23`. This library is not bundled or pinned
by the project; it is a runtime dependency in addition to the toolchain. On a
Debian-based host, install it with `sudo apt-get install libsodium23`. The host
link commands use Linux's `-l:libsodium.so.23`; other operating systems need
their equivalent library and adjusted linker flags. Firmware uses the libsodium
library in the pinned Arduino-ESP32 framework instead.

PlatformIO installs its pinned platform, framework and compiler packages on first
build if they are absent. Provision those toolchain packages before disconnecting
from the network. `cargo-pvm-contract` and its compiler tools must likewise be
installed separately. This bundle does not include browser binaries for live
Playwright tests. Chain queries, provisioning, checkpoint refresh and deployment
still require network access.

## Install and build

From this directory, on the supported Python host:

```sh
sh tools/setup.sh                 # hash-checked Python + npm archives from vendor/
.venv/bin/pio run -d polkadot-lightclient -e esp32dev
npm --prefix door-app run build
(cd door-contract && CARGO_NET_OFFLINE=true npm run build)
sh tools/test.sh                  # verifier, policy, renderer, app and Rust regressions
```

`just setup`, `just firmware`, `just app`, `just contract`, `just test` and
`just render demos/door.jsonl` provide shortcuts. Rust commands must run inside
`door-contract` so Cargo loads its source replacement configuration. On a fresh
clone, generate the vendored trees first (see "Dependency updates" below); a
missing vendored dependency fails the offline install rather than falling back
to a registry.

The firmware can build with the example Wi-Fi values and an unconfigured, closed
door. For a live device, copy `polkadot-lightclient/src/wifi.local.h.example` to
`wifi.local.h` beside it and set credentials. Provision `door.local.h` using the
contract tools. Both local headers are ignored. Supply deployment/admin secrets
through your environment; they are not part of the portable source bundle.
Deployment JSON files are undeployed templates with zero contract addresses.
Checkpoints are public captured chain data, not fresh chain state. Refresh the
trusted checkpoint when its authority set expires.

The SSD1306 uses SDA GPIO25/SCL GPIO26. The MFRC522 uses SS GPIO5, SCK GPIO18,
MOSI GPIO23, MISO GPIO19 and RST GPIO22. Both run at 3.3 V.

See [firmware details](polkadot-lightclient/README.md),
[contract operations](door-contract/README.md), [app details](door-app/README.md)
and [display timelines](demos/README.md). Older operational logs in those files
refer to the original workspace; use the setup commands above for this bundle.

## Configure your own deployment

Offline builds and regression tests do not require live credentials. Before
running your own device or publishing the app, adjust the following:

- **Wi-Fi:** copy `polkadot-lightclient/src/wifi.local.h.example` to
  `wifi.local.h` and set your SSID/password. The local headers in this working
  copy have been reset to the examples; `door.local.h` has `DOOR_CONFIGURED 0`
  and a zero pepper, so the door remains unconfigured.
- **Signing account:** export your own `DOOR_MNEMONIC` and matching
  `DOOR_ADMIN_ADDRESS`, and fund that account on the selected network. Set
  `DOOR_SALT_HEX` to your public per-door salt and `DOOR_PEPPER_HEX` to a new
  random 32-byte secret encoded as 64 hexadecimal characters. Keep these in
  your private environment; no `.envrc` is bundled or required.
- **RFID tags:** replace the synthetic `NAMED` UID mapping in
  `door-contract/tools/door.py` with your Alice/Bob/Charlie tags before deploying
  the key contract. Update the corresponding canonicalization test in
  `door-contract/tools/test_tools.py` if you change that mapping. The bundled
  tag IDs are placeholders, not enrolled physical tags. Public proof captures
  remain unchanged so offline cryptographic checks remain reproducible.
- **Contract and device:** from this directory, run
  `.venv/bin/python door-contract/tools/door.py --keys deploy`, then
  `.venv/bin/python door-contract/tools/door.py --keys provision`. Deployment
  updates `door-contract/keys-deployment.json`; provisioning writes your private
  `door.local.h`. Run `npm --prefix door-app run sync-contract`, rebuild the app
  and firmware, and flash the device. Existing deployment JSON and
  `door-app/src/contract.ts` contain zero-address placeholders until replaced.
  The app and administration tools reject that placeholder for live operations.
- **Network and trust:** the tools and app target the Products devnet/Paseo Asset
  Hub. Check RPC endpoints, genesis checks, the selected SDK network and firmware
  `src/network.h`. Refresh the trusted checkpoint with the firmware tools when
  required; a different network also requires matching contract deployments and
  trust configuration. Captured fixtures are for offline tests.
- **Publishing identity:** `example-door.dot` is a dummy name. Replace it
  consistently in `door-app/polkadot-app-deploy.config.ts`, `door-app/src/wallet.ts`,
  `door-app/tools/deploy.py`, and the wallet/browser test expectations. Use a name
  controlled by your publishing account. Replace `https://door.example.invalid`
  in `door-app/tools/check-gateway.mjs` with your real gateway URL. Update
  `door-app/deployment.json` with your resulting publication record; it is an
  unpublished template. Contract package names use the dummy `@example/` scope
  in `door-contract/contracts/*/Cargo.toml` and `door-contract/tools/door.py`;
  replace that scope consistently before registry publication.
- **Hardware and host:** adjust wiring and `polkadot-lightclient/platformio.ini`
  upload/monitor ports. The default RFC2217 bridge at `host.internal:4000` is an
  example, not a prerequisite. Provision the documented toolchains and system
  libsodium; use the Python wheel workflow below for a different host.

Publish a source-only export that respects `.gitignore`. Vendored dependency
trees are regenerated from the lockfiles; keep `.env*`, `wifi.local.h`,
`door.local.h`, `.local-backups/`, toolchain directories and build outputs out
of the release. Provisioned firmware can contain Wi-Fi credentials and the
pepper, so do not publish those binaries. The local headers stay ignored even
after being reset to harmless placeholders.

Personal account/contract addresses, physical tag IDs, the device MAC address,
deployment transaction hashes and publication CIDs have been removed or replaced
with clearly marked examples. Historical operational notes retain their technical
observations but no longer identify an actual deployment. Network genesis hashes,
shared protocol addresses, checkpoints and captured proof fixtures remain real
public network data; they are required for the existing verification tests.

## Recreating Python wheels

`vendor/python/` is not tracked. On a fresh clone, recreate it before the offline
setup so that `tools/setup.sh` can install from local wheels. On the documented
Linux ARM64 / CPython 3.11 host, download the exact hash-locked wheels into a
separate directory for review:

```sh
python3.11 -m pip download --only-binary=:all: --require-hashes \
  -r requirements.lock --dest .local-backups/python-wheels
```

For another host, use that host's Python and create a version-only requirements
file, then download or build matching wheels (this step requires network access):

```sh
mkdir -p .local-backups
sed 's/ --hash=.*//' requirements.lock > .local-backups/python-versions.txt
python3 -m pip wheel -r .local-backups/python-versions.txt \
  --wheel-dir .local-backups/python-wheels
python3 -m pip hash .local-backups/python-wheels/*.whl
```

Use a fresh wheel directory for each host. Source builds may need additional C
or Rust compilers, system headers and build dependencies; some packages may not
support your host. Version pins alone do not guarantee byte-identical rebuilt
wheels. Review the resulting wheels, copy them into `vendor/python/`, and add
their SHA-256 hashes to the corresponding version entries in `requirements.lock`
(keep existing hashes if supporting both hosts). Then validate offline setup
with `PYTHON=python3 sh tools/setup.sh` on the new host. Do not remove hash checks
from the normal setup script. Regeneration is an online maintenance operation;
normal installation uses only the reviewed, bundled artifacts.

## Local ESP32 emulation with QEMU

Run the ESP32 regression image locally, including inside an Apple container
(Linux ARM64). The emulator is a native process: no Docker, cloud account, API
token or device is involved. The runner disables networking with `-nic none`.

Install Espressif's QEMU fork once, separately from the source dependencies:

```sh
# Debian/Ubuntu runtime libraries (install once):
sudo apt-get install libgcrypt20 libglib2.0-0 libpixman-1-0 libsdl2-2.0-0 libslirp0
python3 tools/install-qemu.py       # or: just qemu-install
python3 tools/qemu.py               # or: just qemu
```

On macOS, install `libgcrypt glib pixman sdl2 libslirp` with Homebrew instead.
The installer selects Linux/macOS ARM64 or x86_64, verifies the archive's SHA-256
from `tools/qemu-release.json`, and installs release
`esp-develop-9.2.2-20260417` under ignored `.tools/qemu/`. Only installation needs
a download. With the PlatformIO toolchain already installed, the test run uses
local source, libraries and captured fixtures. Set `QEMU` or `PIO` to use your own
executables instead. See [Espressif's QEMU guide](https://github.com/espressif/esp-toolchain-docs/blob/main/qemu/esp32/README.md).

The `qemu` PlatformIO environment builds a dedicated regression entry point
against the real firmware's C verifier, fast ed25519 implementation, Arduino
framework's libsodium, and door-policy code. It embeds the checked-in devnet
proofs in flash, reuses the existing tests, and runs them as Xtensa machine code
under the ESP32 ROM, bootloader and FreeRTOS:

- 68 verifier/formatting checks: GRANDPA signatures, header binding, relay and
  Asset Hub trie proofs, wrong authority set, signature/proof tampering and
  malformed encodings. The signature-pool cases use the existing test pool;
  they do not exercise the production FreeRTOS signature worker.
- Door-policy assertions: allowed/denied scans represented by digests, relocking,
  stale and replayed policies, malformed values, public toggle and timer rollover.

The runner creates a disposable 4 MiB flash image, captures output in
`polkadot-lightclient/.pio/build/qemu/qemu-serial.log`, and exits successfully only
on `QEMU_TESTS_PASSED`. Panic, failed assertions, early exit and timeout fail the
command. Guest flash writes are discarded. Assertions stay enabled in this
release build. Use `python3 tools/qemu.py --no-build` to rerun, or `--timeout 60`
to change the wall-clock deadline (default 180 seconds).

**This is firmware regression testing, not a complete virtual door.** It does
not run the production Wi-Fi/RPC loop, physical MFRC522 driver, SSD1306 driver,
or live checkpoint. No local credential headers are compiled into this target.
QEMU's documented ESP32 networking uses OpenETH and would need a separate
transport setup for live-chain integration. Keep using `sh tools/test.sh` for
host sanitizers and the larger WebSocket tests, and `just render demos/door.jsonl`
for an OLED animation preview. Hardware behavior and real-time performance
still require a physical board.

Validated in the Linux ARM64 container: 68/68 core checks and all door-policy
assertions passed in QEMU; a forced short deadline returned a failing exit code.

## Dependency updates

The vendored trees are not tracked. Generate them once after cloning, then
update them deliberately and review the lockfiles. Refresh Cargo sources from
`door-contract` with the pinned Rust toolchain, including the standard library
dependencies used by build-std:

```sh
cargo vendor --locked --sync "$(rustc --print sysroot)/lib/rustlib/src/rust/library/Cargo.toml" vendor
```

Preserve the generated replacement configuration in `.cargo/config.toml`.
After updating npm locks, run `python3 tools/vendor-npm.py` from any directory.
It downloads every resolved archive, verifies its integrity, records the upstream
URL and changes lock entries to relative archive paths. Existing archives are
reused after verification. This refresh operation needs network for new packages.
Python updates need every transitive wheel plus a version and SHA-256 entry in
`requirements.lock`. Keep upstream licenses with all vendored dependencies.
