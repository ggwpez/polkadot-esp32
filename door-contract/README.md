# RFID door policy (Rust / PolkaVM)

For the portable project, vendored dependencies, and required toolchains, start
with the [door sensor README](../README.md). Historical setup notes below describe
the original workspace.

The current public Products app uses the separate
[Door Keys contract and UI](../door-app/README.md) to assign Alice or Bob
exclusively. This document describes the original admin-managed allowlist.

An admin-managed allowlist on **Paseo Asset Hub 1000**, consumed by the ESP32
light client in `../polkadot-lightclient`. Opening is an **OLED mock**: there is
no motor, relay or lock actuator output.

## Tooling and local secrets

The [developer quickstart](https://docs.polkadotcommunity.foundation/getting-started/developers/)
and [contract guide](https://docs.polkadotcommunity.foundation/guides/deploy-contracts-cdm/)
identify `@polkadot-community-foundation/cdm-cli` plus `cdm setup` for Rust
PolkaVM development. This project pins npm package **0.9.0** in `package-lock.json`
(its bundled CLI reports **0.13.1**), and the Rust SDK/compiler source revision
`ba2966a9e47f1503606754061af338d353f809bf`. Node 22+ is required; this run uses
Node 26.7.0. No Solidity source, solc, Hardhat, Foundry, pad or dotns is needed. The ABI uses Ethereum-compatible types, as required by revive.

For a new deployment, follow the [portable configuration checklist](../README.md#configure-your-own-deployment)
and supply your own account, salt, pepper and RFID tags. Personal addresses and
tag IDs below have been replaced with placeholders. Machine paths and operational
notes are historical; no original private environment is bundled.

`direnv` is optional. Export the variables in your own environment (or use
direnv with your own `.envrc`) before running the tools:

| Variable | Purpose |
|---|---|
| `DOOR_MNEMONIC` | New sr25519 deployment/admin signing key |
| `DOOR_ADMIN_ADDRESS` | `YOUR_ADMIN_ADDRESS` |
| `DOOR_SALT_HEX` | Public per-door salt, interpreted as a big-endian integer padded to 32 bytes |
| `DOOR_PEPPER_HEX` | Random 32-byte secret used by admin tooling and ESP32 |
| `TMPDIR` | Directory for scratch outputs, e.g. `.local-backups/door/tmp` |

Store the mnemonic, salt and pepper in a private, ignored file of your own.
The mnemonic is also cached in CDM's user-local `~/.cdm/accounts.json`; the
`status`/`deploy` commands restore that copy from the environment after a
restart. A different existing CDM account is rejected rather than overwritten.
Never put the mnemonic on the ESP32.

References, captured proofs, build logs and scratch files can live in an
ignored `.local-backups/door/` directory. Cargo and npm outputs stay in this
project; the compiler and other system installations can be restored with:

```sh
# From the door-sensor directory, on a Linux container with Node 22+, Rust/rustup,
# gcc, Python venv support and libsodium.so.23 available:
sh tools/setup.sh
.venv/bin/python door-contract/tools/door.py status
```

`setup.sh` creates a project venv with `substrate-interface==1.8.1` for
subsequent containers. `cdm setup` installs the Rust build tooling. The
successful build used Rust nightly 1.100.0 (`f7d782a3b`, 2026-08-19).

## Deploy and administer

Fund the admin SS58 above with PAS on
[Paseo Asset Hub 1000](https://faucet.polkadot.io/paseo?parachain=1000).
Every CDM chain command explicitly uses `-n devnet`. The scripts check the
Asset Hub genesis against `0xd6eec26135305a8ad257a20d003357284c8aa03d0bdb2b357ab0a22371e11ef2`.

Run these from the door-sensor directory with the project venv:

```sh
.venv/bin/python door-contract/tools/door.py deploy
.venv/bin/python door-contract/tools/door.py configure-salt
# Example initial policy: Alice allowed, Bob and Charlie denied.
.venv/bin/python door-contract/tools/door.py allow 0 Alice
.venv/bin/python door-contract/tools/door.py inspect
.venv/bin/python door-contract/tools/door.py provision
sh -c 'cd polkadot-lightclient && pio run -e esp32dev'
sh -c 'cd polkadot-lightclient && pio run -e esp32dev -t upload'
```

Direct `deploy` checks the account mapping, builds and checks the ABI, then
submits through `tools/submit.mjs` using PAPI 2.1.7 and the same devnet chain
descriptors as CDM. The Rust CLI currently cannot sign this runtime’s
`AuthorizeValueTransfer` extension, so it is used only for building, tests and
ABI encoding. Transactions are dry-run first and awaited through finalization.
The deployment address is recorded in `deployment.json`.
No registry or Bulletin authorization is required. For optional name/metadata
publishing, `deploy --register` uses CDM and requires a Bulletin storage grant.
Do not run `resolve` for a direct deployment; it resolves only registry entries.
Deployment refuses to run if `deployment.json` already exists.

Admin changes take effect once the ESP32 proves a new finalized policy:

```sh
# Bob becomes allowed in slot 1; Alice is revoked from slot 0.
.venv/bin/python door-contract/tools/door.py allow 1 Bob
.venv/bin/python door-contract/tools/door.py revoke 0
```

All 11 slots start empty. `setKey(index, digest)` grants or replaces one slot;
a zero digest revokes it. `configureSalt(salt)` changes the salt and clears all
slots. Both mutations require `caller == admin`; the admin is fixed to the
constructor caller. There is no upgrade, transfer-admin or external-call path.
Salt rotation requires re-enrollment but no firmware change. Pepper rotation
requires re-enrollment **and** provisioning/flashing the new pepper.

## Hash and storage format

Commitments are `HMAC-SHA256(pepper, "door-key:" || salt32 || uid_length_u8 || uid_bytes)`.
UIDs are canonical raw bytes (4, 7 or 10), not display strings. A public salt
alone cannot protect a short UID from guessing; the pepper stays off-chain.
This hides recognizable UIDs in contract storage, but **does not prevent
cloning a physical tag's UID**. The present MFRC522 flow reads UIDs without
authentication. Real clone resistance requires authenticated tags and a
challenge-response protocol. The pepper is also extractable from unprotected
ESP32 flash; the demo does not enable flash encryption or secure boot.

The policy is one 392-byte variable-key storage value (below the runtime’s
416-byte item limit):

| Byte offset | Encoding |
|---|---|
| 0 | `DOR1` (4 bytes) |
| 4 | Revision, u32 little-endian |
| 8 | Salt, 32 bytes |
| 40 | Eleven 32-byte HMAC commitments; all-zero means empty |

Logical key: ASCII `door.policy.v1`. On this revive runtime the variable-key
child-trie path is `blake2b-128(key) || key`. The admin is a separate 20-byte
value at logical key `door.admin.v1`. No tag UID or pepper enters the contract.

## What the ESP32 verifies

The existing GRANDPA → relay header → `Paras::Heads(1000)` proof obtains the
Asset Hub root. The firmware then proves `Timestamp::Now`, the contract's child
root under `:child_storage:default:<trie-id>`, and the entire policy under that
child root using `state_getChildReadProof`, all at the same Asset Hub block.
It replaces its in-memory allowlist only after the proofs and format pass.
An `eth_call`, enumeration result or event is never an admission decision.

Provisioning pins the deployment's child-trie identifier in ignored
`polkadot-lightclient/src/door.local.h`. The host tool checks the account-info
storage proof and compares its code hash with the local PolkaVM artifact before
writing that file. Initial deployment/child-ID provisioning is trusted, like
the existing manually provisioned GRANDPA checkpoint: the host does not itself
verify finality. Subsequent device reads use the complete light-client path.
Deployment to another address requires re-provisioning and re-flashing.

The OLED has three rows: sync freshness (`OK` / `STALE`), seconds since the last
successful policy sync and its relay block (`R`); the large OPEN/CLOSED state;
and an authorized key hash abbreviated as `1/2 abcdef..1234`. Multiple keys
rotate every three seconds. These are policy hashes, not owner names. Stale
policies show `no fresh policy` instead of authorized keys; public toggle mode
shows `public toggle`. Before the first successful sync the header reads
`SYNC waiting`. The relay block is omitted if the header would exceed 21 characters.

The device starts locked with no cached policy. A matched tag opens the OLED
mock for five seconds. The OLED shows “OPEN” or “CLOSED” with the corresponding
padlock symbol to the right. A denied tag blinks “CLOSED” every 300 ms for three seconds;
another denied scan restarts that timer, while an allowed scan clears it immediately.
Denied tags, policy changes, verification failures and
Wi-Fi loss close it. A policy expires after 120 seconds of **chain age**, and
replaying the same block cannot extend that deadline. Identical repeated proofs
retain the existing expiry time, as do newer blocks sharing a timestamp. Reboots discard the
allowlist. RFID/OLED runs on a separate FreeRTOS task so RPC stalls cannot
freeze the displayed unlock timer. No configured deployment means “CLOSED /
awaiting deployment”. Reader/OLED wiring remains as documented in the root README.

Freshness uses SNTP wall time initially and a monotonic timer thereafter. SNTP
is not authenticated; the demo assumes honest time provisioning. Proofs establish
state integrity, not the current time. Authority-set rotation still requires
refreshing the existing trusted checkpoint and reflashing; the device fails
closed when the checkpoint is stale. These are explicit demo limitations.

## Validation

```sh
sh -c 'cd door-contract && npm test'
.venv/bin/python door-contract/tools/test_tools.py
sh polkadot-lightclient/test/run_door.sh
sh -c 'cd polkadot-lightclient && sh test/run_devnet.sh && sh test/run_ws.sh'
```

Contract tests cover admin rejection, granting/revoking, salt rotation and bad
slot indices. Host tests cover policy freshness, replay, malformed values,
timer rollover and tampered/missing nodes in both trie legs, including the
392-byte hashed-value leaf. A live existing-contract child proof was also
verified with the **same C trie verifier used by the firmware** (captured
locally during validation). This is RPC/proof-path validation.
See [DEPLOYMENT.md](DEPLOYMENT.md) for the live deployment and hardware results.
