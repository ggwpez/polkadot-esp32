# Products Devnet bring-up — 2026-09-05

Target: prove `System::Number` on Paseo Asset Hub (para 1000), using the existing
GRANDPA → relay header → `Paras::Heads(1000)` → Asset Hub storage proof path.
Contract deployment and RFID admission policy are the next milestone.

## Network identification

The [Products Devnet network reference](https://docs.polkadotcommunity.foundation/reference/networks/)
selects Paseo Asset Hub 1000, not Asset Hub Next 1500. Contracts use pallet-revive.
The Ethereum RPC is a separate service; it is unnecessary for this storage proof.

| Role | Selected endpoint | Cross-check endpoint |
|---|---|---|
| Relay HTTPS/WSS | `paseo-rpc.n.dwellir.com/` | `paseo-v2.rpc.turboflakes.io/` |
| Asset Hub HTTPS | `asset-hub-paseo-rpc.n.dwellir.com/` | `sys.turboflakes.io/asset-hub-paseo` |

Relay genesis: `0x374057be67b355151f271ff70c3db98308c62c8adc48dc6724b6a009a1a014fd`.
Asset Hub genesis: `0xd6eec26135305a8ad257a20d003357284c8aa03d0bdb2b357ab0a22371e11ef2`.
Both providers agreed on each genesis, finalized hash and height in the preflight.
The Asset Hub `ParachainInfo::ParachainId` value was 1000. All four endpoints
accepted certificate-verified TLS 1.2. Both relay WSS subscriptions worked.
See [the captured preflight report](devnet-preflight-2026-09-05.json).

Other documented endpoints: Stakeworld returned HTTP 403 from this environment;
the Ethereum RPC `paseo-assethub-rpc.laissez-faire.trade` failed certificate
validation due to expiry. Neither is selected. Interweb's relay answered with
the same genesis but was not needed for subsequent proof checks.

## Reproduce the checks

Host tooling needs Python with `xxhash`, `cryptography`, `websocket-client` and
`pyserial`; here that is the `pio` virtualenv's `python`.
Core host tests need GCC and `libsodium23` (installed for this run).
Commands below run from `polkadot-lightclient/` with that Python environment.

```sh
python tools/check_devnet.py
python tools/gen_fixtures.py --relay https://paseo-rpc.n.dwellir.com --hub https://asset-hub-paseo-rpc.n.dwellir.com --out test/fixtures/devnet
sh test/run_devnet.sh
sh test/run.sh
python tools/gen_checkpoint.py --endpoint https://paseo-rpc.n.dwellir.com --check-endpoint https://paseo-v2.rpc.turboflakes.io --expected-genesis 0x374057be67b355151f271ff70c3db98308c62c8adc48dc6724b6a009a1a014fd
sh test/run_pre.sh
pio run -e esp32dev
```

Preflight is an RPC consistency/compatibility check. The C tests subsequently
verify signatures and both Merkle proofs, including negative cases. Mainnet
fixtures remain intact; devnet captures live in their own subdirectory.
The captured devnet proof finalized relay #931893 and proved Asset Hub #13084621.
Both core suites passed 68 checks each. The authority-table suite passed 8 checks.

The trusted authority snapshot was independently compared at two providers:
relay #931898, hash `0xde6c78d164e981bc2f70cf9c7ca2e3de23d10dc8d96b07b46a6ee8496803ee9d`,
set 246, 56 authorities, threshold 38. This remains a manually provisioned trust
root; agreement between providers does not make its provisioning trustless.
Authority rotation still requires a fresh checked checkpoint and reflash.

## Firmware

`src/network.h` selects the endpoints and PAS units. The OLED headline shows
the proven block number. `src/checkpoint*` must move with the network selection.
Wi-Fi settings are in ignored `src/wifi.local.h`; copy the example for a new clone.

Initial source baseline: Git commit `5d87506`. That history includes an RFID
project and an original mainnet light client, neither of which is part of this
bundle.

## On-device validation

The upload completed with flash hash verification on the inventory ESP32
(MAC anonymized as `02:00:00:00:00:01`). Firmware build used 1,073,717 bytes of the 3 MiB app
partition. The SSD1306 was detected at 0x3C. Wi-Fi joined on its second attempt
after the access point temporarily refused the first association.

The first cycle verified 38/38 signatures against the 56-authority set,
bound relay #932017, and proved `System::Number = 13084807` on Asset Hub.
The device's 11 negative/self-checks all passed. Subsequent cycles proved
advancing Asset Hub state; the full verification path ran on the ESP32.

```text
finality: #932,019, 38/38 signatures, weight 38/56 in 395 ms
header bound: 327 bytes hash to the finalized block
Paras::Heads(1000) proven from 6 nodes -> Asset Hub #13,084,810
System::Number          = 13,084,810
Timestamp::Now          = 1,788,620,316,000
Balances::TotalIssuance = 876.53M PAS  (876,534,785.8893205628)
consistency: AH block number matches the relay-proven header: yes
cycle took 1,175 ms, heap 90,860 free (largest block 49,140), stack headroom 7,660
```

Final capture: 23 successful cycles, Asset Hub 13,084,807 through 13,084,840; steady-cycle median 1177 ms.
The [serial proof-cycle capture](devnet-device-2026-09-05.txt) excludes local Wi-Fi details.
No verification errors occurred; closing the capture leaves the firmware running.

Source checkpoints: `5d87506` baseline; `a2bfd98` preflight and verified fixtures;
`723ec61` devnet firmware configuration. WebSocket framing also passed 31 host
checks. That capture records the state-read milestone before RFID admission
was added.

## Contract-backed door milestone

The Rust [door policy](../../door-contract/README.md) is deployed on this same
Asset Hub. Firmware now proves its child-trie root and policy bytes, checks
chain age, and uses the resulting allowlist for RFID admission on the OLED.
An unverified contract-call response cannot authorize a tag.

See the [deployment record](../../door-contract/DEPLOYMENT.md) for the address,
transactions and hardware results.

## Sync recovery — 2026-09-09

The board connected and received finalized heads but rejected every signature
with checkpoint set 258. Dwellir and Turboflakes both reported current set 262.
Refreshed the checkpoint and precomputed tables at relay #989052,
`0xefd90f545fac6f258654dc388b676601a6aa3c37aeaa629f6563eee01f23dca0`,
with the generator's genesis check and second-provider snapshot comparison.

The eight authority-table tests and ESP32 build passed. Uploaded through the
RFC2217 bridge at 115200 baud and verified the flashed board using set 262:
11 on-device self-tests passed, successive relay blocks finalized, and the
contract policy was proven fresh at Asset Hub #13166180 and later blocks,
revision 6, one enabled key (Bob per the host's verified contract read).
Observed policy ages were 29–49 seconds during the initial successful cycles.
The initial Wi-Fi association was refused, but its automatic retry connected.

No contract, app publication, or door provisioning change was required.
Authority rotation still requires checkpoint refresh and reflash.
