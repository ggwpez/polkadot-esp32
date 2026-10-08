# Door demo deployment — 2026-09-05

Sanitized historical notes: account and contract addresses and transaction
identifiers below are placeholders. They cannot locate or operate the original
deployment. Create your own using the [configuration checklist](../README.md#configure-your-own-deployment).

Network: Paseo Asset Hub 1000 (`devnet`).

- Contract: `0x0000000000000000000000000000000000000000`
- Admin: `YOUR_ADMIN_ADDRESS`
- Finalized deployment transaction: `TRANSACTION_HASH_FROM_YOUR_DEPLOYMENT`
- Rust PolkaVM artifact: `target/release/door-policy.polkavm`, approximately 16 KB.
- Policy: 11 slots in a single 392-byte proven storage value.
- Direct deployment; no Bulletin or registry publication was needed.

The admin mnemonic and pepper were kept in a private, ignored local file.
Neither belongs in this document or in the published bundle.

The first dry-run rejected the original 552-byte policy because this runtime
limits storage items to 416 bytes. The policy was reduced before deployment.
The Rust CLI could dry-run but could not sign the runtime's additional
transaction extensions. `tools/submit.mjs` uses PAPI and CDM's devnet descriptors
for signing and waits for finalized execution; the contract remains Rust.

Local validation passed: three contract tests, two host tooling/proof tests,
policy admission/revocation/freshness/replay tests under sanitizers, and the
ESP32 firmware build. The existing light-client and WebSocket suites passed
68 and 31 checks respectively.

Initial policy was finalized at revision 2: slot 0 allows Alice; the other ten
slots are empty, so Bob and Charlie are denied. Salt configuration transaction:
`TRANSACTION_HASH_FROM_YOUR_DEPLOYMENT`.
Alice grant transaction:
`TRANSACTION_HASH_FROM_YOUR_DEPLOYMENT`.

Provisioning verified deployed code against the local artifact and verified
20 top-trie nodes plus 13 child-trie nodes with the firmware's C verifier.

Live timing checks found repeated parachain blocks in relay anchors and
different Asset Hub blocks sharing a timestamp. Both are accepted without
renewing the original monotonic expiry. The freshness budget is 120 seconds
of chain age; the screen stays locked until SNTP time is available. Regression
tests cover duplicate blocks, equal timestamps, changed bytes at the same
block, and expiry despite repeated proofs.

## ESP32 live validation

The firmware was flashed successfully to the existing ESP32. It detected the
SSD1306 at `0x3C` and the MFRC522 reader (`0xB2` version register), joined Wi-Fi,
and passed all 11 on-device finality/trie negative checks. Once SNTP initialized,
it continuously verified fresh contract policies through GRANDPA, the relay
header, `Paras::Heads(1000)`, and both contract trie legs. Observed chain ages
were approximately 36–58 seconds, with steady cycles around 1.5 seconds.

A temporary synthetic tag in slot 10 advanced the policy to revision 3 (two
allowed keys). Revoking it advanced the policy to revision 4 (one allowed key);
the ESP32 observed both revisions without another flash. The final policy
allows only Alice in slot 0. Bob and Charlie remain denied.

Grant transaction: `TRANSACTION_HASH_FROM_YOUR_DEPLOYMENT`.
Revocation transaction: `TRANSACTION_HASH_FROM_YOUR_DEPLOYMENT`.

```text
door: policy proven and fresh at Asset Hub #13085947, revision 3, 2 allowed keys, chain age 40000 ms
door: policy proven and fresh at Asset Hub #13085950, revision 4, 1 allowed keys, chain age 36000 ms
```

The raw serial capture was kept locally. Physical tag scans
and visual confirmation of the five-second OLED unlock have been requested
from the user and are not yet confirmed. Host tests cover the admission and
relocking logic; the live capture establishes contract synchronization.

Final capture: 28 accepted proof cycles, Asset Hub #13085929 through
#13085971. The serial connection was closed after capture; firmware remains
running. Final inspection independently confirmed revision 4 and active slot 0.
