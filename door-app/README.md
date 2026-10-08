# Door Keys

For the portable project, vendored dependencies, and required toolchains, start
with the [door sensor README](../README.md). Historical setup notes below describe
the original workspace.

`example-door.dot` and `https://door.example.invalid` are publication placeholders.
Replace them with your own domain and gateway URL using the
[deployment checklist](../README.md#configure-your-own-deployment). The operational
notes below describe the historical demo with identifying records removed, not a
deployment at that dummy URL. Deployment JSON and the app's contract address are
undeployed templates; deploy and sync your own contract before live use.

The Door Keys app has two selectable
buttons: **Alice** and **Bob**. Highlighted means Enabled; unselected means Disabled.
Click **Apply** to save both choices and confirm in your wallet. Neither, either,
or both keys can be enabled.
Anyone with a funded host wallet can change them. Charlie is always denied.

The app changes the lock's accepted key. It does not remotely open the door.
Scan an authorized physical tag to open the OLED door mock for five seconds.
There is no motor or lock actuator attached. The displayed assignment is
finalized chain state, not device telemetry.

## Contract and device

The Rust PolkaVM contract targets Paseo Asset Hub 1000, the Products devnet.
`0x0000000000000000000000000000000000000000` is an undeployed placeholder.
See [the contract deployment template](../door-contract/keys-deployment.json)
and [source](../door-contract/contracts/door-keys/lib.rs).

- `setKeyEnabled(0, true/false)` changes Alice; index 1 changes Bob. The other
  key's current chain state is preserved. Repeating the same setting is idempotent.
- `enabledKeys()` returns a bitmask: 0 = neither, 1 = Alice, 2 = Bob, 3 = both.
- The host CLI also supports `assignKey(0/1/2/3)` for Alice/Bob/Both/None, with
  `assignedKey()` returning that selection. Invalid indices are rejected.
- The constructor pins the public salt and two HMAC commitments. Alice starts
  assigned. The contract has no admin or salt/commitment mutation methods.
- One 392-byte `DOR1` policy at `door.policy.v1` contains one active
  commitment in slot 0 for a single key, or Alice in slot 0 and Bob in slot 1
  for Both. Neither has no active commitments. Switching clears unused slots and increments the revision.
- No UID, mnemonic or pepper enters the frontend. The host wallet signs the
  assignment. The existing pepper is provisioned only to the ESP32.

The ESP32 proves the policy through GRANDPA → relay header → Asset Hub →
contract child trie. It updates its accepted key only after proving the finalized
policy. Policy changes close an existing unlock. Invalid proofs, Wi-Fi loss,
and policy expiry after 120 seconds of chain age also close it. Scanning a denied
key blinks CLOSED. Physical RFID UIDs remain cloneable as described in the
[original door demo](../door-contract/README.md).

## Build and browser test

Node 22+ is required. From this directory:

```sh
npm ci
npm run build
```

`src/contract.ts` contains the public deployment and ABI. Regenerate after
changing contracts with `npm run sync-contract` (requires the Rust ABI in
`../door-contract/target/release/`).

The optional live test exercises all four combinations through the official test host,
then restores the original selection.
After each transaction it verifies the live storage proofs and runs the firmware's
C admission code against Alice, Bob and Charlie, including five-second relocking.
Run when nobody else is changing the assignment:

```sh
# From this directory, with DOOR_MNEMONIC exported in your environment:
npx playwright install --with-deps chromium
npm run test:live
```

Test-host pages contain the signing key. Do not enable Playwright traces or save
the host HTML. Only the locally served test host receives the key; the published
bundle contains neither mnemonic nor pepper. Another test checks reconnect/error
handling outside a Polkadot host.

## Publish

```sh
# From the door-sensor directory, after replacing the dummy domain:
sh door-app/tools/setup-publish.sh
# Export DOOR_MNEMONIC privately for the account that controls your domain.
python3 door-app/tools/deploy.py
```

After configuration, this publishes to Bulletin and updates your chosen name using
its owner account, explicitly targeting `devnet`. It also updates the icon and
app metadata. Logs: `.local-backups/door/app-deploy.log`.

The publishing tools have their own lockfile under `publish/`. Installed tools
stay in `door-app/publish/node_modules/`. PAPI is pinned to 2.1.7 because a loose
transitive dependency otherwise selects PAPI 3, whose removed `/signer` export
breaks the publisher. The script passes the signer explicitly: the original PAD 0.13.1's
`MNEMONIC` fallback incorrectly retains shared pool accounts for Bulletin.
`--js-merkle` avoids the optional native P2P build dependency.

References: [publishing guide](https://docs.polkadotcommunity.foundation/guides/build-and-publish/)
and [host SDK guide](https://docs.polkadotcommunity.foundation/guides/platform-services-sdk/).

The gateway's light client may fail to start in a headless browser. Its built-in
**Use Trusted Provider** option corresponds to
`https://door.example.invalid/?chainBackend=rpc-gateway`. This browser fallback
does not change the ESP32's independent proof verification.

## Provision and flash

```sh
# From the door-sensor directory, with DOOR_MNEMONIC exported:
.venv/bin/python door-contract/tools/door.py --keys inspect
.venv/bin/python door-contract/tools/door.py --keys provision
pio run -d polkadot-lightclient -e esp32dev -t upload
```

On the Mac, keep the serial bridge running:

```sh
esp_rfc2217_server -p 4000 /dev/cu.usbserial-0001
```

The firmware checkpoint was cross-checked with Dwellir and Turboflakes on
2026-09-09: set 262 at relay #989052,
`0xefd90f545fac6f258654dc388b676601a6aa3c37aeaa629f6563eee01f23dca0`.
It needs refreshing again after an authority-set rotation; follow
`polkadot-lightclient/docs/DEVNET.md`.

For host-side operation:

```sh
.venv/bin/python door-contract/tools/door.py --keys enable Bob
.venv/bin/python door-contract/tools/door.py --keys disable Alice
.venv/bin/python door-contract/tools/door.py --keys assign None
.venv/bin/python door-contract/tools/door.py --keys assign Both
.venv/bin/python door-contract/tools/door.py --keys assign Bob
.venv/bin/python door-contract/tools/door.py --keys assign Alice
```

The former exclusive-key deployment is retained in
[`keys-exclusive-deployment.json`](../door-contract/keys-exclusive-deployment.json).
The earlier Both-capable contract is retained in
[`keys-both-deployment.json`](../door-contract/keys-both-deployment.json).
Neither is upgradeable; the app and ESP32 now use the independent-toggle contract above.

The original admin-managed RFID contract and the earlier remote-toggle experiment
are separate deployments, retained for reference. They do not control a device
provisioned to this key-assignment contract.

## Validation on 2026-09-07

- Six Rust tests passed across the contracts, including switching the exclusive
  key from different callers, idempotency and invalid-key rejection.
- The app's live host-wallet test assigned Bob and then Alice. After each
  finalized transaction, the host verified both trie-proof legs and ran the
  firmware's C admission code on Alice, Bob and Charlie. Only the selected
  digest was admitted; five-second relocking passed. The outside-host test passed.
- Firmware flashed successfully over RFC2217, with the flash hash verified.
  SSD1306 and MFRC522 were detected; all 11 device self-tests passed.
- Serial confirmed revision 0 (Alice) at Asset Hub #13129184, revision 1 (Bob)
  at #13129190, and revision 2 (Alice) at #13129205. Every accepted policy held
  exactly one key and passed the device's finality, trie and freshness checks.
- Evidence: `.local-backups/door/device-keys.log`,
  `.local-backups/door/door-keys-proof.json`, and
  `.local-backups/door/keys-before.png`. These checks establish device policy
  synchronization; the automated admission tests supply tag digests in software.
- Version 1.1.0 is published at the existing name, with the new icon and
  metadata. The public gateway loaded the key selector without the RPC fallback
  and showed Alice assigned at revision 2, finalized block #13129271.
  See [deployment.json](deployment.json) for the CID and transactions.
- No physical tag scans were captured in this run. The serial connection was
  closed after verification; firmware remains running with Alice assigned.

## Both-key update — 2026-09-08

The replacement contract supports Alice (0), Bob (1), and Both (2), using the
same ABI methods and 392-byte policy format. Version 1.2.0 adds the Both option
to the web app. The ESP32 is provisioned to the replacement contract; its
existing multi-slot admission and rotating hash display support both tags.

Seven Rust tests passed, including all nine selection transitions and
idempotency. The firmware admission suite covers both-key admission, an unknown
key, five-second relocking, expiry, and immediate revocation when narrowing the
policy. Two host tooling/proof tests passed. The production app build passed.
Browser acceptance testing is left to the user.

Live proof checks confirmed Alice-only, Bob-only, and Both policies using the
actual firmware C admission code. The physical ESP32 accepted revision 1 with
two keys at Asset Hub #13146910, Bob-only revision 2 at #13146946, and restored
Alice-only revision 3 at #13146961. Version 1.2.0 is published at the existing
name, with its content and metadata verified on chain. Serial evidence is in
`.local-backups/door/device-both.log`. Physical tag scans remain a manual check.

## Independent toggles — 2026-09-08

Version 1.3.0 replaces the selector and submit button with two pressed-state
buttons. Clicking Alice or Bob submits `setKeyEnabled` for that key only, with
wallet confirmation. All four combinations are supported, including no keys.
Buttons show finalized state and an Updating indicator while a change is pending.

Eight Rust tests passed, covering all sixteen selection transitions, independent
per-key updates, idempotency, and invalid indices. The ESP32 admission suite and
production app build passed. Live contract proof checks exercised None, Bob,
Both, and Alice through the same per-key setter used by the app. Browser and
physical tag testing are left to the user.

The ESP32 confirmed Both at Asset Hub #13147069 and restored Alice-only at
#13147077 (revision 4). Version 1.3.0 content and metadata were published and
verified on chain. See `deployment.json` and `.local-backups/door/device-toggles.log`.


## Select and Apply — 2026-09-08

Version 1.4.0 uses plain highlighted Alice and Bob buttons with an Apply button.
Clicks only edit the local selection. Apply submits one `assignKey` transaction
for the complete selection, including neither key. Background refreshes preserve
unsaved selections, and rejected transactions leave the selection available to retry.
The “Currently applied” summary shows finalized contract state.

The production TypeScript/Vite build passed. Browser acceptance testing is left
to the user. This release uses the existing contract and ESP32 policy format.
Version 1.4.0 was published successfully; content and executable metadata were
verified on chain. Publication details are in `deployment.json`.

## Wallet progress — 2026-09-08

Version 1.4.1 checks the host's ChainSubmit permission before submitting and
observes the wallet signTx call directly. The SDK's `signing` status is emitted
only after a signed transaction is returned, so it cannot announce a pending
confirmation. Setup and key-selection transactions now report wallet waiting,
signature received, and chain progress separately; errors retain the last step.
A wallet reply arriving after the Apply request has expired is rejected locally.

The TypeScript/Vite build passed. An isolated mock harness exercised successful
Apply, denied permission (no signing), and timeout with a late wallet response.
The user's missing confirmation popup has not yet been reproduced; the update
provides accurate diagnostics, not a verified fix for the host wallet behavior.
Browser and wallet acceptance testing remain with the user.

Version 1.4.1 published successfully; content and executable metadata were verified
on chain. Publication details are in `deployment.json`.

## Gateway signing compatibility — 2026-09-08

Version 1.4.2 pins product-sdk 0.17.0, matching the host/signer package versions
used by paritytech/playground-app-template. The previous SDK 0.27.0 brought
TruAPI 0.13.1, whose product-account selector encodes the derivation index as a
tagged value. The dotli gateway source pins host-api 0.8.6, which decodes that
field as plain u32. Chain/identity permission requests can work while the
transaction payload is incompatible. This release uses TruAPI 0.3.2's matching
format and adapts to the older contract SDK's throwing transaction API.

The explicit HostProvider configuration skips the unused identity/name request
and requests ChainSubmit once, on Apply. Product identity remains example-door.dot;
the checked network genesis remains d6eec261…71e11ef2. SmartContractAllowance from
the community example targets its PGAS environment and was not copied into this
Paseo Asset Hub demo.

`npm run test:protocol` compares app-encoded signing bytes against the gateway's
exact host-api 0.8.6 decoder and encoder, asserting signer, genesis, call data,
extensions and extrinsic version. It passes, as do the production build and
isolated Apply success/permission-denial/late-signature checks. Browser signing
acceptance is still left to the user. The live browser fixture was aligned to
host-api-test-sdk 0.11.0 (0.8 protocol) and was not run.

References:
- https://github.com/paritytech/playground-app-template/blob/main/src/utils.ts
- https://github.com/paritytech/playground-app-community/blob/main/src/utils/contracts.ts
- https://github.com/paritytech/dotli/blob/main/packages/ui/package.json

Reproduction: encoding the same test transaction with the previous TruAPI
0.13.1 selector (`{tag: 'Index', value: 0}`) and decoding it with host-api 0.8.6
throws `Offset is outside the bounds of the DataView`. The replacement encoding
passes the exact byte comparison. This reproduces the protocol failure without
a wallet, browser, or signed transaction.

Version 1.4.2 published successfully; content and executable metadata were verified
on chain. See `deployment.json` for publication details.

## Funding address and footer — 2026-09-08

Version 1.5.0 shows the connected app wallet's SS58 funding address with a Copy
button and identifies Paseo Asset Hub / PAS as the funding network. Account
connection runs separately from chain reads and does not request identity or
signing permissions. Apply reuses the same selected account shown for funding.
The address clears when the signer session loses its selected account; a Connect
wallet action is available when signed out. Clipboard failure selects the address
for manual copying.

Removed the Hardware Lab branding, marketing eyebrow, and OLED demo footer.
The footer always displays the app version beside the contract address; detailed
policy revision and finalized block remain expandable. Vite injects the version
from the deployment manifest config, avoiding a second manually maintained value.

The TypeScript/Vite production build and gateway protocol regression test passed.
Browser testing remains with the user.

Version 1.5.0 published successfully; content and executable metadata were verified
on chain. Publication details are in `deployment.json`.

## Patch publication and DotNS migration — 2026-09-09

Version 1.5.1 bumps the displayed and executable version. The existing door
contract address has been removed; configure your own deployment.

The live dev-dot.li gateway moved to DotNS registry
`0x38cf3dE5877a18157f4C1a4e067F84956F582b31` and content resolver
`0x444578659848ba38D1825238f10B8D75522d278f`. The pinned publisher's bundled
address book still targeted the earlier registry and resolver, so its first
successful publication did not update the gateway's records.
`tools/deploy.py` now passes `publish/devnet-environment.json` to override these
two addresses. They were checked against the live gateway's network bundle;
the migrated name's ownership and previous content were confirmed by the
publisher preflight. This override covers publishing the existing name.

The production build and wallet-protocol regression check passed. See
`deployment.json` for final publication and browser verification details.

Publication in the migrated resolver completed and was verified on chain. A fresh
headless browser through the gateway RPC fallback displayed v1.5.1, Bob enabled,
and the expected door contract address. Wallet signing was not tested.

## Wallet connection recovery — 2026-09-09

Version 1.5.2 disables selected-account persistence: Door Keys has one product
account, and awaiting host local-storage reads can otherwise leave the SDK in
`connecting` after the host has already returned the account. A regression test
reproduces this stall with the pinned SDK and an unanswered storage read.

Wallet connection now has a 20-second deadline. Failure restores Connect wallet
and releases Apply; retry creates a fresh manager. Late replies from expired
attempts cannot update the displayed account or supply a signer. Page teardown
cancels the pending connection. This fixes the reproduced storage-wait path and
bounds other unanswered connection calls; the user's exact host session was
not available for diagnosis.

Validation: production build, gateway signing-protocol regression, five wallet
connection tests (`npm run test:wallet`), and a Playwright account-connection
test using a public development account all passed. The browser test only
connects and checks the funding address; it does not sign transactions.

Version 1.5.2 was published and verified on chain and in the live gateway. The
unauthenticated gateway returned a host account rejection with Connect wallet
enabled; successful account connection was verified in the official test host.
The user’s signed-in gateway session and transaction signing remain unverified.

## Current wallet protocol — 2026-09-09

Version 1.5.3 upgrades product-sdk to 0.27.0 (TruAPI 0.13.1) and the test host
to 0.12.1 (host-api 0.9.1). The live dev-dot.li gateway now reports TruAPI
0.13.1 and encodes product account selectors as `Index(u32) | Raw(bytes32)`.
The SDK 0.17.0 pin used the former plain-u32 format. Its account request fails
to decode with the current host codec; this is reproduced in `test:protocol`.
The earlier SDK downgrade matched the previous gateway, not the migrated one.

Protocol tests now check both account lookup and transaction signing against
independent host-api 0.9.1 codecs, including the rejection of the old account
payload. The product ID remains `example-door.dot`, index 0; account lookup has
no chain field. Transactions still target the pinned Paseo Asset Hub genesis
`d6eec261…71e11ef2`, also present in the live gateway network configuration.
The newer SDK includes the current iframe/MessagePort handshake. Contract
transaction handling now unwraps its Result API and preserves SDK errors.

Production build, three protocol tests, five wallet lifecycle tests, browser
account connection and browser silent-host timeout/retry tests passed.
The user's native phone wallet session has not been directly inspected.
The storage-wait avoidance and timeout recovery from 1.5.2 remain in place.


The [September devnet announcement](https://docs.polkadotcommunity.foundation/updates/2026-09-devnet-update/)
was checked against this release. Publishing dependencies are now pinned to
`@polkadot-community-foundation/polkadot-app-deploy` 0.16.1 and
`@polkadot-community-foundation/dotns-cli` 0.9.1; the temporary environment
file used during the initial migration recovery was removed. The updated
publisher's bundled registry/resolver addresses match the live gateway.
Chain descriptors are pinned to 0.11.0 in the app and contract tooling.
CDM CLI was already 0.9.0; cdm-env is now explicitly pinned to 2.3.0 with the
current contract registry. This direct-deployment project has no cdm.json
registry pin or installed CDM dependencies to migrate.

The finalized v1.5.3 publication was verified in a fresh mobile-sized gateway
browser: it showed Bob enabled and a sign-in message for the unauthenticated
wallet, with Connect wallet enabled. Account lookup no longer produced the
old protocol decoding rejection. Native phone signing still needs validation.
