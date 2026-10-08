# DoorPolicy

Rust PolkaVM contract for the ESP32 RFID/OLED door demo. The deploying caller
is the fixed admin. Only that admin may configure the public salt or grant and
revoke any of 11 HMAC-SHA256 key commitments. Salt changes clear every slot.

`setKey(index, digest)` sets one slot; zero revokes it. `configureSalt(salt)`
sets a nonzero 256-bit salt. `admin()` and `keyAt(index)` are read-only queries.
The bounded raw policy storage format and provisioning steps are documented in
`door-contract/README.md`. No pepper or raw UID belongs on-chain.

UID hashing provides on-chain privacy, not physical tag clone resistance.
