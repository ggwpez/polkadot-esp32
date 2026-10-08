# Polkadot Light Client on ESP32 — Plan

Read Asset Hub on-chain state on the ESP32 without trusting any RPC node.

**Status:** **M1 complete and running on hardware** (2026-08-28). The device verifies GRANDPA
finality, binds the header, walks both trie proofs, and prints proven Asset Hub values as the
chain finalizes them, while showing progress on an SSD1306 panel.
Signature verification runs on both cores (§11), which took the refresh from ~25 s to ~16 s;
held-open connections (§12) took it to ~5.9 s, precomputing each authority's point table
into flash (EXPERIMENTS.md E11) to ~5.3 s, and subscribing to finalized heads over a WebSocket
(§14) to **~4.96 s** — the device now follows the head block by block instead of sampling it on
a timer. 79 host tests, 31 of them on the WebSocket framing, and 11 on-device negative tests pass.
See §10 for measured results.

---

## 1. Why we are writing our own

| Client | Language | Verdict |
|---|---|---|
| [smoldot](https://github.com/smol-dot/smoldot) | Rust | **No.** Embeds a WASM interpreter to execute chain runtimes; heap is tens of MB. Built for browsers, not MCUs. |
| [ComposableFi/beefy-client](https://github.com/ComposableFi/composable-ibc) | Rust `no_std` | Right size, **wrong data** — needs MMR leaf proofs. |
| [octopus-network/beefy-light-client](https://github.com/octopus-network/beefy-light-client) | Rust `no_std` | Same blocker. |

BEEFY is the textbook answer for constrained devices — sampled secp256k1 signatures instead of 401
ed25519. It was ruled out on **data availability, not on hardware**: `mmr_generateProof` returns
`LeafNotFound` on every public endpoint tested (`rpc.polkadot.io`, OnFinality), re-checked 2026-08-31 and
still failing. MMR leaves live in each node's *offchain* DB, which public nodes do not populate. Using
BEEFY would mean running our own relay node — defeating the point.

**It would also not be the speed-up it looks like** (EXPERIMENTS.md E12, measured). secp256k1 is not
cheaper than ed25519 by any margin that survives being ported to Xtensa, and BEEFY adds a ~10-node Merkle
proof per checked signature because the validator set arrives as a root rather than a list. The saving is
entirely in *how many* signatures get checked, and that argument — check `m` at random, a forgery survives
with probability 2^-m — needs nothing from BEEFY: it applies to the GRANDPA justification the device
already downloads, and would take a cycle from ~4.96 s to **~1.8 s at m=80**. It is held back for the same
reason the batch verifier is (§ASSEMBLY.md: the accepted set must not change), not for want of a protocol.
BEEFY finality also trails GRANDPA by 1–6 blocks, so it buys speed against staler data.

The one part of BEEFY with no substitute is the MMR leaf's `beefy_next_authority_set`, which would let the
device follow set rotation from a proof instead of a reflash — an operational fix, not a performance one.

Revisit BEEFY only if we ever run our own relay node with `--enable-offchain-indexing true`.

---

## 2. The verified path

```
   GRANDPA justification (401 ed25519 sigs, 53 KB)
        │  verify against authority set
        ▼
   finalized relay block hash
        │  blake2b(re-encoded header) == hash
        ▼
   relay state_root  ── trie proof ──▶  Paras::Heads(1000)
                                              │
                                              ▼
                                    Asset Hub header ──▶ AH state_root
                                                              │  trie proof
                                                              ▼
                                                       any Asset Hub value
```

Proven live: relay #32755009 → Asset Hub #19992396 → `TotalIssuance = 1,700,157,912.23 DOT`,
with `System::Number` proven from AH state matching the header number proven from the relay chain.

---

## 3. Measurements (on this board, not estimates)

Board: ESP32-D0WDQ6 rev v1.0, 240 MHz, 4 MB flash, **no PSRAM**.

| Quantity | Measured |
|---|---|
| ed25519 verify | **18.7 ms** → 401 sigs = **7.5 s** |
| blake2b-256 | 0.30 ms per 256 B node → ~12 ms per storage proof |
| Heap free after Wi-Fi | 257 KB (largest contiguous block 110 KB) |
| TLS 1.2 handshake | 2.0 s, costs ~46 KB heap |
| HTTPS throughput | 15.6 KB/s → 59 KB proof ≈ 4 s |
| Concurrent TCP peers | 11 held, ~1.4 KB heap each (`LWIP_MAX_SOCKETS`=16) |

Protocol facts, measured live: 600 authorities, `set_id`=3585, threshold 401 weight,
justification 53,507 B, `Paras::Heads` proof 7 nodes / 2,075 B, AH storage proof 9 nodes / 1,446 B (3 keys).

### GRANDPA signed payload — confirmed, 401/401 verified

```
01 ‖ target_hash(32) ‖ target_number(u32 LE) ‖ round(u64 LE) ‖ set_id(u64 LE)   = 53 bytes
```

Variant byte `01` = `Message::Precommit`. Negative control with `set_id+1` verified 0/20.
This was the highest silent-failure risk in the project and it is now settled.

---

## 4. M1 scope — IN  ✅ delivered

**Goal: one trustless read, printed to serial, refreshed on a timer.**
All eight items below are implemented and verified on the board; §10 has the numbers.

1. **Transport — RPC over TLS 1.2**, behind an interface (`fetch_finality_proof`, `fetch_read_proof`,
   `fetch_header`) so M2 can swap in libp2p without touching verification code.
   Endpoints: `rpc-polkadot.luckyfriday.io` (relay), `rpc-asset-hub-polkadot.luckyfriday.io` (Asset
   Hub) — chosen on latency in §12, and TLS 1.2 because this framework's mbedTLS has nothing newer.
2. **SCALE decoding** — compact ints, `Vec<u8>`, headers, digest items.
3. **GRANDPA justification verification** — stream-parse precommits, verify each against the
   authority set, accumulate weight, require `> 2/3`. Reject duplicate signers.
4. **Header binding** — re-encode the header and require `blake2b(header) == commit target hash`.
   Deliberately ignores which block we *asked* for; we trust only what the justification commits to.
5. **Trie v1 proof verification** — full node codec incl. hashed-value leaves/branches (state v1
   stores values >32 B by hash). Must reject: wrong root, tampered node, dropped node, forged value.
6. **Two-hop state read** — relay `Paras::Heads(1000)` → Asset Hub header → AH storage key.
7. **Trust root** — authority set + block hash **hardcoded in flash** (weak subjectivity).
8. **Output** — serial. Verified value plus the relay/AH block numbers it was proven against.

Plus one item pulled forward from M3 on request: the SSD1306 status display (§8, §10).

### Decisions taken

These were defaulted so work could start, and are now settled by the built firmware:

- **Stack: C99 core, C++ only at the edges.** The original default was "C++/Arduino as-is", but the
  host has no C++ compiler and does have a C one. Writing the verification core (`scale`, `trie`,
  `grandpa`, `lc_reader`, `lc_crypto`) as allocation-free C99 means *the same source* builds for the
  ESP32 and for host tests against the system libsodium. That turned out to matter more than the
  language choice: it is what made 40 negative tests cheap to write and instant to run.
- **Values: chain vitals** (`System::Number`, `Timestamp::Now`, `Balances::TotalIssuance`) — needs
  no input from anyone and exercises the whole pipeline. An account balance needs an SS58 address.
- **Trust root: checkpoint only**, no authority-set-change tracking (see Risks). The device says so
  explicitly when the set has rotated, rather than failing obscurely.

---

## 5. M1 scope — OUT

Explicitly not in M1, so scope does not drift:

- **libp2p** — Noise XX, Yamux, multistream-select, Kademlia, WebSocket framing. → **M2**
- **BEEFY / MMR** — blocked on data availability; not planned.
- **`votes_ancestries` handling** — M1 counts only precommits whose target *is* the commit target.
  See Risks; fail-closed, not unsafe.
- **Authority set change tracking** (`ScheduledChange` / `ForcedChange` digests). → **M2**
- ~~**SSD1306 display output.** → **M3**~~ — pulled forward and delivered; see §10.
- **Warp sync / sync from genesis** — infeasible (thousands of set changes × 401 sigs).
- **Runtime calls / WASM execution** — this is why smoldot does not fit. Storage reads only.
- **Submitting transactions.** Read-only device.
- **Multi-provider failover / freshness cross-checking.** → M2

---

## 6. Budgets

**RAM.** Do not buffer the 53 KB justification. Stream-parse it: each precommit is a fixed 132 B
record (hash 32, number 4, sig 64, id 32), verified and discarded. Peak working set:

```
authority set   600 × 32 B  = 19.2 KB   (flash, or RAM if copied)
TLS session                 ≈ 46   KB
streaming buffer            ≈  4   KB
trie proof (largest seen)   ≈  2.1 KB
                            ─────────
                            ≈ 72   KB   against 257 KB free
```

**Flash.** Settled and verified on hardware (`partitions.csv`):

```
factory    app/factory     0x10000  0x310000   3072K   single app slot, no OTA
coredump   data/coredump    0x9000   0x10000     28K
nvs        data/nvs       0x310000  0x320000     64K   authority set + checkpoint
storage    data/spiffs    0x320000  0x400000    896K
```

No OTA: the board is flashed over USB, and what goes stale is the authority set,
which is *data*. A 19,200-byte set was written to NVS and verified byte-for-byte
identical across three reboots, consuming 608 of 2016 entries. The stock 20K nvs
holds ~630 entries, so it would have been full with no room for metadata - that
is why nvs is 64K.

**Trap:** the app must stay at 0x10000. PlatformIO takes the flash offset from
`board.get("upload.offset_address", "0x10000")`, *not* from the partition CSV.
An app placed elsewhere in the table gets written to 0x10000 anyway; the
bootloader then finds garbage and boot-loops emitting no output at all, because
the second-stage bootloader never gets far enough to log. Diagnosed by dumping
flash and looking for the `e9` image magic.

**Stack.** The Arduino loop task's default 8 KB is not enough and this was found the hard way:
adding 132 bytes to a local struct tripped the stack canary mid-TLS-handshake, which presents as a
`Guru Meditation Error` at the first RPC call and looks nothing like a stack problem. mbedTLS plus
the verification code peaks near **9.7 KB**, so `main.cpp` sets the loop stack to 16 KB with
`SET_LOOP_TASK_STACK_SIZE` and prints `uxTaskGetStackHighWaterMark` every cycle to keep the real
margin visible rather than assumed.

**Time per anchor refresh.** Measured **~29 s**, against a ~14 s estimate. The gap is not crypto:
signature verification is interleaved with the TLS reads that feed it, so the justification step
costs ~15 s wall-clock for ~7.5 s of ed25519 work. Streaming trades latency for RAM, and that is
the right trade here — buffering 53 KB to save 7 seconds would spend a quarter of the free heap.
Section 11 measures the other way out of the gap: keep the streaming and move the ed25519 off
the reading core.

---

## 7. Risks

| Risk | Impact | Mitigation |
|---|---|---|
| **Authority set rotates each era (~24 h)** | Checkpoint goes stale; device stops verifying | M1 accepts it and fails closed: on zero valid signatures it prints "the authority set has rotated - regenerate checkpoint.h". M2 tracks `ScheduledChange`. Still the single biggest limit on leaving the device running. |
| **Strict vote matching** rejects a valid justification | Liveness, fail-closed | Log how often precommit targets differ from the commit target; add ancestry walking in M2 if it bites. |
| **TLS 1.2 endpoints disappear** | Cannot reach any provider | `rpc.polkadot.io` is already TLS 1.3-only. Escape hatch is `framework = espidf` with `CONFIG_MBEDTLS_SSL_PROTO_TLS1_3=y` — Arduino's *precompiled* mbedTLS cannot be reconfigured at any version. |
| ~~Flash exhaustion~~ | — | **Closed.** Custom partition table gives a 3 MB app slot; the finished M1 firmware uses 972 KB (30.9%). |
| Header of a session-boundary block is ~24 KB | Refresh fails on those blocks | The block that schedules an authority set change carries the whole next set in its digest. The header buffer is 32 KB so these decode normally instead of failing a few times a day. |
| Provider serves stale-but-valid data | Device shows old values as current | Bound staleness using the proven `Timestamp::Now`; refuse anything older than N minutes. Real fix is M2 (multiple sources). |
| Heap fragmentation | Large allocs fail over time | Largest block measured stable at 110,580 B across every cycle. All large buffers are static, so the allocator is never asked for a big block at runtime. |

**Threat model note.** M1 gives **soundness**: a hostile RPC cannot make the device display a wrong
value — forged proofs are rejected (verified by tamper tests). M1 does **not** give liveness or
censorship-resistance: a provider can refuse to answer or serve stale-but-valid data. That is the
gap M2 closes.

---

## 8. Firmware layout

As built:

```
polkadot-lightclient/
  PLAN.md  README.md  platformio.ini  partitions.csv
  src/
    main.cpp             wifi, timer loop, serial output, on-device self-tests   [C++]
    bench.cpp            core-affinity benchmark over the shipped path (section 11) [C++]
    transport.h/.cpp     TLS + JSON-RPC + streaming hex          [C++, swap point for M2]
    prefetch.h/.cpp      reader task + ring, so the socket drains during crypto   [C++]
    sigpool.h/.cpp       the second core, behind grandpa_sig_pool                 [C++]
    ui.h/.cpp            optional SSD1306 status display                          [C++]
    fmt.h/.c             thousands separators + the panel's short form
    lc_crypto.h/.c       blake2b-256 + ed25519 via libsodium
    lc_reader.h/.c       pull-based byte source (stream or memory)
    scale.h/.c           compact ints, vectors, header + digest decoding
    grandpa.h/.c         localized_payload, streaming precommit verification
    trie.h/.c            v1 node codec + proof walk
    checkpoint.h         GENERATED authority set, set_id, storage keys
  test/
    test_core.c          68 host tests against captured mainnet data
    run.sh               gcc + system libsodium, ASan + UBSan
    fixtures/            GENERATED from live Polkadot
  tools/
    gen_checkpoint.py    dump current authority set -> src/checkpoint.h
    gen_fixtures.py      capture live data -> test/fixtures/
```

The five core files are allocation-free C99 and build unchanged on both targets.
`lc_reader` is what makes that work: the GRANDPA verifier pulls bytes through an interface
that is TLS on the device and memory in the tests, so the tested code is the shipped code.

---

## 9. Definition of done for M1 — all met

- ✅ Device boots, joins Wi-Fi, and on a timer prints a verified Asset Hub value with the relay and
  Asset Hub block numbers it was proven against.
- ✅ Verification is **fail-closed**: bad signature, insufficient weight, header-hash mismatch and
  broken trie proof each print a specific error and show no value.
- ✅ On-device negative tests pass (8/8), run each boot against data that just came off the wire.
- ✅ Values match the reference pipeline, and Asset Hub's own `System::Number` matches the header
  number proven independently from the relay chain — checked every cycle, printed every cycle.
- ✅ Flash and heap headroom recorded — §10.
- ✅ Sync progress and proven values readable on the display without a serial console, with the
  screen marked `STALE` whenever the numbers on it stop being current.

---

## 10. M1 results, measured on the board

Firmware built 2026-08-28, soaked over consecutive refresh cycles against live mainnet.

| | Measured | Budgeted |
|---|---|---|
| Flash | **1,614,225 B, 51.3%** of the 3 MB app slot | 3 MB, no pressure |
| Static RAM | 98,476 B (30.1% of 327,680) | mostly the 32 KB header + 2× 8 KB proof buffers |
| Heap free, idle after Wi-Fi | 191,296 B | — |
| Heap free, steady state | **94,820 B**, constant across cycles | was 185,208 B before §12 held both TLS sessions open |
| Largest contiguous block | 49,140 B, unchanged every cycle | no fragmentation; 110,580 B before §12 |
| Loop task stack peak | ~8.8 KB of 16 KB (headroom 7,660 B) | default 8 KB was **not** enough |
| Full refresh | **24–29 s** single-core; 16.1–17.4 s after §11; 5.81–5.89 s since §12; 5.30–5.35 s with the precomputed authority tables; **4.97–5.01 s** since §14 dropped the head lookup | ~14 s estimated |
| — justification verify | ~15 s single-core; 6.27–6.44 s after §11; 4.55–4.70 s since §12; **3.95–4.00 s** with the tables | 7.5 s of pure ed25519 |
| Signatures per justification | 401–409 of 600, threshold 401 | GRANDPA stops at the threshold |
| Paras::Heads proof | 7 nodes | 2,075 B |
| Asset Hub proof | 9 nodes, 3 keys | 1,446 B |

Heap over five cycles: 190,212 → 189,320 → 189,196 → 189,180 → 189,180. The early drop is
one-time allocator settling, not a leak; it converges and stays there. Adding the display moved
every figure by a fixed, one-time amount and changed none of the shapes: +36 KB flash (Adafruit
GFX + SSD1306), +792 B static, ‑3,972 B heap (the 1 KB framebuffer plus the I2C and GFX objects),
‑32 B of stack headroom, and no measurable change to cycle time — the ~25 repaints per cycle cost
about 25 ms each at 400 kHz, well under 3% of a refresh.

**The display.** An SSD1306 128×64 on I2C, pulled forward from M3. It is a window onto the serial
log with no authority of its own: no `ui_*` call gates verification, and with no panel on the bus
every one is a no-op, so an unplugged screen cannot change what the device does. Two rules shaped
it. Only proven values appear — a number reaches the screen after the signatures, the header hash,
both Merkle proofs, the block-number cross-check and the self-test have all held. And a stale
screen has to look stale: a panel frozen on last hour's block is worse than a blank one, so the
header flips `PROVEN` → `STALE` the moment a refresh fails, carrying the age of the anchor.

Verifying a layout without being in the room needed its own tool. Overflow on a 21-column panel is
silent — a line one character too long is simply clipped — so text that does not fit is now cut
with a visible `~`, and `-DUI_DUMP_FRAMES=N` prints the first N distinct frames to serial as ASCII
art. That dump immediately found two strings one and two characters too long, a Wi-Fi signal meter
that showed full strength at every RSSI (a two-pixel-wide `drawRect` outline is solid), and a
wasted frame painting an empty body. None of the three would have been visible in the source, and
the first two would have looked like working features on the panel.

**What was actually hard.** Not the cryptography — that was measured up front and behaved. The
three things that cost real time were all mundane: a SCALE `Vec<u8>` length prefix that turns a
correct header into a plausible wrong one if skipped; PlatformIO taking the app flash offset from
board config rather than the partition table; and an 8 KB task stack that fails as an unhandled
debug exception inside mbedTLS rather than as anything resembling a stack overflow.

**What the negative tests are worth.** Two tamper tests were written badly enough to pass for the
wrong reason before being fixed — one corrupted a trie node that was not on the key's path, another
re-attributed a vote to an authority that had already voted, so the duplicate check fired before
the signature was ever examined. Both looked like passes. A negative test that does not first
demonstrate it can fail is not evidence of anything.

---

## 11. Two cores for signature verification - measured

The question, asked when the loop task still did everything: it read a 132-byte
precommit off the TLS stream, verified it, read the next one. Network wait and
ed25519 never overlapped, which is the ~15 s-for-7.5 s-of-work gap in section 6.
Was a second core worth it, given core 0 is also running Wi-Fi and mbedTLS, and
both cores share one instruction cache in front of the same SPI flash?

Answered by measurement first and shipped afterwards; the design that shipped is
below the table.

Harness: `src/bench.cpp`, `pio run -e bench`. Four conditions, run against live
mainnet and **interleaved within each rep** rather than in blocks, because RPC
latency drifts over minutes and blocked trials would charge that drift to
whichever condition ran last. Three independent boots: two before the design
shipped (4 reps and 2 reps) and one afterwards, driving the shipped modules.

| Condition | | Justification step |
|---|---|---|
| **SEQ** | one task reads a record, verifies it, reads the next | **14.06 s** / 14.11 / 13.97 |
| **OFF** | prefetch only: reads overlap crypto, one core verifies | **9.86 s** / 9.45 / 9.40 |
| **SPLIT** | prefetch + pool: the second core verifies too | **6.59 s** / 6.49 / 6.41 |
| **DRAIN** | same bytes off the same wire, no verification at all | **6.23 s** / 6.15 / 6.17 |

The first column is the shipped code; the other two are the original harness,
which reached the same figures with its own forked copy of the verification loop
(see *What shipped*, below, for why that copy no longer exists). Agreement across
the two implementations is worth as much as the numbers: the arrangement is what
produces the win, not any particular hand-tuning of it.

**OFF is not a second core.** Worth being explicit, because the name suggests
otherwise: the Arduino loop task runs on core 1 (`CONFIG_ARDUINO_RUNNING_CORE=1`,
and the benchmark now prints `xPortGetCoreID()` to prove it rather than asserting
it), so OFF's reader and verifier are two tasks on that *same* core. Its 4.2 s
comes entirely from letting socket wait and ed25519 overlap. Only SPLIT's further
3.3 s is a second core's arithmetic.

ed25519 alone, Wi-Fi associated but idle, 200 signatures per figure:

| | core 0 | core 1 |
|---|---|---|
| solo | 20.90 / 20.82 ms | 19.50 / 19.49 ms |
| both cores at once | 21.28 / 21.24 ms | 19.82 / 19.84 ms |

**The second core is real.** Running the same ed25519 code on both cores
simultaneously costs under 2% per core. The shared cache was the reason to
expect this not to work and it is not a limit at this code size.

**Core 0 is ~7% slower than core 1 even when Wi-Fi is idle** - that is the Wi-Fi
task, and it is the only asymmetry between the two. It does not stop core 0 from
being the busier verifier under SPLIT: 225-229 signatures on the worker against
174-176 done inline on core 1. Core 1 is where the reader, the verify loop and
the cheap checks all live; core 0's worker shares its core with nothing but the
radio. The earlier harness, which timed each core's ed25519 separately, put it at
23.8 ms per signature on core 0 against 27.0 ms on core 1 - a gap that is
preemption, not arithmetic.

**SPLIT lands 0.3 s above the no-crypto floor.** Verification has stopped being
the constraint; the step is now network-bound, and no further arrangement of
cores can buy anything. That is the finding that settles the question - not that
parallelising works, but that SPLIT is where it stops being worth doing.

**What this is worth.** SEQ -> OFF saves 4.2 s, OFF -> SPLIT another 3.3 s. The
end-to-end effect was measured afterwards rather than estimated; see the shipped
table below.

**What it costs.** An 8 KB ring, a 4 KB prefetch stack and an 8 KB worker stack,
against 185 KB of steady-state free heap - and all of it allocated for the length
of one justification and freed again. Largest contiguous block stayed at
110,580 B, the same figure as every other cycle in section 10: none of this
fragments anything.

### What shipped: SPLIT, with the verification loop left single-threaded

The benchmark's first SPLIT was two worker tasks racing to claim records, each
repeating the cheap checks from `grandpa.c` - an inlined binary search, its own
`voted` bitmap, its own weight accumulation. Faithful for timing, unshippable as
code: it forked the one file that has to be right. The version that shipped
inverts that, and the fork is gone - `bench.cpp` now drives the same
`grandpa_verify_finality_proof_ex`, `prefetch.cpp` and `sigpool.cpp` that
`main.cpp` does, so there is one verification loop in the repository and the
benchmark measures it rather than an imitation of it.

```
core 1, prio 2   prefetch task ──▶ [ 8 KB ring ]
core 1, prio 1   grandpa_verify_finality_proof_ex()  ← reads the ring, does every
                   cheap check itself, in stream order, single-threaded
core 0, prio 1   sigpool worker
```

The loop stays one thread. Vote target, authority lookup and duplicate all
happen exactly where they happened before. The only thing that leaves is the
ed25519 call, which is where 19.5 ms of every 20 ms record goes:

```c
if (pool && pool->submit(pool->ctx, sig, payload, sizeof payload, id)) {
    out->n_deferred++;
    deferred_weight += set->weights[idx];
} else if (lc_ed25519_verify(sig, payload, sizeof payload, id)) {
    out->weight += set->weights[idx];
    out->n_valid++;
} else {
    out->n_bad_sig++;
}
```

Four things make that sound:

**A deferred result needs no attribution.** One bad signature rejects the whole
justification, so the pool reports a failure *count* and nothing else. If `join`
says zero, every submitted signature verified; if it says anything else, nothing
is accepted regardless of which ones they were.

**Nothing is counted optimistically, even for an instant.** Deferred weight is
held aside and folded into `out->weight` only after `join` returns zero. A
caller that looks at the result mid-flight cannot exist, and one that looks at it
on a failure path sees `n_valid == 0` when every signature was bad - which is
what `main.cpp` keys the "authority set has rotated" hint off, the one failure a
passer-by can act on.

**The seat is claimed when the record is read, not when it verifies.** A second
vote from the same authority is refused while the first is still in flight.
Claiming a seat whose signature later turns out to be bad costs nothing, because
that justification is already rejected.

**`join` runs on every path out of the loop, truncation included.** The 53-byte
payload the workers are reading is a local of the verifier's stack frame. The
loop therefore `break`s with a status rather than returning, and the host tests
run the truncation case under ASan, where a missed join is a use-after-return
rather than a subtle miscount.

**A full pool refuses rather than blocks**, and that is the whole load balancer.
`submit` returns 0 with a zero-tick queue send; the verifier then does the check
itself, using cycles it would otherwise spend blocked on the socket. Nothing is
tuned: on the board it settles at about 231 signatures on core 0 to 172 inline on
core 1 without anyone choosing that ratio.

**The prefetch task is the other half.** Without it the same thread reads the
socket and verifies, so every ~20 ms signature check is 20 ms in which nobody is
draining the TCP window. One task above the verifier in priority, pulling hex
into an 8 KB ring, fixes that and is invisible to the verification core - it
arrives as an `lc_reader`, exactly like the memory reader the tests use. It cost
one transport change: `readHexUpTo`, because `readHex` throws away a partial
decode, and a reader that does not know where the hex string ends needs the tail.
Without it the last chunk of every justification was silently lost - it presented
as `justification truncated` at 406 of 408 signatures.

**Either half may fail to start** and the refresh just runs single-core. A slower
anchor is not a failure, and it is one `Serial.printf` on a path that so far has
never been taken.

**Measured, shipped firmware, six consecutive live cycles:**

| | Single-core | Both cores |
|---|---|---|
| Justification verify | 14.79 s | **6.27 – 6.44 s** (mean 6.35) |
| Full refresh cycle | 25.1 s | **16.1 – 17.4 s** |
| Signatures | 401–408, all verified | 401–408, all verified |
| — on core 0 / inline on core 1 | — | ~231 / ~172 |
| Heap free, steady state | 185,208 B | 182,992 B, flat over six cycles |
| Largest contiguous block | 110,580 B | 110,580 B |
| Loop task stack headroom | 6,652 B | 6,652 B |
| Flash | 1,008,201 B | 1,012,989 B (+4,788) |

6.35 s against the 6.15 s DRAIN floor: the justification step is now within 0.2 s
of moving those bytes with no verification at all. **Verification is no longer
the constraint, and the transport is.**

**The test suite grew from 40 to 48.** The new ones are equivalence tests, not
new assertions about GRANDPA: every scenario the single-core tests cover is
re-run through four pool configurations - one that always refuses, one that
defers everything, one whose small queue drains repeatedly mid-stream, and one
that falls back inline on every third check - and every observable field of
`grandpa_result` must match the inline run. `weight` is compared only on
acceptance, because on a rejection the pooled run deliberately drops the
deferred weight rather than reporting a total it never fully verified. The
single-core path is still the default and still the one `grandpa_verify_finality_proof`
takes, so it remains the tested path rather than a second one.

**The larger lever is still the transport, and it compounds.** DRAIN moves 53,014
payload bytes in 6.2 s, but the wire carries them as JSON-RPC hex - about 106 KB
at ~17 KB/s, consistent with the 15.6 KB/s in section 3. `RpcSession::getByte`
reads one byte at a time through mbedTLS, twice per decoded byte, ~106,000 calls
per justification; that is the first thing to look at, before M2b's libp2p
transport removes the hex encoding entirely. Both now show up undiluted, because
nothing else is in the way.

### Caveats

- Justification size varies between runs (401-408 signatures); per-run counts are
  printed, and every condition now reports the same byte count for the same
  justification (401 x 132 + an 82-byte header = 53,014 B).
- ed25519 measured here at 19.5-21.0 ms against the 18.7 ms in section 3. Section
  3's figure predates this toolchain (platform 7.0.1, IDF 4.4.7) and was not
  taken with Wi-Fi associated.
- Full-cycle timings come from the shipped firmware end to end; the
  four-condition table times the justification step alone.
- The 6.2 s DRAIN floor is everything that is not ed25519 - wire wait and
  read-path CPU together. Section 12 splits it: almost all of it is wire wait,
  and the read-path CPU that looked like the obvious suspect was worth nothing.

---

## 12. The transport - measured

Section 11 ended with the justification step sitting 0.3 s above a 6.2 s no-crypto floor, and with
the note that how much of that floor a faster transport could recover was not yet known. This
section answers it. The target was the relay chain's 6 s block time: a refresh that fits inside one
block can follow the finalized head continuously instead of sampling it.

**The obvious candidate was not the problem.** `RpcSession::getByte()` read a byte at a time, and in
this framework `WiFiClientSecure::read()` with no argument is `read(&b, 1)`, which calls
`available()` and then `get_ssl_receive` — two trips into the TLS record layer per byte, about
420,000 of them for a 106 KB justification. Giving the session a 2 KB read buffer collapsed that to
roughly one call per two kilobytes. It changed nothing measurable: 6,382 ms → 5,866 ms, inside the
run-to-run spread. The buffer stays, because it is obviously right and costs 2 KB, but the finding
is the negative one — per-byte call overhead was real, and was not the constraint.

Finding the constraint needed the cycle timed by phase. `-DLC_NET_STATS` builds in a stopwatch that
prints a line per step, plus what the socket actually did: time to first byte, bytes, how many reads
carried them, and how much of the streaming window was spent idle with nothing to read.

| Phase | Before | Sockets kept | + provider changed |
|---|---|---|---|
| relay TLS handshake | 2,169 ms | **28 ms** | 27 ms |
| chain head + its header | 718 | 544 | **302** |
| `grandpa_proveFinality`, to the first proof byte | 1,240 | 1,026 | **181** |
| stream + verify the justification | 5,899 | 5,471 | **4,688** |
| relay TLS handshake (second) | 2,284 | **49** | 49 |
| fetch the finalized header | 309 | 253 | **154** |
| `Paras::Heads` proof, and the walk | 424 | 558 | **194** |
| Asset Hub TLS handshake | 2,237 | **29** | 28 |
| Asset Hub storage proof | 321 | 315 | **189** |
| read the values, and the self-test | 53 | 50 | 50 |
| **full refresh** | **15,666 ms** | **8,334 ms** | **5,873 ms** |

Each column is a single consecutive cycle, so they add up. Across cycles the shipped build measures
**5.83–5.89 s** a refresh over eight consecutive warm cycles — inside Polkadot's 6 s block, which was
the point of the exercise. The two changes are independent and neither subsumes the other: keeping
the sockets removed 6.6 s of handshake, changing the provider removed 2.5 s of waiting.

**Three TLS handshakes cost 6,690 ms — 43% of the refresh, more than all 401 signatures.** That is
the whole finding. Two of the three were avoidable outright:

- *The mid-cycle reconnect.* The relay session was closed after the justification on the reasoning
  that the rest of the proof was unread and a fresh connection would be cheaper. Instrumenting the
  drain showed there is no rest of the proof: the verifier consumes the response exactly, zero bytes
  left, and `skipBody()` returns in a millisecond because the tail is already in the read buffer. It
  had been paying 2.3 s to avoid 1 ms. It now drains — but only on success, since after a failure the
  remainder really is out there and could take seconds, and that path closes the socket instead.
- *Both connections now outlive the cycle.* Nothing about a refresh requires a fresh socket, and
  measured against these endpoints a keep-alive survives the full 60 s idle between refreshes: the
  second cycle's two handshakes come back at 27 ms and 28 ms. Anything that goes wrong closes both,
  because a session parked in the middle of a response body is worse than no session at all.

**Wi-Fi modem sleep was on.** The ESP32 default parks the radio between DTIM beacons, which is free
for a device that wakes to send one request and costly for one doing a dozen round trips.
`WiFi.setSleep(false)` costs a permanently powered radio; what it buys is measured below, and is not
what it first looked like.

### What was left was the provider, and the window arithmetic was a coincidence

With the handshakes gone the refresh was 7.9–8.8 s, and ~6.3 s of that was two items: about 1.0 s
before the first byte, and about 5.3 s streaming 106 KB at ~20 KB/s. Both were charged to things
outside the firmware, and the second was charged to the wrong one.

The reasoning at the time: an 8 KB read buffer returns full 8,192-byte reads and moves throughput
not at all; 94% of the streaming window is spent idle with the socket empty; a wired host pulls the
same body at 112 KB/s. That correctly rules out the application. It was then attributed to lwip's
`CONFIG_LWIP_TCP_WND_DEFAULT = 5,760`, compiled into the framework's precompiled library, because
5,760 bytes over the round trip the small requests implied works out at almost exactly the observed
rate. It fit to within a few per cent, and it was wrong.

**Changing provider took the stream from ~5.3 s to 0.64 s — 21 KB/s to 167–203 KB/s** on the same
board, same Wi-Fi, same lwip, same 5,760-byte window. onFinality's public tier was the ceiling the
whole time. The window arithmetic fit because two unrelated numbers happened to multiply out
correctly, which is the failure mode of an explanation that is never tested against an alternative.

The alternative was cheap. Pointing `curl` at four other endpoints took two minutes and would have
settled it before any of the window analysis was written. The lesson worth keeping is not about TCP:
when a measurement implicates something you cannot change, spend the two minutes proving it is that
before you write it down, because an untestable conclusion is exactly the kind that stops getting
questioned.

### Which provider, and one that cannot be used

| | to first byte | `Accept-Encoding: gzip` | usable |
|---|---|---|---|
| `rpc.polkadot.io` | 0.10 s | 46,470 B vs 107,390 | **no — TLS 1.3 only** |
| `rpc-polkadot.luckyfriday.io` | 0.19 s | 46,012 B vs 107,918 | yes — shipped |
| `polkadot-rpc.publicnode.com` | 0.12 s | 46,063 B vs 106,070 | relay only, no Asset Hub |
| onFinality `/public` | 1.36 s | ignores it | yes — was shipped |

Parity's own endpoint is the fastest and cannot be used at all: it rejects TLS 1.2 with a
`protocol_version` alert, and the mbedTLS 2.28 in this framework has no TLS 1.3. From the board that
presents as `(-30592) SSL - A fatal alert message was received from our peer` on every connection,
which looks like a firmware bug for as long as it takes to point `openssl s_client -tls1_2` at it.
The ESP32 also has neither ChaCha20 nor Poly1305 compiled in, which is what these hosts prefer, so
the suite that actually gets negotiated is ECDHE-ECDSA-AES-GCM — present on both sides, and worth
checking before switching rather than after.

None of this is a soundness question. Every byte any of them returns is checked against the trust
root, so the choice is latency and liveness only.

### Wi-Fi modem sleep: real, but not for the reason first recorded

`WiFi.setSleep(false)` was made on throughput evidence — 17.3 to 21.3 KB/s against onFinality. Once
the provider changed, that reason evaporated: streaming measures 160–184 KB/s with modem sleep on or
off, indistinguishable. Re-measured end to end against the current provider, it is still worth
**~500 ms a refresh** — 6.29–6.51 s with it on, 5.83–5.89 s with it off — and all of that is round
trip latency on the small requests, not bandwidth. It is also the difference between sitting above
and below the block time. Kept, on better evidence than it was originally taken on; `-DLC_WIFI_MODEM_SLEEP`
restores the default for anyone who wants to re-run the comparison.

### Two things that only appeared once the transport got out of the way

**The task watchdog panicked the board.** `sigpool`'s worker polls its queue with a 50 ms timeout,
and blocking on that queue was the only reason IDLE0 ever ran. Once the transport kept the queue
full the worker stopped blocking, IDLE0 starved, and the watchdog aborted. Both verify paths now
yield deliberately — the worker every 32 checks, the verify loop in its progress callback — which
costs about 15 ms across a justification. The bug was always there; the network had been scheduling
the board on its behalf.

**Free heap halves.** Holding two TLS sessions open costs about 46 KB each: steady-state free heap
goes from 185,208 B to 89,764 B and the largest contiguous block from 110,580 B to 49,140 B. The
per-cycle working set (8 KB ring, 4 KB prefetch stack, 8 KB worker stack) still fits, and did across
every cycle soaked. The margin is real but thin, and it was measured the hard way: an experimental
8 KB read buffer added 12 KB and `sigpool_start` began failing from the second cycle on, printing
`single-core fallback: no signature worker` and doubling the verify to 9.8 s. That buffer was
reverted — it bought no throughput — but the episode is why the fallback message earns its place.

### Where a cycle's time actually goes — the numbers the progress bar is cut from

Captured 2026-08-31 with `-DLC_NET_STATS`, authority set 3588, on a steady cycle (not the first,
which pays a TLS handshake and the self-test on top). Cycle total 5,033 ms:

| step | panel says | ms | share | bar |
|---|---|---|---|---|
| `grandpa_proveFinality`, to the first proof byte | getting justification | 264 | 5.2% | 0 → 5 |
| stream + verify the justification | verifying signatures | 4,082 | 81.1% | 5 → 86 |
| relay connection reused + fetch the header | binding the header | 196 | 3.9% | 86 → 90 |
| fetch the `Paras::Heads` proof + walk it | proving Paras::Heads | 203 | 4.0% | 90 → 94 |
| Asset Hub TLS handshake (reused) | reaching Asset Hub | 28 | 0.6% | 94 → 95 |
| fetch the Asset Hub proof, read the values | proving Asset Hub | 199 | 4.0% | 95 → 99 |
| on-device self-test (first cycle only, ~220 ms) | on-device self-test | 50 | 1.0% | 99 → 100 |

The right-hand column is why the display carries **one** bar per cycle rather than a bar per step.
Equal slices would park it at 20% for four seconds and then cross the remaining 80% in one; these
slices make the bar's position a claim about elapsed work that is true to within a few percent.
Only `verifying signatures` fills its slice gradually — it is the one step that can count itself,
from the verifier's own precommit counter. The rest are single jumps, and the bar sits at the
*start* of a step's slice for its duration, so it never runs ahead of the device.

The first cycle is 6,572 ms rather than 5,033: a cold Asset Hub TLS handshake is 1,384 ms instead
of 28, and the self-test adds 223 ms (`read the values, and the self-test` goes 50 → 273 ms).

---

## 13. Later

### The refresh is inside a block; what is next is the arithmetic

Section 12 got a refresh to 5.83–5.89 s against a 6 s block, which is what "follow the finalized
head" needs. The composition has inverted: **ed25519 is the constraint again**, 4.55–4.70 s of the
5.87, and the whole transport is now 640 ms of streaming plus about 1.0 s of round trips. Section 11
predicted this would happen if the transport ever got out of the way, and it has.

So the next second is a crypto second, not a network one:

- **Signature verification is the whole budget.** 401 checks at ~19.5 ms, split across two cores,
  with 206 landing on the worker and 195 inline. The theoretical two-core floor is ~3.9 s and the
  measurement is 4.6 s, so there is roughly 0.7 s of scheduling slack to go at before anything
  cleverer is needed. Beyond that the levers are a faster ed25519 (batch verification amortises the
  scalar multiplications across a whole justification, which is exactly the shape of this workload)
  or accepting that 600 authorities on a 240 MHz core costs what it costs.
- **`REFRESH_INTERVAL_MS` is still 60 s.** Now that a refresh fits in a block, running back to back
  is a policy decision rather than an impossibility: it is a power, thermal and RPC-load question,
  and one public endpoint may not want a justification every six seconds from every device.

**Response compression is no longer worth much.** It was going to be the big win when the body took
5.3 s; at 640 ms, halving the bytes saves about 0.3 s, against ~32 KB for a deflate window plus
~11 KB of decompressor state on a heap that is already down to 90 KB. The endpoints do offer it —
`Accept-Encoding: gzip` returns 46,012 bytes against 107,918 — and a streaming inflate behind
`lc_reader` is still the right shape if the transport ever becomes the constraint again. It is not
today, and it should not be built until it is.

**The TCP receive window is a dead end, and §12 explains why it looked like one.**
`CONFIG_LWIP_TCP_WND_DEFAULT` is 5,760 bytes and the board now streams at 167–203 KB/s through it.
There is nothing there.

**Following the head needs a WebSocket, and the endpoint will do it over TLS 1.2.** ***Built — see
§14.*** This is the probe that preceded it, kept because it is why the design looks the way it does.
Measured against `rpc-polkadot.luckyfriday.io`, the endpoint already shipped:

- **Every subscription method is refused over HTTP.** `chain_subscribeFinalizedHeads`,
  `grandpa_subscribeJustifications`, `chainHead_v1_follow` and `state_subscribeStorage` all return
  `{"code":-32603,"message":"Internal error"}` — jsonrpsee declining to run a subscription on a
  request/response transport. There is no long-poll fallback. So this is a WebSocket or it is
  nothing.
- **`wss://` on the same host and port negotiates TLS 1.2 with `ECDHE-ECDSA-AES128-GCM-SHA256`** —
  the exact suite §12 measured the board negotiating. The TLS 1.3 wall that rules out
  `rpc.polkadot.io` is not in the way here; the upgrade is an HTTP `Upgrade:` on a socket the
  firmware already knows how to open, and both sessions are already `static` in `loop()`, so a held
  socket costs no heap the device is not holding through the 60 s idle anyway.
- **The prize is `grandpa_subscribeJustifications`, not the head.** It pushes the encoded
  `GrandpaJustification` unsolicited, ~53 KB binary / 106 KB of JSON hex — the same bytes the fetch
  costs now, minus the request round trip and the node's proof-build time (181 ms to first byte in
  the §12 table). Decoded, one is `round: u64`, `target_hash`, `target_number`, a compact count and
  then 401 records of exactly 132 bytes: `grandpa_verify_finality_proof_ex` parses it unchanged from
  `out->round` on. What it does *not* have is the `FinalityProof` preamble the current path skips —
  the block hash and the compact length — so it needs an entry point that starts two reads later,
  not a second parser.
- **Cadence, over 78 s: 9 finalized-head notifications and 7 justifications**, heads arriving in
  bursts of 1–3 blocks every 8–12 s, each justification about 0.4 s behind its head notification.
  A 5.3 s refresh keeps up with that, but only at roughly a 60% permanent duty cycle on both cores,
  and the pushes arrive whether or not the previous one has finished verifying. Deciding what to do
  with a justification that lands mid-verify — drain and drop, or verify streaming — is the actual
  design question, and it is a policy one, not a feasibility one. §14 answers it by not
  subscribing to justifications at all.


**M2a — authority set tracking.** The most valuable next thing, and independent of libp2p. Today
the device stops working when the set rotates, roughly daily. The block that schedules a change
carries the whole next set in a `ScheduledChange` consensus digest, which the 32 KB header buffer
already decodes; what is missing is walking forward to that block, verifying it, and writing the new
set to NVS — where a 19,200-byte set has already been shown to persist across reboots. This turns
the trust root from something flashed into something the device maintains itself.

**M2b — liveness, and getting out of TLS.** Two arguments now, not one. The first is liveness: one
provider that can refuse to answer. The second is what TLS costs, which was measured when the
question "do we need it at all?" was asked properly.

Nothing in the design relies on it. The tunnel is deliberately uncertified (see `transport.h`), so it
stops a passive observer and nothing else, and every byte is checked against the trust root
regardless. It is paid for access rather than security: **all six candidate endpoints refuse plain
HTTP** — port 80 gives 301, 403 or 404 — and Substrate's unencrypted 9944 accepts a TCP connection
from a load balancer and then speaks nothing. The bill is **~45 KB of heap per open session**
(185,208 B free with none open, 94,768 B with two) and **~155 KB of linked mbedTLS** in a 1,015 KB
image. Halving the free heap is what makes the deflate window in the section above awkward, and it
is the same 90 KB M2b would want for peers.

libp2p does not escape encryption — Noise is mandatory — but it escapes *this* encryption: Noise XX
is X25519, ChaCha20-Poly1305 and BLAKE2, all already in the libsodium this firmware links, with no
X.509 chain to parse and no pair of 16 KB record buffers per connection. The ESP32's mbedTLS has
neither ChaCha20 nor Poly1305 compiled in, which is a good illustration of the point: the primitives
libp2p needs are the ones already on the device, and the ones TLS needs are the ones that had to be
dragged in.

libp2p over raw TCP (bootnode port 30333 confirmed open on two of three Polkadot bootnodes; no TLS,
Noise instead — all primitives already in libsodium). multistream-select → Noise XX → Yamux → `/<genesis>/light/2`
(`RemoteReadRequest`) and `/<genesis>/sync/2`. Plus multi-peer failover. Verified already: the board
reached 11 concurrent TCP peers at ~1.4 KB each, and 4 Polkadot bootnodes answered
`/multistream/1.0.0` — RAM is not the constraint, code complexity is. The verification core needs no
changes for this: it already reads through `lc_reader` and knows nothing about TLS or JSON, so the
work is confined to `transport.cpp`.

**M3 — richer output.** The display is done (§10). What is left under this heading is what to put
on it once M2a exists: an account balance needs an SS58 address, which needs a way to get one into
the device — a captive portal, or a key baked in at flash time.

---

## 14. Following the head - built

§13 probed whether the device could stop sampling the chain on a timer and start following it. It
can, and it does. `REFRESH_INTERVAL_MS` is gone; the relay leg is a WebSocket subscribed to
`chain_subscribeFinalizedHeads`, and a cycle begins when the node says a block was finalized.

**Heads only. The proof is still pulled.** Subscribing to `grandpa_subscribeJustifications` was the
greedier option and was not taken: it saves a round trip and the node's ~181 ms of proof-building,
and in exchange it pushes 106 KB unbidden whether or not the previous one has finished verifying.
A head notification is 861 bytes, so one landing in the middle of a call costs microseconds to
absorb; a justification landing there costs ~0.6 s of wire at the 167-203 KB/s this board manages,
for bytes that may then be thrown away. The pull stays.

**One socket, not two.** Ordinary calls work over the WebSocket - measured at 146 ms for
`chain_getFinalizedHead`, 149 ms for `chain_getHeader`, 219 ms for `state_getReadProof`, the same
latencies HTTP gave - so the WebSocket replaces the relay's HTTPS session instead of joining it.
That was the constraint that shaped everything else: a third TLS session is ~45 KB against 94,820
free, and §12 records an 8 KB read buffer being enough to make `sigpool_start` fail. Asset Hub
stays on plain HTTPS, which also keeps both transports exercised on every cycle rather than letting
one rot.

**No library could have been used.** Every off-the-shelf Arduino WebSocket client hands over a
complete message. The justification messages measured 106,068-107,652 bytes against 94,820 bytes of
free heap, so that API shape is unusable here regardless of which library it is. It has to be a
streaming frame reader - which is what `RpcSession` already was. Everything above `getByte()`
(`scanTo`, `readHex`, the prefetcher on core 1, the GRANDPA verifier) reads through one byte source
with a framing layer underneath, and that layer was three variables: `chunked`, `remaining`, `eof`.
WebSocket framing is the same shape. `getByte()` gained a branch and nothing above it changed. The
chunked-encoding reader written in §12 to stream a 53 KB justification turned out to be the
abstraction RFC 6455 needed.

**`Sec-WebSocket-Accept` is deliberately not checked.** It is sha1(key + a fixed GUID), and what it
defends against is a caching intermediary being tricked into treating the upgrade as an ordinary
response - which cannot happen inside a TLS tunnel with no proxy in it. `transport.h` already
argues that tunnel is uncertified on purpose; this is the same argument, and a 101 that is not a
WebSocket fails on the first frame header anyway.

### Never interrupt a verify; redirect the next one

A cycle takes ~5 s and heads arrive every 6-12 s, sometimes several at once. The rule is that a
running verification always finishes, and only the *next* one is redirected - so the coalescing is
one slot rather than a queue:

    absorbed head #118  ->  head_number = max(head_number, 118), head_count++
    absorbed head #119  ->  head_number = 119,                   head_count = 2
    takeHead()          ->  #119, coalesced 2, slot cleared

Heads absorbed inside `call()` while it waits for a response land in the same slot, which is what
makes it work across a whole cycle: the device comes back to the newest block the node has
finalized, never to a backlog it would take three cycles to work off. `loop()` starts with
`pumpHeads(0)` - take everything that queued while we were busy, without waiting - and only blocks
if that found nothing. It is printed when it happens, because a device quietly skipping blocks and
a device keeping up look identical otherwise:

    --- cycle 2 ---
      2 heads arrived while the last cycle ran; taking the newest
      node finalized #32,793,118

### The result gets two seconds — `RESULT_DWELL_MS`, added 2026-08-31

Following every head was the wrong default for the panel. With a ~5 s cycle against a 6 s block the
proven values were on screen for about a second, after four seconds of watching a progress bar fill
— the display spent most of its life showing work in progress and almost none showing the answer.
`RESULT_DWELL_MS` (default 2000) holds the result before the next cycle may start. It is a floor,
not a period: a cycle that happens to finish with three seconds to spare waits for none of it.

It is deliberately not `MIN_CYCLE_GAP_MS`. That knob is about how often a public endpoint should be
asked for a justification; this one is about whether a person can read the answer. One wait serves
both — the loop holds for whichever is longer — but they are different questions and merging them
into one number would mean tuning one and silently changing the other.

The cost is blocks, and the coalescing above is what pays it. Measured over 21 consecutive cycles
on 2026-08-31 (relay #32,795,584–618, 21 proven, 0 failures, 4 cycles reporting coalesced heads):

| | every head | with a 2 s dwell |
|---|---|---|
| cycle | 4,92–5,06 s | unchanged, 4,92–5,06 s |
| end of a cycle to the start of the next | 0–1 s, whatever the chain left | 2.00–2.01 s, then whatever the chain left |
| blocks between proofs | 1 | 1–3, median 1 |
| result on screen | ~1 s | ≥2 s |

The gap distribution is the honest number here: 1, 1, 1, 2, 1, 2, 0, 1, 2, 1, 2, 4, 3, 1, 3 and so
on. It still usually proves consecutive blocks — 5 s of cycle plus 2 s of dwell only exceeds a 6 s
block by one second, so it slips a block roughly every sixth cycle rather than every other one. The
0 is a block proven twice, which happens when the node re-pushes a head the device already used.

### Measured, against live Polkadot

Sixteen consecutive cycles across two flashes, following blocks one per block
(32,793,118-129 and 32,793,168-172):

| | before (§13) | now |
|---|---:|---:|
| full cycle | 5,296-5,347 ms | **4,938-5,010 ms** |
| — justification verify | 3,950-4,000 ms | 3,960-4,098 ms |
| — chain head + its header | ~302 ms | **gone** |
| heap free / largest block | 94,820 / 49,140 | 94,592 / 49,140 |
| static RAM | 98,476 B | 98,476 B |
| flash | 1,614,225 B | 1,617,769 B |

The ~330 ms is `chain_getFinalizedHead` followed by `chain_getHeader`, which the subscription makes
redundant: the notification *is* the header, so the block number is already in hand. Nothing else
moved - the whole WebSocket layer cost 3,544 bytes of flash, 228 bytes of heap and no measurable
time. Heap was flat at 94,592 across all eleven cycles.

The device now spends about 5 s of every 6 s block verifying, which is the thing §13 warned about
and is now the operating point: **following the head means the board never idles.**
`MIN_CYCLE_GAP_MS` (default 0) is the knob for backing off, and it is a politeness and power
question rather than a capability one.

**The failure mode to watch is backpressure, and it fails closed.** Nothing reads the relay socket
while a justification is streaming or a proof is being walked, so notifications queue - on the
server's per-connection send buffer and in a 5,760-byte TCP window, about six of them. At a 5 s
cycle and a 6 s block that is roughly one, so it is not close today. If it ever were, jsonrpsee
drops the subscription rather than the connection, which would leave the device holding a healthy
socket and waiting for pushes that stop coming - indistinguishable from a quiet chain.
`HEAD_SILENCE_MS` exists for exactly that: 60 s without a head drops the socket and re-subscribes,
because heads arrive every 8-12 s and silence that long is never normal.

### What is tested, and what the board cannot test

`src/ws_frame.c` knows nothing about sockets, TLS, HTTP or JSON - bytes arrive through one callback
and leave through another - so `sh test/run_ws.sh` drives the whole framing layer from byte arrays
on the host. **31 assertions.** That split exists because the endpoint exercises almost none of it:
luckyfriday sends no pings (45 s watched with client pings disabled), never fragments a message and
has never closed one mid-stream, so on real traffic the interesting half of the file ships
unexecuted. The tests produce by hand what it will not send - both extended length forms, a
four-fragment message with an empty fragment in it, a ping *between* two fragments, a close
mid-message, a stream cut off mid-payload - plus the six protocol violations that must drop the
socket rather than be tolerated: a reserved bit, a masked server frame, an orphan continuation, an
unknown control opcode, a fragmented ping, a 200-byte ping, and two data messages interleaved.

The ping case is the one worth the effort. A pong is written from inside a read, which on the
device means the prefetch task writes to the socket while the verifier is mid-record. It is the one
event that could corrupt a justification rather than fail it, and it is the one event the endpoint
will not produce.

