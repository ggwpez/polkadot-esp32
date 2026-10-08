# Polkadot light client on an ESP32

For the portable project, vendored dependencies, and required toolchains, start
with the [door sensor README](../README.md). Historical setup notes below describe
the original workspace.

**Active configuration: Products Devnet (Paseo Asset Hub 1000).** See
[devnet bring-up](docs/DEVNET.md) for endpoints, proof checks and checkpoint
regeneration. The OLED headline is now the proven block number;
serial also reports timestamp and issuance in PAS. The mainnet measurements
and examples below describe the earlier configuration.

Reads Asset Hub on-chain state on a $5 microcontroller without trusting the RPC
node it talks to.

**M1 is working on hardware.** The device verifies GRANDPA finality from several
hundred ed25519 signatures, binds the relay header to it, and walks two Merkle
proofs to reach an Asset Hub value — comfortably inside one Polkadot block. It
does not sample the chain on a timer: it subscribes to finalized heads over a
WebSocket and starts a cycle when the chain finalizes a block, so it follows the
head block by block (§14). It does that with heap to spare and about half its
flash used, most of that being the precomputed authority tables.
An optional 128×64 OLED shows the progress. The signature checks run on both cores
(PLAN.md §11), the connections are held open across cycles and the provider was
chosen on measured latency (§12).
§12 also records where that analysis went wrong for a while, which is the more
useful half.

Every measured number lives in PLAN.md and EXPERIMENTS.md, which are dated logs.
This file deliberately carries none, so it cannot quietly go stale.

One cycle, captured from serial:

```
--- cycle 2 ---
  2 heads arrived while the last cycle ran; taking the newest
  node finalized #32,793,118
  verifying justification ............
  finality: #32,793,118, 401/401 signatures, weight 401/600 in 3,973 ms
    (207 checked on the second core, 194 inline while it was busy)
  header bound: 327 bytes hash to the finalized block
  Paras::Heads(1000) proven from 7 nodes -> Asset Hub #20,095,142

  proven against Asset Hub #20,095,142 (state root from relay #32,793,118)
    System::Number          = 20,095,142
    Timestamp::Now          = 1,788,167,898,000
    Balances::TotalIssuance = 1.70B DOT  (1,700,563,339.7056265564)
    consistency: AH block number matches the relay-proven header: yes
  cycle took 4,968 ms, heap 94,592 free (largest block 49,140), stack headroom 7,580
```

## What "without trusting the node" means

The node is asked for everything and believed for nothing:

```
GRANDPA justification (a signature per authority, over one block hash)
     │  every signature checked against the authority set in flash
     ▼
a relay block hash a supermajority of validators signed
     │  blake2b(re-encoded header) must equal that hash
     ▼
a relay state root
     │  Merkle proof of Paras::Heads(1000)
     ▼
the Asset Hub header, and so the Asset Hub state root
     │  Merkle proof
     ▼
the value
```

Only one thing is trusted a priori: the authority set baked into
`src/checkpoint.h`. Everything else is derived from it by arithmetic that fails
closed. A hostile RPC provider — or anyone on the network path — can refuse to
answer or serve stale data, but cannot make the device display a value that was
not in the chain state.

The TLS connection is deliberately **not** certificate-checked. A man in the
middle can do exactly what a hostile provider can do, and no more; a CA bundle
would add bytes and an expiry date to a device with no OTA, and buy no
soundness. See the comment at the top of `src/transport.h`.

## The display

An SSD1306 128×64 OLED on I2C (`0x3C`, SDA GPIO25 / SCL GPIO26) shows what stage
a cycle has reached and how far through the cycle that is, then the proven values
until the next block lands. The number in the header is always an age, never a
countdown: nothing is scheduled any more, so how long ago a thing was proven is
the only honest thing to say.

There is **one bar per cycle**, not one per step, and its steps are cut to the
measured cost of each stage rather than into equal slices (PLAN.md §12). Asking
for the justification is the first 5%, verifying its several hundred signatures
is the next 81%, and binding the header, walking both Merkle proofs and reading
the values share the last 14%. Only the signature stretch fills gradually —
it is the one step that can count itself, straight from the GRANDPA verifier's
own precommit counter — and the bar sits at the start of a step's slice for its
duration, so it never claims more progress than the device has made.

```
 PROVEN                    3s  ▂▄▆_        SYNC #7                   4s  ▂▄▆_
 ────────────────────────────────          ────────────────────────────────
 relay  #32,770,159                        verifying signatures
 hub    #20,032,285
                                           [█████████░░░░░░░░░░░░░░░░░░░░░]
 issuance 1.70B DOT
                                           128 of 401 checked
 401/600 sig  set 3586                     last #32,770,147 24s
```

It is a window onto the serial log and nothing more: it never gates
verification, and if no panel answers on the bus every call is a no-op. Two
rules shape the layout:

- **Only proven values appear.** A number reaches the screen after the
  signatures, the header hash, both Merkle proofs, the block-number
  cross-check and the self-test have all held — never before.
- **A stale screen has to look stale.** A panel frozen on last hour's block is
  worse than a blank one, so the header flips from `PROVEN` to `STALE` the
  moment a refresh fails, with the age of the anchor beneath it. Failures show
  the reason in words for a few seconds first.

Layout bugs on a 21-column panel are silent — a line one character too long is
just clipped — so text that does not fit is cut with a visible `~`, and
building with `-DUI_DUMP_FRAMES=N` prints the first N distinct frames to serial
as ASCII art — one per view, one per stage within a sync, and one from inside
the signature stretch, which is the only place the bar moves without the stage
changing. That is how the layout above was checked without looking at the panel;
it caught two overlong strings and a signal meter that showed full strength at
every RSSI, and it is how the bar's slices were measured off the glass rather
than reasoned about.

Timing has the same problem — a refresh that takes sixteen seconds does not say
which second to go after — so `-DLC_NET_STATS` builds in a stopwatch that prints
one line per phase, plus what the socket did: time to first byte, bytes, how many
reads carried them, and how much of the streaming window was spent idle. That is
what found three TLS handshakes eating nearly half of a refresh. Both flags are off by
default and cost nothing when they are.

## Layout

```
src/
  lc_crypto.h/.c   blake2b-256 and ed25519, via libsodium
  lc_reader.h/.c   pull-based byte source, so the justification is never stored
  scale.h/.c       SCALE codec: compact ints, vectors, block headers
  trie.h/.c        Substrate trie v1 node codec and proof walk
  grandpa.h/.c     justification verification
  checkpoint.h     GENERATED trust root: authority set, set_id, storage keys
  checkpoint_precomp.c/.h  GENERATED cache: the point tables the 600 keys expand
                   to, so the verifier does not rebuild them 400 times a cycle
  transport.h/.cpp JSON-RPC over TLS, buffered     [the swap point for M2's libp2p]
  prefetch.h/.cpp  reader task, so the socket drains while signatures verify
  sigpool.h/.cpp   the second core, behind grandpa.h's optional pool interface
  fmt.h/.c         thousands separators and the short form the panel shows
  ws_frame.h/.c    RFC 6455 framing, and nothing else - no socket, no JSON
  ui.h/.cpp        optional SSD1306 status display
  main.cpp         wiring, the head-driven cycle loop, on-device self-tests
test/
  test_core.c      host tests against real captured mainnet data
  run.sh           build and run them
  test_ed25519.c   ed25519 batch verification: correctness and host timing
  run_ed.sh        build and run those
  test_precomp.c   the precomputed authority tables: right points, same verdicts
  run_pre.sh       build and run those
  test_ws.c        WebSocket framing, including everything the endpoint never sends
  run_ws.sh        build and run those
  test_fe_model.c  the generated field multiply against ref10's, exhaustively
  run_fe.sh        build and run that
  host/            libsodium's few symbols, so the ed25519 tests need no board
  fixtures/        GENERATED, captured from live Polkadot
lib/
  ed25519_fast/    vendored libsodium ref10 plus a batch verifier  [experimental]
    fe25519_mul_xtensa.S   handwritten field multiply, benched by env:mcbench_asm
tools/
  gen_checkpoint.py  dump the current authority set into src/checkpoint.h
  gen_fixtures.py    capture live data into test/fixtures/
  gen_sig_corpus.py  freeze a justification's signatures for benchmarking
```

The verification core (`scale`, `trie`, `grandpa`, `lc_reader`, `lc_crypto`) is
plain C99 with no allocation and no STL, so the identical source builds for the
ESP32 and for host tests. Only transport, the display and orchestration are C++.

## Building and testing

```sh
./test/run.sh              # host tests, real mainnet data, ASan + UBSan
./test/run_ed.sh           # ed25519 batch verification, no libsodium needed
./test/run_pre.sh          # precomputed authority tables, no libsodium needed
./test/run_ws.sh           # WebSocket framing, no board and no network
./test/run_fe.sh           # the generated field multiply vs ref10's
pio run -t upload          # build and flash
```

Regenerating the trust root, which is needed when the authority set rotates:

```sh
python3 tools/gen_checkpoint.py     # rewrites src/checkpoint.h and the tables
python3 tools/gen_fixtures.py       # refreshes test/fixtures/
```

`gen_checkpoint.py` also writes `src/checkpoint_precomp.c`, the precomputed
point tables for those keys. They are a cache, not a second trust root - derived
from the keys and nothing else - but they must not fall behind the keys, so
`main.cpp` refuses to compile if the two disagree on `set_id`. To rebuild only
the tables, from the keys already on disk and with no network access at all:

```sh
python3 tools/gen_checkpoint.py --precomp-only
```

Both need the repo-root `.venv` (`xxhash`, `cryptography`).

## Testing

Two layers, because they catch different things.

**Host tests** (`./test/run.sh`) run the same C files the firmware builds,
against a real justification, real headers and real storage proofs captured from
mainnet. The interesting ones are negative: a flipped signature bit, a vote
re-attributed to another authority, an unknown signer, a duplicate vote, a
truncated justification, a wrong `set_id`, every single-bit change to the header,
every single-bit change to every proof node, a forged value, and malformed node
encodings.

**Ed25519 batch verification** (`./test/run_ed.sh`) is a separate, faster loop
over the real precommits frozen out of the captured justification, so it needs
neither a board nor a network nor a system libsodium. It is where the
performance work lives; see `EXPERIMENTS.md` for results and `ASSEMBLY.md` for
the baseline it started from. Not wired into the firmware: batch verification
accepts a signature class libsodium rejects, and that has to be settled first.

**WebSocket framing** (`./test/run_ws.sh`) drives `src/ws_frame.c` from byte
arrays — no board and no network, because the file deliberately knows nothing
about sockets. It exists because the endpoint exercises almost none
of that code: it sends no pings, never fragments a message and has never closed
one mid-stream, so the tests produce those by hand along with the protocol
violations that must drop the socket. The ping case matters most — a pong is
written from inside a read, which on the device means the prefetch task writes to
the socket while the verifier is mid-record.

**On-device self-tests** run once per boot on data that just came off the wire,
because passing on x86 with Debian's libsodium is not the same as passing on
xtensa with the framework's. They confirm every field of the GRANDPA signed
payload is load-bearing, and that no single-bit tamper of a live proof yields a
different value.

## Known limits in M1

- **The authority set goes stale.** It rotates roughly every 24 h. When it does,
  the device fails closed and says so; re-run `gen_checkpoint.py` and reflash.
  Tracking `ScheduledChange` digests to update it trustlessly is M2.
- **One provider, so no liveness guarantee.** Soundness is covered; a provider
  that refuses to answer, or serves an old-but-valid block, is not. Which one it
  is affects only speed — §12 measured a wide spread across public endpoints —
  and Parity's own `rpc.polkadot.io` is unusable regardless, because
  it requires TLS 1.3 and this framework's mbedTLS is 2.28. M2's libp2p work is
  what closes the liveness gap.
- **Votes for descendants are not counted.** GRANDPA allows an authority to
  precommit to a descendant of the commit target, proven via `votes_ancestries`.
  Those votes are skipped, which can only lower the counted weight, so it fails
  closed. Not yet observed to matter — the counter is printed when it happens.
- **It does not verify every block, by choice.** A cycle very nearly fills a 6 s
  block, so following every finalized head would leave the proven values on the
  panel for about a second after four seconds of progress bar. `RESULT_DWELL_MS`
  (default 2000) holds the result for two seconds before the next cycle may
  start, which costs a block now and then: over a 21-cycle soak the device
  proved blocks one to three apart rather than every one. Nothing is queued —
  heads that arrive during the hold are folded into one and the next cycle takes
  the newest, never a backlog. Set it to 0 to follow every block.
  `MIN_CYCLE_GAP_MS` (default 0) is the separate knob for whether one public
  endpoint should be asked for a justification this often, which is a question
  for whoever runs it and for the power budget. PLAN.md §14 has the
  measurements.
- **A running verify is never interrupted.** Heads that arrive mid-cycle are
  coalesced into one slot, so the next cycle starts from the newest block rather
  than working off a backlog. It says so when it happens.
- **Verification is the budget now.** Four fifths of a cycle is ed25519 checks
  across two cores; the rest is streaming the justification plus a handful of
  round trips. Making this faster means making ed25519 faster — see ASSEMBLY.md.
  PLAN.md §12–14 have the measurements.
- **The display shows one value.** There is room for a single headline number,
  currently total issuance — three significant figures, rounded down so the short
  form never reads higher than what was proven. Serial leads with the same short
  form and then gives every digit.

See `PLAN.md` for the full scope, budgets and measurements.
