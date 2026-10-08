# Ed25519 verification: experiment log

Running record of what was tried, what it measured, and what it cost. Read
`ASSEMBLY.md` first for the baseline this starts from.

Everything below is reproducible from a clean checkout:

```sh
sh test/run_ed.sh                       # correctness + host timing, under a second
W=7 CHUNK=512 sh test/run_ed.sh         # any tuning
pio run -e batchbench -t upload --upload-port 'rfc2217://host.internal:4000?ign_set_control'
```

---

## The starting question

`ASSEMBLY.md` ends with a recommendation to spend 3-7 days on a handwritten
Xtensa `fe25519_mul` and expect 10-20% off the whole verifier, and to treat
batch verification as a separate, later project. The measurements below say the
ordering should be the other way round: batch verification is worth more than
twice as much, took days rather than months, and - crucially - it moves the
bottleneck, which changes what an assembly kernel would even be worth
afterwards.

The one thing assembly has that batching does not is that it cannot change which
signatures are accepted. Batching can, and does. See
[The semantic gap](#the-semantic-gap-the-decision-this-turns-on), which is the
real subject of this document.

---

## E0. Getting into a loop that is not two minutes long

Nothing else here was possible until this was.

**Problem.** Every measurement in `ASSEMBLY.md` needed a flash and a serial
capture over an RFC2217 bridge: about two minutes per iteration, and the
signatures came from a live justification, so the light client had to be running
and synced.

**What was done.**

- `tools/gen_sig_corpus.py` pulls the ed25519 work out of the justification
  already captured in `test/fixtures/finality_proof.bin` and freezes it into
  `test/fixtures/ed_corpus.h`: **403 real Polkadot GRANDPA precommits, every one
  of them over the same 53-byte localized payload** (round 6047, set 3585, block
  32755461). No network, no chain state, no board.

  That every precommit signs an identical message is not a convenience, it is
  the property batch verification needs, and it is a fact about GRANDPA rather
  than about this capture: `grandpa.c` counts only votes on the commit target
  itself and skips votes for a descendant.

- `test/host/` supplies the four libsodium symbols the vendored ref10 code calls
  (SHA-512 and three constant-time helpers) plus a transcription of
  `crypto_sign_verify_detached`. This machine has no libsodium at all, and now
  does not need one.

- `test/run_ed.sh` builds and runs the whole correctness suite.

**Result.** The loop went from ~120 s to **0.4 s**, and from "the board and the
chain both have to be up" to "gcc". The device is now reserved for the one
question it alone can answer: wall-clock time on an Xtensa LX6.

---

## E1. Batch verification

**Hypothesis.** ~400 independent double-scalar multiplications can be replaced
by one multi-scalar multiplication over ~800 points, checking

```
sum(z_i * R_i) + sum(z_i * h_i * A_i) - sum(z_i * s_i) * B  ==  O
```

with fresh random 128-bit `z_i`. Per signature that is roughly 45 group
operations instead of roughly 330.

This is sound for GRANDPA specifically because **the answer only has to be one
bit for the whole justification**. A justification carrying any invalid
signature is rejected outright, so no per-signature attribution is needed.
`grandpa.c` already depends on exactly this property when it hands signature
checks to the other core.

**Implementation.** `lib/ed25519_fast/src/ed25519_batch.{h,c}`, a bucket
(Pippenger) MSM with signed digits, folding in chunks so peak memory is a
tunable constant rather than a function of the justification size. It is
`#include`d into `ed25519_fast.c` for the reason `ed25519_ref10.c` is: one
translation unit, so the field arithmetic inlines and ref10's file-static
helpers are in scope without patching upstream.

**Result, host, 403 signatures, w=6 chunk=128:**

| | per signature | 403 signatures |
|---|---:|---:|
| per-signature (ref10, `-O2`) | 32.8 us | 13.2 ms |
| batch | 17.8 us | 7.2 ms |
| | | **1.84x** |

Correct on the first run, which is less impressive than it sounds: the corpus is
403 real signatures that must all verify, so a wrong carry anywhere fails loudly.

---

## E2. Duif-form points instead of `ge25519_cached`

**Hypothesis.** The bucket loop is the whole cost. `ge25519_madd` uses three
field multiplications where `ge25519_add` uses four, and a `ge25519_precomp` is
120 bytes where a `ge25519_cached` is 160. Normally the conversion costs a field
inversion per point, which would eat the saving several times over.

**Observation that makes it free.** Every point entering a batch comes straight
out of `ge25519_frombytes` or `ge25519_frombytes_negate_vartime`, both of which
set `Z = 1` and `T = X*Y`. So `x` and `y` are already `X` and `Y`, and `2dxy` is
`T * d2` - one multiplication, no inversion. `p3_z1_to_precomp()`.

The invariant is asserted on the first point of each batch rather than every
point: it is structural, not data-dependent, so checking it 806 times would cost
a field reduction each for no more information.

**Result:** state 31.7 KB -> 25.9 KB (-18%) and 18.8 -> 17.9 us/sig (-5%) at
w=6 chunk=128. Both directions matter, but the memory is the one that decides
what fits on the ESP32.

---

## E3. Window and chunk sweep (host)

Two points per signature, so `chunk=806` holds the entire justification and
folds only once. Baseline: **32.8 us/sig** per-signature.

| w | chunk | state | us/sig | vs per-signature |
|---:|---:|---:|---:|---:|
| 4 | 128 | 24.8 KB | 17.0 | 1.93x |
| 5 | 128 | 24.6 KB | 16.9 | 1.94x |
| 6 | 128 | 25.9 KB | 17.8 | 1.84x |
| 7 | 128 | 30.2 KB | 21.0 | 1.56x |
| 5 | 256 | 46.1 KB | 15.2 | 2.16x |
| 6 | 256 | 46.3 KB | 15.5 | 2.12x |
| 7 | 256 | 49.8 KB | 16.9 | 1.94x |
| 5 | 512 | 89.1 KB | 14.5 | 2.26x |
| **6** | **512** | **87.1 KB** | **13.9** | **2.36x** |
| 7 | 512 | 89.1 KB | 14.1 | 2.33x |
| 6 | 806 | 133.9 KB | 12.9 | 2.54x |
| 7 | 806 | 134.1 KB | 12.8 | 2.56x |
| 8 | 806 | 140.2 KB | 13.0 | 2.52x |

Reading it:

- **The window matters much less than the chunk.** A fold costs
  `2 * NBUCKETS` additions per window for the bucket summation whatever the
  batch length, so a large window in a small chunk is pure overhead - w=8 at
  chunk=128 is *slower than verifying one at a time*.
- The optimum window rises with the chunk, as the model says: w=4..5 at 128,
  w=6 at 512, w=6..8 at 806, and it is flat across those.
- Returns fall off hard past chunk=512. Going 512 -> 806 buys 7% for another
  47 KB.

---

## E4. Where the time actually goes

Measured by timing `add()` and `final()` separately. Chunk folds happen inside
`add()`, so at `chunk=806` (one fold, at the end) `add()` is the pure
per-signature cost.

| | chunk=128 | chunk=512 | chunk=806 |
|---|---:|---:|---:|
| `add()` - decode R and A, SHA-512, two scalar muls, recode | 16.7 us | 11.0 us | **6.6 us** |
| `final()` - bucket MSM and base scalarmult | 1.1 us | 2.9 us | 6.3 us |
| total | 17.8 us | 13.8 us | 12.9 us |

**This is the most useful number in the document.** The per-signature work that
batching cannot remove is 6.6 us against 32.8 us for a full verification. So:

- The **floor for any batch scheme built on this preprocessing is 5.0x**, and
  the MSM currently costs about as much again, landing at 2.5x.
- The remaining 6.6 us is two point decompressions (a field exponentiation
  each), one SHA-512 over 117 bytes, and two scalar multiplications mod L.
- **One of those two decompressions is redundant work.** `A_i` is an authority
  public key. The authority set is fixed for a whole era and is already in RAM;
  the same 400-odd keys are decompressed again in every single justification.
  Caching them in Duif form is 120 bytes per authority - 72 KB for a
  600-authority set - and would remove roughly a third of the per-signature
  floor. That is the highest-value item left, and it is bookkeeping rather than
  cryptography.

It also reframes the assembly question. `fe25519_mul` is a smaller share of a
batched verifier than of a per-signature one, so the 10-20% `ASSEMBLY.md`
projects would apply to a smaller number. Assembly is worth strictly less after
batching than before it.

---

## E5. On the board

`src/batchbench.cpp`, `env:batchbench`. Same 403-signature corpus, and the
reference arm is the framework's **prebuilt** libsodium, because that is what
the firmware ships and consensus is defined by what it accepts.

The device suite is deliberately not the host suite. A fold costs
`2 * NBUCKETS` additions per window regardless of batch length, so on this chip
even an 8-signature batch is on the order of a hundred milliseconds, and
sweeping 1,192 bit flips over full batches would take half an hour. The host
does the exhaustive sweep in under a second. The board answers the questions
only it can: does the batch agree with the shipped libsodium on this silicon,
how much RAM can the state have, and what is the wall clock.

### Results

403 signatures, `w=6`, one 89,148-byte state, WiFi down. The `-O3` arm ran the
full agreement suite (**1,681 checks, 0 disagreements**); the other arms ran the
quick sanity check (8 checks, 0 disagreements) so that all four could be flashed
and captured in one sitting.

**Per-signature cost, by optimisation level of the vendored code:**

| arm | prebuilt `-Os` (baseline) | vendored | batch, chunk 512 | batch speedup |
|---|---:|---:|---:|---:|
| `-O3` (full suite) | 18.567 ms | 24.298 ms | 14.744 ms | 1.26x |
| `-O3` (quick) | 18.586 ms | 23.616 ms | 14.668 ms | 1.27x |
| `-O2` (quick) | 19.288 ms | 21.443 ms | 14.845 ms | 1.30x |
| **`-Os` (quick)** | 19.303 ms | **17.681 ms** | **12.057 ms** | **1.60x** |

Two things fall out of this table, and neither was expected.

**1. `-Os` is not a compromise, it is the fastest setting - for both arms.**
The vendored code goes 24.298 -> 21.443 -> 17.681 ms/sig as the optimiser is
turned *down*, and only at `-Os` does it finally beat the prebuilt libsodium it
replaces (1.09x). The batch improves the same way, 14.744 -> 12.057 ms/sig, an
18% gain from a flag. This is the device-side twin of E6: `-O3` emits the same
203 multiplies as `-Os` and pays for it with 47 extra spills and 123 more bytes
per `fe25519_mul`, and on a chip with a 32 KB instruction cache that is a pure
loss. `ASSEMBLY.md` measured vendored `-O3` at 0.94-0.95x of prebuilt in
`edbench` and treated the slowdown as a puzzle; the same comparison inside the
larger `batchbench` image is 0.76x. It is not a puzzle, it is the optimiser
trading cache for nothing - and the fact that the *same* pair of verifiers
measures 0.94x in a small image and 0.76x in a big one is itself the cache
effect showing up twice.

**2. The baseline is not constant across arms.** The prebuilt libsodium is byte
for byte the same code in all four builds, yet it measures 18.567 ms in the
`-O3` arm and 19.303 ms in the `-Os` arm - a 4% spread. Nothing about libsodium
changed; only what is linked around it did. That is cache and layout
interference, and it is a warning about method: **compare ratios within an arm,
never absolute milliseconds across arms.** The speedups in the last column are
trustworthy, the raw millisecond columns are only trustworthy down to a few
percent.

**Chunk sweep** (ms/sig; larger chunks mean fewer folds and more RAM):

| chunk | state | `-O3` | `-Os` |
|---:|---:|---:|---:|
| 64 | 13.5 KB | 19.697 | 16.951 |
| 128 | 24.0 KB | 17.000 | 14.297 |
| 256 | 45.6 KB | 15.650 | 12.952 |
| 512 | 89.1 KB | 14.744 | **12.057** |

Returns diminish but have not stopped at 512. Note that at `-O3`, `chunk=64` is
*slower than verifying one at a time* - a small batch is a pessimisation,
because a fold costs `2 * NBUCKETS` point additions no matter how few signatures
went into it. There is a minimum useful batch size and it is somewhere above 64.

**Both cores** (`-Os`, 403 signatures split 201/202, each core with its own
89 KB state):

| chunk | core0 | core1 | wall | ms/sig | vs baseline |
|---:|---:|---:|---:|---:|---:|
| 64 | 4363 ms | 4360 ms | 4391 ms | 10.90 | 1.77x |
| 128 | 3776 ms | 3776 ms | 3809 ms | 9.45 | 2.04x |
| 256 | 3434 ms | 3434 ms | 3465 ms | 8.60 | 2.25x |
| 512 | 3223 ms | 3227 ms | **3252 ms** | **8.07** | **2.39x** |

The two cores track each other to within 4 ms, so the split is even and there is
no memory-bus contention worth worrying about. **7.78 s -> 3.25 s for a real
600-authority justification, a 2.39x end-to-end improvement**, with no change to
what the verifier accepts beyond the cofactor gap discussed below.

The caveat is RAM: two states is 178 KB, measured with WiFi down and 340 KB
free. A production light client holding TLS buffers and a WiFi stack will not
have that. `chunk=256` on two cores is 91 KB total for 2.25x and is the
realistic configuration; single-core `chunk=256` at 46 KB for 1.49x is the
conservative one.

---

## E6. What `fe25519_mul` actually compiles to on Xtensa

This one needs no board, which is the point - it is the cheapest experiment in
the document and it should have been the first. Compile `ed25519_fast.c` with
the ESP32 toolchain at three optimisation levels and count the instruction mix
in the two functions `ASSEMBLY.md` nominates as the target.

```
xtensa-esp32-elf-gcc -c -std=gnu99 -O{s,2,3} -mlongcalls -ffunction-sections \
    -Ilib/ed25519_fast/src lib/ed25519_fast/src/ed25519_fast.c
xtensa-esp32-elf-objdump -d --section=.text.fe25519_mul
```

`fe25519_mul`:

| level | bytes | insns | multiplies | load/store | `bltu` |
|---|---:|---:|---:|---:|---:|
| `-Os` | 3145 | 1284 | 203 | 288 | 114 |
| `-O2` | 3268 | 1331 | 203 | **335** | 114 |
| `-O3` | 3268 | 1331 | 203 | **335** | 114 |

`fe25519_sq`:

| level | bytes | insns | multiplies | load/store | `bltu` |
|---|---:|---:|---:|---:|---:|
| `-Os` | 1923 | 791 | 113 | 165 | 69 |
| `-O2` | 2015 | 829 | 113 | **202** | 69 |
| `-O3` | 2015 | 829 | 113 | **202** | 69 |

**`-O3` and `-Os` emit the identical number of multiplies and the identical
number of carry branches.** Everything `-O3` adds is 47 more loads and stores
and 123 more bytes. There is no arithmetic gain at all - only spill traffic and
code growth. That is a static, reproducible explanation for the result
`ASSEMBLY.md` recorded as a surprise: vendored `-O3` benchmarks *slower* than
prebuilt `-Os` (0.94x in `edbench`, 0.76x in the larger `batchbench` image),
and recovers at `-O2`. The compiler is not
finding parallelism at higher levels on this function; it is only unrolling into
a register file that cannot hold the working set.

### Where the 1284 instructions go

Three costs, and the interesting thing is which one is *not* the problem.

**Multiplies: already optimal.** Xtensa LX6 has no 32x32->64 multiply; it has
`mull` for the low word and `mulsh`/`muluh` for the high, so a full product is
two instructions. A 10-limb schoolbook product is 100 partial products plus the
`*19` reduction terms, so roughly 100-110 64-bit products, or 200-220
instructions. The compiler emits 203. **There is nothing to win here** - a hand
written multiply cannot issue fewer multiplies than the algorithm requires, and
GCC is already at the floor. This matters because "write `fe25519_mul` in
assembly" implicitly assumes the multiplier is the bottleneck, and it is not.

**Carry detection: ~27% of the function, and entirely an ISA artifact.** Every
`bltu` is this idiom:

```
  fb:  mull    a2, a6, a14
  fe:  mulsh   a15, a6, a14
 101:  add.n   a2, a13, a2
 103:  movi.n  a14, 1
 105:  bltu    a2, a13, 10a      ; sum < addend  =>  a carry came out
 108:  movi.n  a14, 0
 10a:  add.n   a3, a3, a15
 10c:  add.n   a3, a14, a3
```

LX6 has neither add-with-carry nor set-on-less-than, so detecting the carry out
of a 64-bit accumulation costs two `movi` and a data-dependent branch. At three
instructions per site, 114 sites is roughly 342 instructions - about a quarter
of the function - spent on bookkeeping rather than arithmetic, and the branches
are on data, so they are not free even when predicted.

**Spills: 288 loads and stores for 30 words of live data.** Two 10-limb inputs
and one 10-limb output is 30 words against 16 architectural registers, so the
64-bit accumulators live on the stack. `-O3` makes this strictly worse (335).

Approximate split at `-Os`:

| | instructions | share |
|---|---:|---:|
| multiplies | 203 | 16% |
| carry detection (`movi`/`bltu`/`movi`) | ~342 | 27% |
| loads and stores | 288 | 22% |
| adds and the rest | ~451 | 35% |

### What this means for the assembly plan

The target is not the multiplier, it is the **half of the function spent on
carry handling and spills**. That changes the approach:

- **Delay the carries - try this first, it is portable C.** ref10 limbs are
  <= 26 bits, so partial products are <= 52 bits and several can be summed in a
  64-bit accumulator before anything can escape. Propagating once per column
  instead of once per accumulation attacks the whole 27% without writing a line
  of assembly, and it can be developed and proven on the host in seconds with
  the existing test suite.
- **Make the carry branchless.** `movltz`/`moveqz` conditional moves *are* in
  the ESP32 core, so the `movi`/`bltu`/`movi` triple can become a compare plus a
  conditional move, or the standard bit trick
  `carry = ((a & b) | ((a | b) & ~sum)) >> 31`. This trades a data-dependent
  branch for one or two extra ALU ops - worth measuring, not obviously a win on
  instruction count alone.
- **Investigate MAC16.** The assembler accepts `umul.aa.ll`, `mula.dd.ll`,
  `ldinc` and `rsr.acclo` for the `esp32` target, which suggests a 40-bit `ACCX`
  multiply-accumulate path that would remove the carry idiom at its root.
  **Unverified on silicon** - the assembler accepting a mnemonic only proves the
  binutils config allows it, not that this core implements the option. Confirm
  with a one-instruction probe on the board (an unimplemented option raises an
  illegal-instruction exception) before designing anything around it.
  `ASSEMBLY.md` does not consider this path at all.
- **Register pressure caps the win.** Any hand-written version faces the same 16
  registers and the same 30 words. This bounds what is achievable and looked
  consistent with `ASSEMBLY.md`'s 10-20% estimate.

**E8 has since built it and measured it, and this section was too optimistic.**
The carry idiom really is the only target, and removing it really does cut 12%
of the instructions - and the function got 3.4% faster, because the instructions
GCC wastes were sitting in the shadow of the multiplier latency. Read E8 before
acting on anything above.

And the caveat from E4 still dominates: after batching, `fe25519_mul` is a
smaller share of the remaining work, so a 15% win on it is worth
correspondingly less. The honest ranking is that **the `-O2`/`-Os` flag choice
and the authority-key cache are both larger, cheaper wins than any of this.**

---

## E7. Both cores, one signature at a time

`src/mcbench.cpp`, `env:mcbench`. E5 measured the batch on two cores and left
the per-signature two-core figure as a projection - "about half, because the
batch scaled that way". A projection is the wrong thing for a decision about
whether to accept a consensus divergence to rest on, so this measures it.

Everything here is ordinary ref10 verification of one signature at a time.
Nothing about the accepted or rejected set changes, which is the entire point:
this arm needs no answer to the Substrate question before it can ship.

Two flashes cannot be compared by absolute milliseconds - E5 measured a 4%
spread on byte-identical libsodium across images, from instruction-cache layout
alone. So every image times the framework's prebuilt libsodium as an in-image
anchor, and the arms are read as ratios to it.

| 403 signatures, `-Os`        | wall | ms/sig | vs 1-core prebuilt |
|---|---:|---:|---:|
| one core, prebuilt libsodium | 7.59 s | 18.828 | 1.00x |
| one core, vendored ref10     | 7.14 s | 17.708 | **1.06x** |
| two cores, prebuilt          | 3.87 s |  9.596 | 1.96x |
| two cores, vendored          | **3.65 s** | 9.068 | **2.08x** |

Round-to-round spread was under 5 ms on every arm, so these are not noisy.

**Scaling is nearly free.** Splitting the corpus in half and pinning one half to
each core:

| | core0 busy | core1 busy | wall | parallel efficiency | per-core slowdown |
|---|---:|---:|---:|---:|---:|
| prebuilt | 3847 ms | 3853 ms | 3867 ms | 0.981 | 1.015 |
| vendored | 3636 ms | 3639 ms | 3654 ms | 0.976 | 1.019 |

The two cores finish within 4 ms of each other and each runs 1.5-2% slower than
it does alone. That residual is the shared instruction cache and the memory bus,
and it is the whole cost of the second core. There is nothing to tune: the work
is uniform, so half each is optimal and no scheduler is needed.

**What this does to the batch's case.** Comparing ratios within each image, as
E5 requires:

| | speedup vs that image's 1-core prebuilt anchor |
|---|---:|
| per-signature, two cores (E7) | 2.08x |
| batch chunk 512, two cores (E5) | 2.39x |

The batch is worth **1.15x over the semantics-preserving path** - about 0.4
seconds on a 403-signature justification. That is the entire return on the
cofactored/cofactorless divergence, the 91 KB of state, the per-signature
fallback path, and the unanswered question about what Substrate accepts.

Put the other way: of the 2.39x the batch appeared to deliver, `-Os` and the
second core account for 2.08x of it, and neither changes a single accepted or
rejected signature.

Note also that **production already has this shape**. `src/sigpool.cpp` runs a
verification worker on the other core and `grandpa.c` falls back to verifying
inline whenever the queue is full, which balances the split without tuning. What
it does not yet do is use the vendored verifier - it calls the prebuilt
`lc_ed25519_verify` - so the 1.06x above is available and unclaimed. That swap
should be measured in the production image before it is made, because E5's
4%-across-images result means a 6% win measured in a benchmark image is not
automatically a 6% win in a 360 KB one.

---

## E8. The handwritten assembly, measured

`lib/ed25519_fast/src/fe25519_mul_xtensa.S`, generated by
`tools/gen_fe25519_mul.py`, built by `env:mcbench_asm`.

E6 said the multiplier is at its algorithmic floor and the recoverable cost is
the carry idiom. This is that idea carried out. GCC spends eight instructions
folding one product into a 64-bit accumulator, and it selects the carry into a
register before adding it unconditionally:

```
mull  t0, f, g          mull   t0, f, g
mulsh t1, f, g          mulsh  t1, f, g
add.n lo, lo, t0        add.n  lo, lo, t0
movi.n c, 1             add.n  hi, hi, t1
bltu  lo, t0, L         bgeu   lo, t0, L
movi.n c, 0             addi.n hi, hi, 1
L: add.n hi, hi, t1   L:
   add.n hi, hi, c
        GCC: 8                  by hand: 6
```

In assembly the branch can skip the increment instead of selecting it. On 100
products that is 200 instructions, and it is the only real idea in the file.

The function is generated rather than typed, because 100 products and a 12-step
carry chain is a place where one transposed index is a consensus bug that shows
up on one input in 2^30. The term table in the generator is pasted verbatim from
ref10's header and parsed; every instruction implementing it was still chosen by
hand. `python3 tools/gen_fe25519_mul.py --c` emits the same table as portable C,
which was checked against ref10 on the host over **2.2 million random and
extreme inputs, including both aliasings, with zero mismatches**, before any of
it went near the board.

### What it cost to get right

Two bugs, both structural rather than arithmetic, both fatal, and neither
detectable by reading the code:

- **Registers above a11.** The function is reached by `call8`, which rotates the
  register window by 8, and a callee entered that way owns a0-a11. a12-a15 are
  the next window and belong to whatever frame the hardware has not spilled yet.
  Writing them assembles, runs, computes the right answer, and corrupts the
  caller's frame on return: `Double exception`, `EXCCAUSE 2`, shredded
  backtrace. GCC's own `fe25519_mul` uses a10-a15, which is not a licence to
  copy - GCC emitted every call site in the image and can widen them.
- **The top of the stack frame.** A windowed frame is reserved at both ends. The
  bottom 16 bytes are the usual base save area; the top 32 are where
  `_WindowOverflow8` spills the interrupted frame's a0-a7 - which is to say,
  into this frame. Locals put there survive until the first window overflow
  lands on them, which is to say until the function is called from something
  deep enough, which is to say not during any test small enough to debug. GCC
  gives this function a 192-byte frame for 120 bytes of data for exactly this
  reason.

Both are now stated in the generator, at the constants that encode them.

### The result

| | instructions | bytes | cycles per call |
|---|---:|---:|---:|
| GCC `-Os` | 1284 | 3145 | 1575 |
| handwritten | **1131** | **2806** | **1521** |
| | -11.9% | -10.8% | **-3.4%** |

Correctness first: 60,000 differential cases on the device against the C routine
(20,000 inputs, each also run through both aliasings), sampled across ref10's
full documented precondition with every eighth case pinned to a signed extreme,
plus the four hand-checkable cases and the full 1,577-check agreement suite
against the framework's prebuilt libsodium. **Zero mismatches, zero
disagreements.** The assembly is right.

It is also very nearly pointless.

| 403 signatures, `-Os`, asm image | wall | ms/sig | vs that image's anchor |
|---|---:|---:|---:|
| one core, prebuilt | 7.37 s | 18.288 | 1.00x |
| one core, vendored + asm | 7.12 s | 17.666 | 1.04x |
| two cores, prebuilt | 3.75 s | 9.308 | 1.96x |
| two cores, vendored + asm | 3.67 s | 9.096 | 2.01x |

Against the C-only image's 17.708 ms/sig, the assembly image runs 17.666 - a
0.2% difference, smaller than the 2.5% the anchor itself moved between the two
flashes. **End-to-end, this is indistinguishable from zero.**

`ASSEMBLY.md` set the stop/go threshold itself: *continue only if `fe25519_mul`
improves by at least 15% in isolation.* It improved by 3.4%. **Stop.**

### Why 12% fewer instructions bought 3% fewer cycles

1284 instructions in 1575 cycles is 1.23 cycles per instruction. 1131 in 1521 is
1.35. The handwritten version has a *worse* CPI, and it is not mysterious: it is
denser in dependencies. `add.n lo, lo, t0` uses the result of the `mull` two
slots earlier, `bgeu lo, t0` uses the result of the `add.n` one slot earlier,
and the `l32i` feeding each `mull` is two slots ahead of it. GCC's `movi`/`movi`
pair, which looks like pure waste on an instruction count, is sitting in the
shadow of the multiplier latency. Removing filler from a dependent chain does
not make the chain shorter.

The fix would be software pipelining - overlapping the next product's loads and
multiplies with the current one's accumulation. There are registers for it
(a2-a11, of which the loop uses eight) and it is the obvious next revision. It
is not obviously worth days, because the ceiling is now known: even at a perfect
1.0 CPI this function would take 1131 cycles against 1575, and the end-to-end
gain would still be bounded by whatever share of verification it owns - which,
from these two images, is small enough that a 3.4% kernel win vanished into
inter-image noise.

### The representation change that would have worked, and does not

The reason the carry idiom is there at all is that Xtensa LX6 has no
add-with-carry. The standard escape is to split each product at bit `s` and run
two 32-bit accumulators - the low `s` bits in one, the rest in the other - which
is branch-free and needs six instructions with `src` and a shift pair:

    mull / mulsh / src (>>s) / mask / add L / add H

`tools/limb_bounds.py` computes whether the accumulators can overflow, from
ref10's documented preconditions rather than from typical values:

```
 limbs  bits/limb  terms    max |h|            split s  accum insns
    10 26/25/26/25...     10     2^60.4               NONE          800
    11 24/24/23/23...     11     2^56.3              26-28          726
    12 22/22/22/21...     12     2^52.6              22-28          864
```

For ref10's layout the low accumulator needs `s <= 28` and the high one needs
`s >= 30`. **No split point exists**, and this is not a near miss to be argued
about - upstream's own comment bounds `|h0|` by `1.4*2^60`, and two 32-bit
accumulators cannot hold 60.4 bits of range. Every 64-bit carry in this function
is forced by the limb layout.

An 11-limb layout would admit the split, at 726 accumulation instructions
against 800 - about 9%. It also means re-deriving every bound and rewriting
every `fe25519_*` routine in a non-uniform 23-bit representation. That is the
"algorithmic or representation change" `ASSEMBLY.md` said would be needed to
reach 2x, and it is worth 9% of one function.

---

## E9. In production, against the real chain

Everything above was measured with WiFi down, on a fixed corpus, in an image
that contained nothing but the benchmark. This is the same change measured where
it has to work: `env:esp32dev`, radio up, signatures arriving from the network as
they are verified.

**The `-DLC_USE_FAST_ED25519` A/B, in the production image.** Four consecutive
cycles each, taken back to back against live Polkadot:

| | signatures | verify | ms/sig |
|---|---:|---:|---:|
| prebuilt libsodium | 401, 401, 401, 401 | 4730 / 4731 / 4642 / 4663 ms | 11.700 |
| vendored ref10 | 404, 410, 402 | 4465 / 4511 / 4450 ms | **11.041** |

**1.060x** - the same figure the benchmark image gave (1.06x), so the ~30 KB the
vendored copy adds to a 1.0 MB image costs nothing in instruction-cache terms.
That was not safe to assume: E5 found byte-identical libsodium moving 4% between
images from layout alone, which is exactly why this A/B was run in the image that
ships rather than inferred from E7.

About 0.27 s off a 403-signature justification.

**The second core is real, and it balances itself.** Every cycle splits close to
evenly - 207/197, 211/199, 208/194, 203/198 - with no tuning anywhere. That is
`sigpool` submitting to the worker until its 4-deep queue backs up and then
verifying inline, which turns out to be a better scheduler than a fixed split
would be, because it adapts to whatever the socket is doing.

**What a cycle actually costs.**

```
cycle took ~6,000 ms
  of which verify  ~4,450 ms   (74%)
```

Signature verification is three quarters of a sync cycle. Everything else - the
TLS session, streaming the justification, binding the header, the seven-node
Paras::Heads proof, the Asset Hub state proof - is the remaining quarter.

**Production runs slower per signature than the benchmark**, 11.04 ms/sig against
E7's 9.07 ms/sig on two cores. The benchmark had the radio off and the whole
corpus in RAM; production is verifying while the WiFi driver runs on core 0 and
the justification is still arriving over the socket. That ~22% is the cost of
doing this on a real network, and no amount of arithmetic optimisation touches
it. Worth remembering when reading any of the numbers above it.

**What the batch would be worth here.** Applying E7's measured 1.15x to the
verification share: 4.45 s -> 3.87 s, and a cycle from ~6.0 s to ~5.4 s. Roughly
10% of sync time, for a cofactored/cofactorless divergence.

### The failure that came first

The first production run reported `401 precommits, 0 valid` on every cycle. The
code names this case itself - "zero valid signatures usually means the authority
set has rotated" - but a verifier change had just landed, so the message was not
evidence. Re-flashing the identical build with the prebuilt libsodium reproduced
the failure exactly, which isolated it in one flash cycle.

The set had rotated: `checkpoint.h` was captured at relay #32,765,729 in set 3586,
and the chain had reached #32,783,700 in **set 3587** - about 30 hours and one era
later. Regenerating it fixed it.

Two things worth keeping from that:

- **A stale trust root and a broken verifier present identically.** Both give
  zero valid signatures out of a full precommit set. The only cheap
  discriminator is to swap the verifier back, so it is worth being able to do
  that in one command - which is what keeping `LC_USE_FAST_ED25519` a flag,
  rather than editing `lc_crypto.c` in place, buys.
- **`checkpoint.h` is a trust root, and regenerating it is not a build step.**
  `tools/gen_checkpoint.py` prints `SANITY-CHECK set_id AND THE BLOCK HASH
  BEFORE FLASHING` for a reason: a device flashed with a checkpoint follows
  whatever chain those 600 authorities sign. The current one is set 3587 at
  #32,783,803, hash `0x2ee35ce4...05d91b`, and it should be checked against an
  explorer by someone rather than taken from this log.

---

## E10. Where a verification's time actually goes, on the device

`env:mcbench`, `-Os`, one core, each phase looped internally so the timer is
swamped and nothing can be optimised away. This is step 1 of `ASSEMBLY.md`'s
spike - an exclusive breakdown on real silicon - and it had never been run, which
means every claim in this document about which part of verification is worth
attacking was, until now, an estimate.

| phase | us | share |
|---|---:|---:|
| input screening (canonicality, small order) | 27.2 | 0.2% |
| SHA-512 over 117 bytes | 194.5 | 1.1% |
| `sc25519_reduce` | 14.8 | 0.1% |
| **decompress A** | **1163.3** | **6.6%** |
| **build `Ai[8]`** | **478.9** | **2.7%** |
| double scalar multiplication (table included) | 14568.7 | 83.1% |
| `ge25519_tobytes` + compare | 1088.4 | 6.2% |
| **whole verification** | **17534.1** | 100% |

Three things fall out of this, and they reorder the whole remaining plan.

**1. The scalar multiplication is 83%, and it is the floor.** 256 doublings and
a sliding window of additions. Nothing in E6 or E8 touches its structure, which
is why a 12% instruction cut in `fe25519_mul` produced a 3% kernel win and
nothing measurable end to end. Any further arithmetic tuning is bounded by this
number.

**2. 9.4% is spent recomputing 600 constants.** Decompressing A and building
`Ai[8]` depend on **nothing but the public key**. There are 600 authorities, the
set is fixed for an era, and this work is redone on every one of ~403 signatures,
every cycle, forever. `ge25519_frombytes_negate_vartime` alone is 6.6% because it
runs `fe25519_pow22523` - roughly 250 field operations to recover one coordinate
that was already known when `checkpoint.h` was generated.

The fix costs no RAM at all. `Ai[8]` is what
`ge25519_double_scalarmult_vartime` actually consumes - A is only used to build
it - so `tools/gen_checkpoint.py` can emit the eight cached points per authority
straight into `checkpoint.h`, and the runtime work becomes a table lookup. At
`8 * sizeof(ge25519_cached)` that is 1280 bytes per authority, 768 KB for 600,
against 2.1 MB of free flash in the current 1.0 MB image. **Zero heap** - which
matters, because production runs with 94 KB free and a 49 KB largest block, so
the obvious "cache it in RAM" version does not fit and was never going to.

This is bookkeeping, not cryptography, and it is now the best remaining item by a
distance: 9.4% measured, against the batch's 1.15x on the whole justification and
its consensus divergence.

It also opens a second door for free. The window width is a compile-time choice
in `slide_vartime`; a wider window means more precomputed odd multiples and fewer
additions in the 83%. Today `Ai[8]` is built per signature, so a wider window
would cost more to build than it saves. Precomputed in flash, `Ai[16]` costs the
same at runtime as `Ai[8]` and strictly fewer additions in the main loop. Size
this before assuming it - it is a real but unmeasured effect, and 768 KB becomes
1.5 MB.

**3. `ge25519_tobytes` is 6.2%, and it is not free to remove.** The cost is a
field inversion to get an affine y. The standard escape is to compare
projectively against the decoded `R` instead of re-encoding, cross-multiplying
by the Z coordinates. That is **a semantic change of exactly the kind the batch
makes**: libsodium compares encoded bytes and therefore rejects a non-canonical
`R` encoding, while a projective comparison accepts it. It belongs in the same
gated category as the cofactor question, and it is worth 6.2% rather than 15%,
so it should be the last thing anyone reaches for.

### What the ceiling looks like

Against today's production 11.04 ms/sig and 4.45 s per justification (E9):

| | ms/sig | per justification | semantics |
|---|---:|---:|---|
| today | 11.04 | 4.45 s | - |
| + authority tables in flash | ~10.0 | ~4.03 s | unchanged |
| + wider window (unmeasured) | ? | ? | unchanged |
| + batch instead of per-signature | ~9.6 | ~3.87 s | **diverges** |
| perfect everything except the scalar mult | ~9.2 | ~3.70 s | unchanged |

> Row 2 has since been built and measured, and it beat this estimate: **1.128x,
> not the 1.10x projected here**, because Duif-form entries also make the 83%
> slightly cheaper. See E11.

The last row is the wall. 83% of a verification is 256 point doublings and a
sliding window, and short of a different curve, a different algorithm, or
different silicon, that is what a GRANDPA justification costs on an ESP32.

---

## E11. The authority tables, built and measured

E10 said 9.4% of a verification is spent rebuilding constants that are fixed for
an era. This is that change, shipped.

`tools/gen_checkpoint.py` now also writes `src/checkpoint_precomp.c`: for each of
the 600 authority keys, the eight odd multiples `A, 3A, ... 15A` of the decoded
(negated) point. `lc_ed25519_verify_pre()` takes that table instead of running
`ge25519_frombytes_negate_vartime` and the eight-entry build, and `grandpa.c`
selects it with the authority index the duplicate check has already paid for.

Two decisions in the shape of it are worth recording, because both turned out to
matter more than expected.

**The entries are `ge25519_precomp`, not `ge25519_cached`.** E10 sized this as
`8 * sizeof(ge25519_cached)` = 1280 bytes per authority. Duif form - `yplusx`,
`yminusx`, `xy2d`, with Z implied to be 1 - is 960 bytes instead, and it is what
`ge25519_madd`/`ge25519_msub` consume. ref10 already reserves those for its own
fixed base-point table `Bi[8]`; they skip the `fe25519_mul(r->X, p->Z, q->Z)`
that `ge25519_add` needs, which removes one field multiplication from each of the
~43 additions a 256-bit sliding-window scalar makes. **That is why the measured
saving is 11.1% and not the predicted 9.3%** - the table is smaller *and* the
83% gets slightly cheaper. E2 had already noticed Duif form was the better
representation and left it as a note; this is where it pays.

**The tables are correct as points, not as bytes.** ref10's field elements are
not canonical: the same point has many limb representations depending on which
addition chain produced it. Writing affine coordinates out in radix-2^25.5 is
therefore exactly as correct as reproducing ref10's own chain would be - the
result is compared after `ge25519_tobytes`, which reduces - and it means the
generator can be 90 lines of Python big-integer arithmetic rather than a
limb-level transcription of ref10 that would have to be right in the same way
for a different reason.

That freedom is worth spending on headroom rather than on brevity. The plain
split gives limbs in `[0, 2^26)`, already inside `fe25519_mul`'s documented
`|f_i| <= 1.65*2^26` precondition; the generator instead carries with
round-to-nearest and emits **signed balanced limbs**, halving the magnitude and
matching the convention of ref10's own precomputed table in `fe_25_5/base2.h`.
These entries are consumed by exactly the same `ge25519_madd`/`ge25519_msub` as
that table, so there was no reason for them to live in a wider range than it
does, and every reason not to invent one here.

### Measured, `env:mcbench`, one image, interleaved

The corpus is set 3585 and the flashed tables are set 3587, so 390 of its 403
signers still hold a seat. **All three arms run over those same 390 records**, so
the ratios are not comparing different work, and the tables being read are
`src/checkpoint_precomp.c` out of memory-mapped flash rather than a fixture built
for the benchmark.

| | one core | two cores | ms/sig, 1 core | ms/sig, 2 cores |
|---|---:|---:|---:|---:|
| prebuilt libsodium `-Os` | 7.55 s | 3.85 s | 19.363 | 9.877 |
| vendored ref10 `-Os` | 6.97 s | 3.57 s | 17.866 | 9.155 |
| **vendored + tables** | **6.19 s** | **3.16 s** | **15.877** | **8.114** |

Three rounds, spread under 0.2% within each arm.

**Tables against the same verifier without them: 1.125x on one core, 1.128x on
two - 11.1% and 11.4% off.** Against the framework's prebuilt libsodium, which
is where this project started, two cores with tables is **2.39x**.

Parallel efficiency is unchanged at 0.978, so the 562 KB of new read-only data
does not cost anything in cache terms - which was not obvious in advance, given
E5 found image size alone moving byte-identical code by 4%.

### In production, against the real chain

`env:esp32dev`, radio up, live Polkadot, signatures arriving over TLS as they are
verified - the same conditions as E9, so the numbers are directly comparable.

| | signatures | verify | ms/sig |
|---|---:|---:|---:|
| vendored ref10, no tables (E9) | 404, 410, 402 | 4465 / 4511 / 4450 ms | 11.041 |
| **vendored + tables** | 401, 401, 401, 410 | **3974 / 3949 / 3986 / 4004 ms** | **9.866** |

**1.119x in production**, against 1.128x in the benchmark image - close enough
that the 562 KB of new read-only data is again costing nothing in cache terms.
About 0.48 s off a justification, and a full refresh cycle from ~6.0 s to
**5.30-5.35 s**.

The self-split across cores is unchanged: 206/195, 208/193, 207/194, 212/198.
Heap is 94,820 free with a 49,140 B largest block, both within noise of the
94,768 / 49,140 E9 recorded - the tables are in flash and touch neither.

Cumulatively, against the framework's prebuilt libsodium where this started, the
justification step has gone 4.70 s -> 4.45 s -> **3.97 s**, all of it without one
accepted or rejected signature changing.

> The 5.30-5.35 s cycle is now 4.95-5.01 s: PLAN 14 replaced the timer with a
> finalized-head subscription, which also deleted the `chain_getFinalizedHead` +
> `chain_getHeader` pair the cycle used to open with. That is transport, not
> arithmetic - the justification step is unmoved at 3.96-4.10 s - but it moves
> ed25519 from 75% of a cycle to **80%**, so the ranked steps below are worth
> slightly more than they were when they were written.

### What it accepts

Nothing changed, and this is the claim the work stands or falls on.

- **Host, `test/run_pre.sh`, in under a second.** All 600 generated tables hold
  the same eight points ref10 derives from the same keys, compared as reduced
  encodings. Then 1,860 verification inputs - the 403 real precommits, all 512
  signature bit flips, all 256 key bit flips, eight edge encodings in each of
  three positions, S+L and S+2L, 63 swapped-key forgeries and 600 random inputs -
  decided identically by the table path and by libsodium's
  `crypto_sign_verify_detached`. Zero disagreements.
- **The table has to be load-bearing, or none of that means anything.** A
  verification handed another authority's table must fail, and one handed an
  all-zero table must fail. Both are asserted, and the first of them caught a
  bug in the test itself: the first corpus signer *is* a current authority, so
  "another authority's table" has to skip its own.
- **Device, `env:mcbench`.** 903 checks against the prebuilt libsodium in the
  same image - the 390 corpus records through their real table pointers, 512
  signature bit flips, one wrong table. Zero disagreements. This is not a second
  copy of the host suite; it answers the different question of whether the bytes
  in *this linked image* are the tables the host checked, which a truncated
  array or a partial flash would break without changing a line of source.
- **Device, in production.** `self_test_grandpa()` now takes the precommit that
  just came off the wire and verifies it through the flashed table, then through
  a neighbouring authority's table, and requires accept and reject respectively.

### Two ways this could go wrong operationally, and what stops them

The tables are a **cache of `checkpoint.h`, not a second trust root** - derived
from those keys by arithmetic and nothing else. But a cache that falls behind
its source is exactly how a fail-closed system fails confusingly:

- **A stale table with fresh keys** would reject every signature, which looks
  identical to the authority set having rotated - the failure E9 already spent a
  session on. `src/main.cpp` `#error`s if the two disagree on `set_id` or count.
- **Regenerating the cache must not be able to rotate the trust root.**
  `gen_checkpoint.py --precomp-only` reads the keys back out of the existing
  `checkpoint.h` and touches no network at all, so rebuilding tables cannot
  silently move the device onto a different chain.

`env:esp32dev` grew from 32.9% to 51.3% of its 3 MB app partition (1,035,957 ->
1,614,225 bytes) and did not move RAM at all: 98,476 bytes either way. The
RAM version of this idea never fit - production runs with 94 KB free and a
49 KB largest block against 562 KB of tables - so flash was not a convenience
here, it was the only version that works.

---

## E12. BEEFY, priced against what we already have

BEEFY is the protocol built for light clients, so the question is fair: how much
of the 3.96-4.10 s justification would it save? Measured where it could be
measured, and the answer is **none of it**. Every second BEEFY appears to save
comes from *sampling*, and sampling is not a BEEFY feature - it is available
against GRANDPA today, on this device, with no new protocol and no new node.

### Per signature: secp256k1 is not the win

BEEFY validators sign with **ECDSA over secp256k1, hashed with keccak256** -
chosen so an Ethereum contract could verify commitments with the `ecrecover`
precompile, not because the curve is cheap in software. Both primitives measured
on the same host through the same FFI overhead, on a 53-byte message:

| Primitive | Library | Verify |
|---|---|---:|
| ed25519 | libsodium (what the device runs) | 22.47 us |
| ECDSA secp256k1, verify | libsecp256k1 | 13.60 us (**0.61x**) |
| ECDSA secp256k1, recover | libsecp256k1 | 16.95 us (0.75x) |

secp256k1 looks 1.3-1.6x cheaper, and that number should not be trusted on this
board. libsecp256k1 earns it with the GLV endomorphism, a wide wNAF and a large
precomputed generator table, all tuned for 64-bit limbs; on a 32-bit target it
falls back to the 10x26 field representation, which is the representation ref10
was designed around in the first place. OpenSSL, which implements secp256k1
through its generic EC path with none of that tuning, verifies the same curve at
**125.9 us - 3.5x slower than its own ed25519**. The spread between 0.61x and
3.5x is entirely implementation, so the honest statement is that on Xtensa the
two are **within a factor of about 1.5 in one direction or the other, and it
cannot be settled without flashing a benchmark**.

Even taking the flattering 0.61x at face value: 401 signatures at 0.61x is 2.4 s
against 3.96 s. A cycle goes 4.97 s -> 3.4 s. That is the entire per-signature
prize, it requires the optimistic end of a factor nobody has measured here, and
it costs a new curve, a new hash and a new protocol to collect.

BEEFY also adds work per signature that GRANDPA does not have. The validator set
reaches the client as a **Merkle root**, not a list, so each checked signature
carries a ~10-node inclusion proof - roughly 3 ms at this board's measured
0.30 ms per 256-byte node, about +15% on a 19.3 ms signature. GRANDPA's
authorities are already in flash, indexed, with their precomputed tables (E11).

### The count is the win, and it is not BEEFY's

The Snowbridge client does not verify 400 signatures. It verifies a random
sample, sized by

> N = ceil(log2(R * V * (1/S) * (75+E) * 172.8)) + 1 + 2*ceil(log2(C))

with V the validator count, C a validator's prior uses, and R, S, E the
relayer's stake ratio, the slash rate and the RANDAO commitment expiry. Three of
those five inputs are **Ethereum economics** - a bonded relayer that can be
slashed, and RANDAO as an unpredictable seed the prover cannot grind. Neither
exists here, so the ~25 figure quoted in PLAN.md 1 does not transfer.

What does transfer is the argument underneath it, and it is not specific to
BEEFY. Any threshold-signature list works: to be accepted a justification needs
2/3 of the set, an adversary holding under 1/3 can produce at most 1/3 valid, so
**at least half of the claimed signatures must be forged**. Check `m` at random
and a forgery survives with probability at most 2^-m.

This device is in a *better* position than a contract to use that. It picks the
sample itself, locally, after the full list has arrived, from `esp_random()` -
which is a true RNG precisely because the radio is up. The server never learns
the choice and so cannot grind it. No RANDAO, no bond, no relayer.

**And it applies to the GRANDPA justification the device already downloads.**
At the measured 19.3 ms per signature per core, across two cores:

| sampled | verify | cycle | vs today |
|---:|---:|---:|---:|
| 401 (today, all) | 3,960-4,098 ms | 4,938-5,010 ms | 1.00x |
| 80 | ~772 ms | ~1.78 s | **2.8x** |
| 64 | ~618 ms | ~1.63 s | 3.1x |
| 30 | ~290 ms | ~1.30 s | 3.8x |

**Size `m` against the attacker's whole budget, not against one attempt.** A
rejected sample costs the server nothing, and the device asks for a fresh
justification every ~5 s: about 6.3 million attempts a year, 2^22.6. At m=30
that leaves 2^-7.4 over a year, which is not a security margin. m=64 gives
2^-41, m=80 gives 2^-57 - the range worth considering starts at 64, not at 25.
The table above is why the difference costs about 480 ms and should simply be
paid.

### It collides head-on with the one rule this project has

ASSEMBLY.md: *the accepted and rejected signature set must remain identical to
the existing libsodium verifier.* Sampling breaks that on purpose. It accepts
justifications full verification would reject, with probability 2^-m - a
**smaller** gap than the cofactored batch's (which is deterministic and
constructible by any authority, see the next section), but a real one, and of
the same kind that got the batch verifier held back.

The difference is that this one is a dial. 2^-80 is not a hazard anybody has to
reason about; 2^-30 is. That is a decision, not a finding, and it belongs to
whoever owns the trust root.

### The blocker is still the blocker, re-checked today

None of the above is reachable through BEEFY anyway. `mmr_generateProof`, which
is what binds a signed commitment to an actual header, **still fails on public
infrastructure** (2026-08-31):

```
rpc.polkadot.io      {"code":8011,"message":"Leaf was not found","data":"LeafNotFound"}
OnFinality           {"code":8011,"message":"Leaf was not found","data":"LeafNotFound"}
```

`mmr_root` and `beefy_getFinalizedHead` both answer fine - it is only the leaf
proofs that are missing, because MMR leaves live in each node's offchain DB and
public nodes do not run with `--enable-offchain-indexing true`. Unchanged since
PLAN.md 1 first recorded it.

### And BEEFY is behind

BEEFY finality trails GRANDPA finality. Six samples, ~7 s apart:

| beefy | grandpa | lag |
|---:|---:|---:|
| 32,796,291 | 32,796,293 | 2 blocks (~12 s) |
| 32,796,291 | 32,796,294 | 3 blocks (~18 s) |
| 32,796,291 | 32,796,294 | 3 blocks (~18 s) |
| 32,796,291 | 32,796,294 | 3 blocks (~18 s) |
| 32,796,291 | 32,796,297 | 6 blocks (~36 s) |
| 32,796,299 | 32,796,300 | 1 block (~6 s) |

The BEEFY head sat still for four samples and then jumped eight blocks, which is
what signing at intervals rather than per block looks like. A device that today
proves the newest finalized head every ~5 s would be proving a head **1-6 blocks
old**, and the panel's whole premise is that what it shows is fresh. Faster
cycles against staler data is not obviously a trade worth making.

### Verdict

BEEFY buys, at most, an unmeasured per-signature factor that could go either
way; it costs a new curve, a Merkle proof per signature, a self-hosted archive
node, and 1-6 blocks of freshness. The thing actually worth having from it - the
sampling argument - needs none of that and can be pointed at the justification
the device already has in RAM. **If sampling is ever acceptable, do it on
GRANDPA. If it is not, BEEFY does not help.**

One thing BEEFY does have that sampling does not: the MMR leaf carries
`beefy_next_authority_set`, so a client can follow set rotation from a proof
instead of a reflash. That is the standing operational wound here - the trust
root goes stale roughly daily - and it is worth noting that the fix for it is
the *one* part of BEEFY that has nothing to do with speed.
---

## The semantic gap: the decision this turns on

**This is not a footnote, and it is the reason to stop before shipping.**

The batch equation is cofactored - the sum is multiplied by 8 before the
comparison, which is what makes the random-weight argument sound over the full
group. libsodium's per-signature check is cofactorless. They agree on every
input tested except one class:

> a signature whose residual `R + hA - sB` is a non-zero point of order 1, 2, 4
> or 8. libsodium rejects those. A cofactored batch accepts them.

This is not exotic. **Any authority can construct one from its own key**: pick
`r`, commit to `R = rB + T` for a torsion point `T` instead of `rB`, and sign
normally. `torsion_divergence()` in `test/test_ed25519.c` builds exactly that
and asserts the disagreement, including inside a full 403-signature batch, so
the gap is a measured fact that a future change cannot quietly erase.

**Why it matters.** Polkadot's threshold is 401 of 600. A rogue authority could
produce a vote this light client counts and Substrate does not, taking a
justification from 400 to 401 in our view only - we would consider a block final
that the network does not. That is a safety failure, narrow but real: it needs
one malicious authority and a justification sitting exactly on the margin.

**Why it cannot simply be fixed.** The failure mode needs the residual's torsion
component to be zero, and the torsion group is Z/8. Any single linear check over
a group that small has a collision probability of at least 1/8, and an attacker
choosing an order-2 residual gets 1/2. Dropping the cofactor multiply makes the
batch *stricter* but only takes the attacker's odds from 1 to at worst 1/2,
which is not a security argument. Reaching 2^-128 would need about 43
independent checks. Testing each `R_i` for torsion directly costs a
scalar multiplication by L per signature, which is the entire saving and more.

So the options are genuinely:

1. **Accept the difference and document it.** This is what ed25519-dalek and
   ed25519-zebra do, and Zebra is a consensus system. The exposure is bounded:
   the divergence can only ever *add* a vote from a key already in the authority
   set, and never removes one, so we can never reject what Substrate accepts.
2. **Establish what Substrate itself does** before deciding. Our verifier is
   libsodium; Substrate's GRANDPA is ed25519-dalek. If those two already differ
   on small-order or non-canonical keys, then this codebase has a pre-existing
   divergence that matters more than the one introduced here, and the right fix
   is to match dalek rather than libsodium. **This is unresolved and is the next
   thing to settle.** It is a question about Substrate's source, not about
   arithmetic, and it should be answered before any of this ships.
3. **Batch as a fast path only where the margin is comfortable**: use the batch
   result when the counted weight clears the threshold by more than the largest
   plausible number of rogue authorities, and fall back to per-signature
   verification when the justification is near the margin. Costs nothing in the
   common case and closes the attack, at the price of a rule that has to be
   argued for.

Everything else - non-canonical scalars, non-canonical point encodings,
small-order `R` or `A`, points off the curve - is rejected by the batch exactly
as libsodium rejects it, in libsodium's order, and this is tested on 1,797
inputs on the host and again on the board.

Two checks in `lc_batch_add()` exist only because of this. The per-signature
verifier re-encodes the recomputed `R` and compares bytes, so it gets rejection
of a non-canonical `R` encoding, and of an `R` that is not a curve point at all,
for free. The batch decodes `R` and uses it, so both have to be rejected
explicitly or it would accept signatures libsodium does not.

---

## What the tests cover

`sh test/run_ed.sh` - 31 assertions, 0.4 s:

- SHA-512 against published vectors at every block boundary and at 117 bytes,
  the length production actually hashes.
- All 403 captured precommits verify, through both the fast path and the
  libsodium transcription.
- Signed-digit recoding round-trips 4,000 scalars.
- The batch accepts the corpus, an empty batch, **every prefix length 1..403**
  (so no chunk fold is mishandled), and holds under 200 different weight seeds.
- **Single-bit corruption**: all 512 flips of a signature and all 256 of a
  public key, each inside a full 403-signature batch; all 424 flips of the
  payload, so a wrong `set_id` or round cannot pass; and a flipped bit at every
  one of the 403 positions in the batch.
- Batch and per-signature agree on 1,797 inputs: the corpus, every bit flip, the
  eight small-order encodings and `p-1`/`p`/`p+1` substituted for the key, for
  `R` and for `S`, non-canonical `S+L` and `S+2L`, and 600 random inputs.
- Forgeries that are individually well-formed: two swapped signatures, a
  signature replayed under another authority's key, and the whole corpus against
  a neighbouring round - each under 100-300 weight seeds, because these are the
  ones the 2^-128 argument is responsible for.
- The known divergence, asserted rather than assumed.
- The streaming API: sticky failure, early rejection without group arithmetic,
  and refusal of an over-long message.

`sh test/run_pre.sh` - 8 assertions, under a second, covering the precomputed
authority tables (E11). It is deliberately two separable claims rather than one
end-to-end sweep, because they can fail independently:

- **The tables are the right points.** All 600 generated tables hold the same
  eight points ref10 derives from the same keys, compared as reduced encodings
  because ref10's field elements are not canonical. Plus the `set_id` and count
  binding the tables to `checkpoint.h`.
- **The verdicts are libsodium's.** 1,860 inputs decided identically by the
  table path and `crypto_sign_verify_detached`: the 403 real precommits, all 512
  signature bit flips, all 256 key bit flips, eight edge encodings in each of
  three positions, `S+L` and `S+2L`, 63 swapped-key forgeries, 600 random
  inputs. A key that does not decode has no table, and is asserted to be one the
  reference rejects too - refusing to build must never be the more permissive
  answer.
- **The table is load-bearing.** A signature checked against another authority's
  table, and against an all-zero table, must fail; a `NULL` table must fall back
  and still verify the whole corpus. Without these, tables full of zeros pass
  everything above.

Three more suites cover the assembly, because the host cannot vouch for
instruction encoding and the device is a slow place to be exhaustive:

- **The term table, on the host.** `python3 tools/gen_fe25519_mul.py --c` emits
  the generator's product table and carry chain as portable C; 2.2 million
  random and extreme inputs against ref10's own `fe25519_mul`, including both
  aliasings, zero mismatches. This is what stops a transposed index, and it runs
  in seconds.
- **The encoding, on the device.** `env:mcbench_asm` runs `lc_fe25519_difftest`
  before it times anything and refuses to report a number if it fails: 20,000
  inputs x 3 (direct, `h == f`, `h == g`), sampled across ref10's full
  *documented* precondition rather than the range the verifier happens to
  produce, with every eighth case pinned to a signed extreme. Plus four
  hand-checkable cases printed one at a time with the port flushed between them,
  so a fault names an instruction instead of a sweep.
- **The whole verifier, against what production actually runs.** `env:mcbench`
  and `env:mcbench_asm` both check the vendored verifier against the framework's
  **prebuilt libsodium** on 1,577 inputs: all 403 precommits, all 512 signature
  bit flips, all 256 key bit flips, 126 swapped-key and swapped-signature
  forgeries, the eight small-order and non-canonical encodings substituted for
  `R` and for `A`, an out-of-range `S`, and 256 deterministic garbage inputs.
  Zero disagreements on both images.

`env:mcbench` additionally checks **the tables as linked into that image** - 903
inputs against the same prebuilt libsodium - and `src/main.cpp`'s
`self_test_grandpa()` checks them **in production against a precommit that just
came off the wire**, accepting through the signer's table and rejecting through a
neighbour's. The host suite vouches for the tables in the repository; only the
board can vouch for the bytes in the image.

---

## Ranked next steps

Ordered by measured gain per unit of effort and risk. Everything above item 4 is
semantics-preserving: it changes what the light client costs, not what it
accepts.

1. **Take the second core and the vendored verifier at `-Os`.** (E5, E7.)
   2.08x, measured, and not one accepted or rejected signature changes. Two
   parts, and the first is already done:

   - `lib/ed25519_fast/library.json` declines to set an optimisation level and
     `env:esp32dev` adds none, so **a production build already inherits the
     framework's `-Os` and is correct.** Nothing to fix; the thing to do is not
     to "helpfully" add `-O3` later. `ASSEMBLY.md`'s 0.94-0.95x for the vendored
     path, and the 0.76x in the larger `batchbench` image, are both `-O3`
     artifacts - at `-Os` the same code runs at 1.06-1.09x.
   - **`src/sigpool.cpp` already runs a second core** and `grandpa.c` already
     falls back to inline verification when its queue is full, which balances
     the split without tuning - measured at 207/197 on live cycles, with no
     tuning anywhere (E9).
   - **Done:** `env:esp32dev` now sets `-DLC_USE_FAST_ED25519`, routing
     `lc_ed25519_verify` through the vendored ref10 copy. Measured in the
     production image against live Polkadot at **1.060x** (11.700 -> 11.041
     ms/sig), matching the benchmark image exactly, so the ~30 KB costs nothing
     in cache terms. The host test build deliberately does not define it and
     keeps linking the system libsodium, because that is the second independent
     implementation the corpus is checked against.
2. **Settle what Substrate accepts.** Blocks the batch shipping at all, and
   nothing else. See the semantic-gap section: the batch is cofactored, ref10 is
   cofactorless, and no cheap check closes the gap.

   E7 changed the size of the prize this question is guarding. Against the
   semantics-preserving path the batch is worth **1.15x**, roughly 0.4 s on a
   403-signature justification - not the 2.39x it appeared to be worth when the
   comparison was against one core. If dalek and libsodium already disagree on
   the torsion case, that pre-existing divergence matters more than this one and
   should be found first either way.
3. **Precompute the authority tables into flash.** ***Done*** (E10 proposed it,
   E11 built and measured it). **1.128x, semantics unchanged, zero RAM.**

   `tools/gen_checkpoint.py` writes `src/checkpoint_precomp.c` alongside the
   keys: the eight odd multiples of each of the 600 authority keys, in Duif
   form. `lc_ed25519_verify_pre()` takes it instead of decompressing A and
   rebuilding the table, and `grandpa.c` selects it with the authority index the
   duplicate check already found. 562 KB of flash (32.9% -> 51.3% of the app
   partition), RAM unchanged at 98,476 bytes.

   It beat E10's 9.4% estimate, at 11.1% on one core and 11.4% on two, because
   Duif entries let the scalar loop use `ge25519_madd`/`ge25519_msub` and drop
   one field multiplication from each of ~43 additions.

   Correctness is `test/run_pre.sh` on the host, 903 more checks in the
   benchmark image, and a live check in `self_test_grandpa()`. The operational
   hazard is a cache that falls behind its keys, so `main.cpp` `#error`s on a
   `set_id` mismatch and `--precomp-only` rebuilds tables without touching the
   network.

4. **Measure a wider sliding window.** Unmeasured, semantics-preserving, and now
   cheap to try: the table is built at generation time, so `Ai[16]` costs the
   same at runtime as `Ai[8]` and buys strictly fewer additions inside the 79%.
   `slide_vartime`'s window is the thing to change, and 562 KB becomes 1.1 MB -
   which still fits, at 69% of the app partition. Size the gain before believing
   it: E8 is the cautionary tale about instruction counts that do not become
   cycles, and this one also has to survive the flash cache.
5. **Wire the batch into `grandpa.c`** - only if item 2 resolves and 1.15x is
   judged worth a consensus divergence. The `grandpa_sig_pool` interface already
   has the right shape (`submit`/`join`, one bit at the end), so a batch is a
   pool whose `join` returns 0 or "all of them". Needs a per-signature fallback
   on batch failure, both to keep failures attributable and because a failing
   batch rejects the justification either way.
6. **Tune the chunk to whatever RAM the running light client actually has.** The
   benchmark has WiFi down and 340 KB free; production will have much less. Note
   from E5 that small chunks are actively harmful - `chunk=64` at `-O3` is slower
   than verifying one signature at a time.
7. **Assembly: built, measured, and stopped.** (E8.) `fe25519_mul` is now
   written by hand for Xtensa - 12% fewer instructions, 11% smaller, correct on
   60,000 differential cases and the full agreement suite - and it is **3.4%
   faster in isolation and indistinguishable from zero end-to-end**.
   `ASSEMBLY.md` set the threshold at 15% in isolation; this is 3.4%. The code
   stays in the tree behind `LC_FE25519_ASM` because it is correct, tested, and
   the measurement is the useful artifact, but it is not the default and should
   not be.

   If anyone picks it up again, the next revision is software pipelining, not
   more instruction removal: the handwritten version has a *worse* CPI than
   GCC's (1.35 against 1.23) because the instructions GCC appears to waste are
   hiding multiplier latency. And do not reach for the two-accumulator
   representation trick - `tools/limb_bounds.py` proves no split point exists
   for ref10's limb layout.
