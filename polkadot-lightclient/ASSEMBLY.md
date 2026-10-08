# Xtensa Ed25519 Assembly Optimization Handoff

> **Superseded - read `EXPERIMENTS.md` first.** The work this document proposes
> has now been done and measured, and the result is a stop.
>
> - **The `fe25519_mul` assembly exists, is correct, and is not worth
>   shipping.** `lib/ed25519_fast/src/fe25519_mul_xtensa.S` is 12% fewer
>   instructions and 11% smaller than GCC's `-Os` output, verified on 2.2 M host
>   cases and 60,000 device differential cases with zero mismatches. It is
>   **3.4% faster in isolation and indistinguishable from zero end-to-end**.
>   The stop/go threshold below asks for 15% in isolation. See E8.
> - **The `-O3` result below is a flag artifact, not a property of the vendored
>   code.** At `-Os` the same vendored ref10 runs at **1.06-1.09x of prebuilt
>   libsodium** rather than the 0.94x recorded here. `-O3` and `-Os` emit
>   *identical* multiply and carry-branch counts for `fe25519_mul`; `-O3` only
>   adds 47 spills and 123 bytes.
> - **"Assembly for `fe25519_mul`" targeted the wrong thing, and so did this
>   document's estimate of what the right thing was worth.** GCC is at the
>   algorithmic floor on multiplies, and the recoverable cost is the carry
>   idiom - but removing 12% of the instructions bought 3.4% of the cycles,
>   because the instructions GCC appears to waste are hiding multiplier latency.
>   The handwritten version has a worse CPI than GCC's.
> - **The semantics-preserving win was the second core, and it was already
>   there.** Per-signature verification on both cores at `-Os` is **2.08x**,
>   measured, with 0.98 parallel efficiency (E7). `src/sigpool.cpp` has run a
>   second core all along. Against that baseline, batch verification is worth
>   1.15x - not the 2.39x it appears to be worth when compared against one core -
>   and that 1.15x is the entire return on the cofactored/cofactorless
>   divergence that `EXPERIMENTS.md` documents and gates.
>
> - **The second semantics-preserving win was above the field arithmetic, not
>   inside it.** An exclusive phase breakdown on the device - step 1 of the spike
>   recommended below, which had never actually been run - found 9.4% of every
>   verification going into decompressing the public key and rebuilding its
>   eight-entry multiple table, work that depends on nothing but a key of which a
>   GRANDPA era has 600 fixed ones. Precomputing those into flash is **1.128x**,
>   measured, with no change to what is accepted (E11). That is a third of what
>   this document's most optimistic field-arithmetic estimate promised, for a
>   generator script rather than weeks of Xtensa.
>
> The consensus-equivalence requirement stated below is exactly the right lens,
> and it is what makes the two-core result the answer: it changes nothing about
> what is accepted.

## Objective

Evaluate whether handwritten Xtensa LX6 assembly can materially reduce the
time spent verifying GRANDPA Ed25519 signatures on the dual-core ESP32.

This is a performance project only. The accepted and rejected signature set
must remain identical to the existing libsodium verifier because any semantic
difference can cause a consensus divergence.

## Measured baseline

The board is an ESP32-D0WDQ6 revision 1.0 running at 240 MHz. The benchmark
uses a valid signature over a 53-byte message, matching a localized GRANDPA
precommit payload.

An A/B test compared Espressif's prebuilt libsodium ref10 implementation,
compiled at `-Os`, with the same ref10 path vendored as one translation unit
and compiled at `-O3 -fwhole-program`.

| Implementation | Time per signature | 401 signatures, one core | Projected across two cores |
|---|---:|---:|---:|
| Prebuilt libsodium `-Os` | 19.266 ms | 7.73 s | 3.86 s |
| Vendored ref10 `-O3` | 20.399 ms | 8.18 s | 4.09 s |

The `-O3` implementation was 5.9% slower and added approximately 30 KB of
code. Four interleaved rounds were tightly grouped:

| Round | Prebuilt `-Os` | Vendored `-O3` | Relative result |
|---|---:|---:|---:|
| 1 | 19.297 ms | 20.399 ms | 0.95x |
| 2 | 19.238 ms | 20.400 ms | 0.94x |
| 3 | 19.297 ms | 20.399 ms | 0.95x |
| 4 | 19.232 ms | 20.400 ms | 0.94x |

Before timing, the two implementations agreed on 1,617 valid, bit-flipped,
small-order, non-canonical, and deterministic garbage inputs.

The reproducible benchmark is in `src/edbench.cpp`. The experimental vendored
implementation is isolated under `lib/ed25519_fast` and is not linked into the
normal `esp32dev` firmware.

## What the disassembly says

The current Xtensa compiler output already uses native `mull` instructions, so
assembly will not reveal an unused hardware multiplier. The opportunity is
instead in register allocation, scheduling, carry handling, and reducing
memory traffic.

Notable observations from the linked benchmark image:

- The `-O3` `fe25519_mul` uses a 192-byte stack frame and performs substantial
  spilling and reloading.
- The inlined `lc_ed25519_verify_fast` is approximately 15.8 KB by itself.
- The complete `-O3` verifier object is approximately 30 KB.
- Enlarging the hot path made performance worse, strongly suggesting that
  instruction-cache pressure must be treated as a first-class constraint.
- Verification is dominated by the variable-time double-scalar multiplication
  and its field multiplications and squarings. SHA-512 and input validation are
  not likely to be valuable assembly targets.

Do not assume that further unrolling is beneficial. Ref10 is already largely
straight-line C, and the experiment showed that code-size growth can outweigh
instruction-level improvements on this chip.

## Estimated scopes

| Scope | Estimated effort | Expected whole-verification gain | Risk |
|---|---:|---:|---|
| Hand-tune `fe25519_mul` and `fe25519_sq` | 1-3 weeks | 8-18% | Moderate |
| Field arithmetic plus point add/double | 4-8 weeks | 15-30% | High |
| Purpose-built Xtensa Ed25519 verifier | 2-4 months | 25-45% | Very high |
| Independent review and production hardening | Add 1-2 months | No additional speed | Necessary |

These estimates assume an engineer already comfortable with Xtensa assembly
and multi-precision arithmetic. Ramp-up can double the schedule.

Applied to the measured 401-signature workload:

- A plausible field-arithmetic result is approximately 6.3-7.1 seconds on one
  core instead of 7.73 seconds.
- A very strong, complete verifier could plausibly reach approximately
  4.3-5.8 seconds on one core.
- With both cores kept busy and little additional contention, elapsed time
  should be approximately half of the single-core figure.

A 2x improvement from assembly alone is not a reasonable planning assumption.
Reaching that range would probably require an algorithmic or representation
change as well as assembly.

## Recommended feasibility spike

Start with one narrowly bounded kernel. Do not begin by rewriting the complete
verifier.

1. Add cycle instrumentation around `fe25519_mul`, `fe25519_sq`,
   `sc25519_reduce`, and `ge25519_double_scalarmult_vartime` to establish an
   exclusive cycle breakdown on the device.
2. Preserve the current C routine under a reference-only symbol.
3. Implement one compact Xtensa assembly version of `fe25519_mul` using the
   same 10-limb 25.5-bit representation and ABI.
4. Differential-test the assembly output against the C routine over boundary
   values and a large deterministic random corpus.
5. Run the complete signature A/B benchmark, not only a field-operation
   microbenchmark.
6. Inspect linked symbol sizes and instruction-cache behavior before expanding
   the scope to squaring or point operations.

Expected effort for this spike is approximately 3-7 engineering days.

### Stop/go threshold

Continue beyond the spike only if all of the following hold:

- `fe25519_mul` improves by at least 15% in isolation.
- Complete Ed25519 verification improves by a statistically stable amount.
- The implementation does not materially increase the hot instruction
  footprint.
- Differential and signature agreement tests report zero discrepancies.
- The gain remains when both ESP32 cores verify concurrently.

If the field kernel improves but end-to-end verification does not, stop. That
would indicate either instruction-cache displacement or that the optimized
operation is not responsible for enough total cycles.

## Correctness requirements

Assembly arithmetic must be tested independently from signature verification.
At minimum, cover:

- zero, one, and maximum limb values;
- carry-chain boundaries;
- field values around `p - 1`, `p`, and `p + 1`;
- aliasing permitted by the C API, including output equal to either input;
- deterministic random field elements;
- comparison after canonical reduction;
- valid signatures and every single-bit mutation of signature, key, and
  message;
- small-order point encodings;
- non-canonical point and scalar encodings;
- simultaneous execution on both cores.

The assembly should retain the existing libsodium verification wrapper and its
canonicality and small-order checks. Replacing those checks is outside the
scope of a field-arithmetic optimization.

For production, require review by someone other than the assembly author. A
wrong result is more serious than a crash: it may selectively accept or reject
a GRANDPA vote and diverge from the network's consensus rules.

## Benchmark procedure

Build and flash the existing compiler A/B benchmark with:

```sh
pio run -e edbench_os -t upload \
  --upload-port 'rfc2217://host.internal:4000?ign_set_control'
```

The RFC2217 bridge does not support reliable monitor-driven modem-control
reset. Reset and capture serial output in one connection, allowing for the
benchmark's startup delay:

```sh
python3 -u -c "import serial,time,sys; \
s=serial.serial_for_url('rfc2217://host.internal:4000?ign_set_control', \
baudrate=115200,timeout=.5); \
s.dtr=False; s.rts=True; time.sleep(.5); s.rts=False; \
end=time.time()+180; \
exec('while time.time()<end:\n b=s.read(4096)\n if b:\n  sys.stdout.buffer.write(b); sys.stdout.buffer.flush()'); \
s.close()"
```

For assembly work, add separate field-operation timings but retain the full
signature benchmark as the acceptance measurement. Interleave reference and
candidate rounds to reduce temperature and clock-state bias. Report:

- cycles or microseconds per field operation;
- milliseconds per valid signature;
- all individual round results, not only the average;
- projected time for 401 signatures;
- one-core and simultaneous two-core results;
- linked text-size delta;
- number of differential inputs and disagreements.

After benchmarking, restore the production firmware:

```sh
pio run -e esp32dev -t upload \
  --upload-port 'rfc2217://host.internal:4000?ign_set_control'
```

## Strategic comparison with batch verification

Handwritten assembly preserves the current per-signature verification
semantics and is therefore the lower semantic-risk optimization. Its likely
benefit is around one second, possibly two in an unusually successful complete
rewrite.

Batch verification has much larger potential because all GRANDPA precommits in
a justification sign the same 53-byte payload under different keys. It could
replace hundreds of independent double-scalar multiplications with a
multi-scalar multiplication. However, it changes consensus-sensitive
verification behavior, requires exact compatibility with Substrate's rules,
and needs individual-verification fallback after a batch failure.

The recommended ordering is:

1. Run the bounded assembly feasibility spike if a semantics-preserving speed
   improvement is valuable enough to justify specialist effort.
2. Stop early unless the field kernel clears the measured threshold.
3. Treat batch verification as a separate design and soundness project rather
   than extending the assembly task into it.

## Current recommendation

Do not fund a complete handwritten verifier based only on theoretical gains.
Fund the 3-7 day `fe25519_mul` feasibility spike, measure it on the real board,
and make the larger decision from that result. The most likely production
outcome is a compact field-arithmetic assembly module delivering a 10-20%
whole-verifier improvement; the credible upper end for a substantially larger
rewrite is approximately 45%.
