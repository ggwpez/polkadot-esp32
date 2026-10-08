#!/usr/bin/env python3
"""Can a 32-bit machine accumulate a field multiply without 64-bit carries?

The Xtensa LX6 has no add-with-carry, so every 64-bit accumulation in
fe25519_mul costs a compare and a branch - EXPERIMENTS.md E6 measured that at
27% of the function. The standard way out is to split each product at bit s and
run two 32-bit accumulators, L for the low s bits and H for the rest, which is
branch-free:

    mull / mulsh / src (>>s) / extui (&(2^s-1)) / add L / add H     6 insns

against GCC's 8 with a data-dependent branch. It only works if neither
accumulator can overflow 32 bits, which is a property of the limb layout, not
of the code. This computes whether it does, for ref10's actual preconditions.

    python3 tools/limb_bounds.py
"""
from math import log2, ceil

# ref10 fe_25_5: 10 limbs alternating 26 and 25 bits, and the DOCUMENTED
# precondition on the inputs to fe25519_mul is 1.65*2^26 on even limbs and
# 1.65*2^25 on odd ones. The 1.65 is not slack to be argued away: it is what
# fe25519_add and fe25519_sub can hand to a multiply without an intervening
# reduction, which is exactly how ge25519_add uses them.
SLACK = 1.65


def limb_bits(n, i):
    """Bit width of limb i in an n-limb representation of a 255-bit field."""
    if n == 10:
        return 26 if i % 2 == 0 else 25          # ref10, exactly
    # Uniform-ish split of 255 bits: the first (255 mod n) limbs get one more.
    base, extra = divmod(255, n)
    return base + 1 if i < extra else base


def max_abs_h(n):
    """Worst case |h_k| over all output limbs, for an n-limb schoolbook multiply
    with the 19 and 2 folding ref10 uses.

    h_k = sum over i+j == k of f_i g_j, plus sum over i+j == k+n of 19 f_i g_j,
    and the terms where both i and j sit on a short (odd) limb pick up a further
    factor 2 because 2^255 = 19 mod p leaves a spare bit. Taking every term at
    its bound at once is pessimistic and deliberately so - a bound that only
    holds on average is not a bound."""
    fb = [SLACK * 2.0 ** limb_bits(n, i) for i in range(n)]
    worst = 0.0
    for k in range(n):
        tot = 0.0
        for i in range(n):
            j = k - i
            if j >= 0:
                tot += fb[i] * fb[j]
            else:
                j += n
                # reduced term: times 19, and times 2 when the wrap costs a bit
                two = 2.0 if (limb_bits(n, i) < 26 and limb_bits(n, j) < 26) else 1.0
                tot += 19.0 * two * fb[i] * fb[j]
        worst = max(worst, tot)
    return worst


def feasible(n, terms):
    """Best split point s for an n-limb layout, or None if there is none.

    L accumulates `terms` values in [0, 2^s), so it needs terms * 2^s < 2^32 -
    unsigned, because the low accumulator is never negative.
    H accumulates the signed quotients, so it needs |h| / 2^s < 2^31."""
    out = []
    for s in range(16, 32):
        l_ok = terms * 2.0 ** s < 2.0 ** 32
        h_ok = max_abs_h(n) / 2.0 ** s < 2.0 ** 31
        if l_ok and h_ok:
            out.append(s)
    return out


print(f"{'limbs':>6} {'bits/limb':>10} {'terms':>6} {'max |h|':>10} "
      f"{'split s':>18} {'accum insns':>12}")
print("-" * 70)
for n in (10, 11, 12, 13, 14, 16):
    h = max_abs_h(n)
    terms = n
    ok = feasible(n, terms)
    # 6 instructions per term when the split works, 8 (one of them a branch)
    # when it does not and the accumulation has to be a real 64-bit add.
    insns = n * n * (6 if ok else 8)
    bits = "/".join(str(limb_bits(n, i)) for i in range(min(n, 4))) + "..."
    print(f"{n:>6} {bits:>10} {terms:>6} {'2^%.1f' % log2(h):>10} "
          f"{(str(ok[0]) + '-' + str(ok[-1]) if ok else 'NONE'):>18} {insns:>12}")

print()
n = 10
h = max_abs_h(n)
print(f"ref10, 10 limbs: |h| <= 2^{log2(h):.2f}")
print(f"  L needs 10 * 2^s < 2^32   ->  s <= {int(32 - log2(10)):d}")
print(f"  H needs 2^{log2(h):.2f} / 2^s < 2^31  ->  s >= {ceil(log2(h) - 31):d}")
print("  no s satisfies both: the two-accumulator split is not available to "
      "ref10's layout.")
