#!/usr/bin/env python3
"""Emit a handwritten Xtensa fe25519_mul from ref10's own term table.

Why generate rather than type it out: the function is 100 products and a
12-step carry chain, and a single transposed index in it is a consensus bug
that only shows up on one input in 2^30. The term table below is COPIED
VERBATIM from lib/ed25519_fast/src/vendor/private/ed25519_ref10_fe_25_5.h and
parsed, so the products cannot drift from upstream's; every instruction that
implements them was still chosen by hand.

What the assembly is actually for, from EXPERIMENTS.md E6: GCC emits 203
multiplies against an algorithmic floor of ~200, so the multiplier is not the
target. The target is the carry idiom. GCC spends 8 instructions per
accumulation:

    mull t0 / mulsh t1 / add lo,lo,t0 / movi c,1 / bltu lo,t0,L /
    movi c,0 / L: add hi,hi,t1 / add hi,hi,c

selecting a carry into a register and then adding it unconditionally. In
assembly the branch can skip the increment instead of selecting it, which is 6:

    mull t0 / mulsh t1 / add lo,lo,t0 / add hi,hi,t1 /
    bgeu lo,t0,L / addi hi,hi,1 / L:

That is the whole idea. It is worth 2 instructions on each of 100 terms.

It is also worth almost nothing, and the measurement is the point of the file
now rather than the speed. EXPERIMENTS.md E8: 12% fewer instructions, 11%
smaller, correct on 2.2 M host cases and 60,000 device cases - and 3.4% faster
in isolation, indistinguishable from zero end-to-end. GCC's apparently wasted
movi pair is sitting in the shadow of the multiplier latency, so the handwritten
version ends up with a worse CPI (1.35 against 1.23). This is built only by
env:mcbench_asm and is not the default. Do not make it the default.

    python3 tools/gen_fe25519_mul.py > lib/ed25519_fast/src/fe25519_mul_xtensa.S
    python3 tools/gen_fe25519_mul.py --c > /tmp/model.c      # host-testable model
"""
import re
import sys

# --- ref10's h0..h9, verbatim -------------------------------------------------
# Copied from ed25519_ref10_fe_25_5.h. Do not tidy: the point of pasting it is
# that it can be diffed against the header.
TERMS = """
h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38
h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19
h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38
h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19
h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38
h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19
h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38
h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19
h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38
h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0
"""

# ref10's suffix convention: _2 doubles the f operand, _19 multiplies the g
# operand by 19, _38 does both. Nothing else appears.
SUFFIX = {"": ("f", "g"), "2": ("f2", "g"), "19": ("f", "g19"), "38": ("f2", "g19")}


def parse():
    out = []
    for line in TERMS.strip().splitlines():
        lhs, rhs = line.split("=")
        k = int(lhs.strip()[1:])
        terms = []
        for tok in rhs.split("+"):
            m = re.fullmatch(r"f(\d)g(\d)(?:_(\d+))?", tok.strip())
            if not m:
                raise SystemExit("unparsable term: " + tok.strip())
            i, j, suf = int(m.group(1)), int(m.group(2)), m.group(3) or ""
            fk, gk = SUFFIX[suf]
            if fk == "f2" and i % 2 == 0:
                raise SystemExit(f"{tok.strip()}: ref10 only doubles odd f limbs")
            terms.append((fk, i, gk, j))
        if len(terms) != 10:
            raise SystemExit(f"h{k}: {len(terms)} terms, expected 10")
        out.append((k, terms))
    if len(out) != 10:
        raise SystemExit("expected 10 output limbs")
    return out


# ref10's carry chain, as (limb, shift, limb_it_carries_into, multiplier).
# The last entry of each pair-round is the one that wraps 2^255 -> 19.
CARRIES = [
    (0, 26, 1, 1), (4, 26, 5, 1),
    (1, 25, 2, 1), (5, 25, 6, 1),
    (2, 26, 3, 1), (6, 26, 7, 1),
    (3, 25, 4, 1), (7, 25, 8, 1),
    (4, 26, 5, 1), (8, 26, 9, 1),
    (9, 25, 0, 19),
    (0, 26, 1, 1),
]

# --- stack frame --------------------------------------------------------------
# A windowed frame is reserved at BOTH ends and only the middle is the
# function's own.
#
# The bottom 16 bytes are the base save area, the ABI's usual reservation. The
# top 32 are the part that is easy to miss and cost a Double exception to find:
# when the register window overflows, _WindowOverflow8 spills the interrupted
# frame's a0-a7 into the 32 bytes immediately BELOW its caller's stack pointer -
# which is to say, into the top 32 bytes of THIS frame. Locals there survive
# until the first window overflow lands on them, which is to say until the
# function is called from something deep enough, which is to say not during any
# test small enough to debug. GCC gives this function a 192-byte frame for 120
# bytes of data for the same reason.
BASE = 16                 # base save area
TOPRESERVE = 32           # _WindowOverflow8's landing zone
F2 = BASE                 # 2*f1, 2*f3, 2*f5, 2*f7, 2*f9        5 words
G19 = F2 + 5 * 4          # 19*g1 .. 19*g9                      9 words
H64 = G19 + 9 * 4         # h0..h9 as (lo, hi)                 20 words
FRAME = (H64 + 20 * 4 + TOPRESERVE + 15) & ~15

F2SLOT = {1: 0, 3: 1, 5: 2, 7: 3, 9: 4}

# Every output limb uses each of f0..f9 exactly once, and ref10 only ever
# doubles the ODD limbs - so the five even ones are always used plain and could
# live in registers for the whole product phase.
#
# Only one of them does. This function is reached by call8, which rotates the
# register window by 8, and a callee entered that way owns a0-a11: a12-a15 are
# the next window and belong to whatever frame the hardware has not spilled yet.
# Writing them assembles, runs, computes the right answer, and then corrupts the
# caller's frame on the way out - it cost a Double exception with EXCCAUSE 2 and
# a shredded backtrace to find. GCC's own fe25519_mul does use a10-a15, which is
# not a licence to copy: GCC knows it emitted every call site in the image and
# can widen them, and nothing here knows that.
#
# a11 is the one register left over after the accumulator, the product, the two
# multiplicands and the three pointers, and it is also needed in the carry
# chain - which runs after the product phase, so the two uses do not overlap.
FREG = {0: "a11"}


def operand(kind, idx):
    """Where to load one multiplicand from: (base register, byte offset)."""
    if kind == "f":
        return "a3", idx * 4
    if kind == "g":
        return "a4", idx * 4
    if kind == "f2":
        return "a1", F2 + F2SLOT[idx] * 4
    if kind == "g19":
        return "a1", G19 + (idx - 1) * 4
    raise AssertionError(kind)


def emit_asm():
    L = []
    a = L.append
    a("/* GENERATED by tools/gen_fe25519_mul.py - do not edit.")
    a(" *")
    a(" * fe25519_mul for Xtensa LX6, in the same 10-limb 25.5-bit representation")
    a(" * and with the same ABI as the C routine it replaces, including the")
    a(" * aliasing the C API permits: h may be f or g, because nothing is written")
    a(" * to h until every product has been formed.")
    a(" *")
    a(" * void fe25519_mul_xtensa(int32_t h[10], const int32_t f[10],")
    a(" *                         const int32_t g[10]);")
    a(" *   a2 = h, a3 = f, a4 = g")
    a(" *")
    a(" * Register use throughout: a5:a6 is the 64-bit accumulator, a7:a8 the")
    a(" * product being folded in, a9/a10 the two multiplicands, a11 the one")
    a(" * spare. Nothing above a11 is touched - see FREG in the generator for")
    a(" * why that is a hard limit and not a style choice.")
    a(" */")
    a("\t.text")
    a("\t.align 4")
    a("\t.global fe25519_mul_xtensa")
    a("\t.type   fe25519_mul_xtensa, @function")
    a("fe25519_mul_xtensa:")
    a(f"\tentry\ta1, {FRAME}\t/* {BASE} base + {H64 + 20 * 4 - BASE} locals"
      f" + {FRAME - H64 - 20 * 4} reserved for _WindowOverflow8 */")
    a("")
    a("\t/* 2*f1, 2*f3, 2*f5, 2*f7, 2*f9 - add.n is the doubling. */")
    for i, slot in sorted(F2SLOT.items()):
        a(f"\tl32i\ta5, a3, {i * 4}")
        a("\tadd.n\ta5, a5, a5")
        a(f"\ts32i\ta5, a1, {F2 + slot * 4}")
    a("")
    a("\t/* 19*g1 .. 19*g9. These stay inside int32 by exactly the margin")
    a("\t * upstream notes: 19 * 1.65 * 2^26 is 1.96 * 2^30. */")
    a("\tmovi.n\ta11, 19")
    for j in range(1, 10):
        a(f"\tl32i\ta5, a4, {j * 4}")
        a("\tmull\ta6, a5, a11")
        a(f"\ts32i\ta6, a1, {G19 + (j - 1) * 4}")
    a("")

    a("\t/* f0, f2, f4, f6, f8 stay in registers for the whole product phase. */")
    for i, r in sorted(FREG.items()):
        a(f"\tl32i\t{r}, a3, {i * 4}")
    a("")

    def fsrc(fk, i):
        """Emit the load for a multiplicand and name the register holding it."""
        if fk == "f" and i in FREG:
            return FREG[i]
        b, o = operand(fk, i)
        a(f"\tl32i\ta9, {b}, {o}")
        return "a9"

    for k, terms in parse():
        a(f"\t/* ---- h{k} ---- */")
        fk, i, gk, j = terms[0]
        fr = fsrc(fk, i)
        gb, go = operand(gk, j)
        a(f"\tl32i\ta10, {gb}, {go}")
        a(f"\tmull\ta5, {fr}, a10")
        a(f"\tmulsh\ta6, {fr}, a10")
        for n, (fk, i, gk, j) in enumerate(terms[1:], 1):
            lab = f".Lh{k}_{n}"
            fr = fsrc(fk, i)
            gb, go = operand(gk, j)
            a(f"\tl32i\ta10, {gb}, {go}")
            a(f"\tmull\ta7, {fr}, a10")
            a(f"\tmulsh\ta8, {fr}, a10")
            a("\tadd.n\ta5, a5, a7")
            a("\tadd.n\ta6, a6, a8")
            a(f"\tbgeu\ta5, a7, {lab}")
            a("\taddi.n\ta6, a6, 1")
            a(f"{lab}:")
        a(f"\ts32i\ta5, a1, {H64 + k * 8}")
        a(f"\ts32i\ta6, a1, {H64 + k * 8 + 4}")
        a("")

    a("\t/* ---- carry chain ----")
    a("\t * Every step is ref10's:")
    a("\t *     c = (h + 2^(s-1)) >> s;   h_next += c*m;   h -= c << s;")
    a("\t * The last line never needs a 64-bit subtract. Writing t = h + 2^(s-1),")
    a("\t * h - (c << s) == (t mod 2^s) - 2^(s-1), so the reduced limb falls out")
    a("\t * of the low word alone and is already the int32 the result wants.")
    a("\t *")
    a("\t * c itself does NOT fit in 32 bits on the early steps - upstream bounds")
    a("\t * |h0| by 1.4*2^60, so c can reach 2^34 - which is why every step here")
    a("\t * is 64-bit and why the two-accumulator trick that would remove these")
    a("\t * carries entirely does not apply to this limb layout. See")
    a("\t * tools/limb_bounds.py. */")
    for n, (src, shift, dst, mult) in enumerate(CARRIES):
        lab = f".Lc{n}"
        a(f"\t/* carry {src} -> {dst}, {shift} bits"
          + (f", times {mult}" if mult != 1 else "") + " */")
        a(f"\tl32i\ta5, a1, {H64 + src * 8}")
        a(f"\tl32i\ta6, a1, {H64 + src * 8 + 4}")
        # bias = 1 << (shift-1), built with a shift so no literal pool is needed
        a("\tmovi.n\ta7, 1")
        a(f"\tslli\ta7, a7, {shift - 1}")
        a("\tadd.n\ta5, a5, a7")
        a(f"\tbgeu\ta5, a7, {lab}a")
        a("\taddi.n\ta6, a6, 1")
        a(f"{lab}a:")
        a(f"\tssai\t{shift}")
        a("\tsrc\ta8, a6, a5")
        a(f"\tsrai\ta9, a6, {shift}")
        # t mod 2^shift. extui cannot do this: its field width caps at 16 bits,
        # and these masks are 25 and 26. A shift pair is the same two slots.
        a(f"\tslli\ta5, a5, {32 - shift}")
        a(f"\tsrli\ta5, a5, {32 - shift}")
        a("\tsub\ta5, a5, a7")
        a(f"\ts32i\ta5, a1, {H64 + src * 8}")
        # The reduced limb is signed, so its high word is a sign extension, not
        # zero. Storing zero here reads back as a large positive value for every
        # negative limb, and every later step that touches this limb is wrong.
        a("\tsrai\ta6, a5, 31")
        a(f"\ts32i\ta6, a1, {H64 + src * 8 + 4}")
        if mult != 1:
            a(f"\t/* c *= {mult}, 64-bit: muluh supplies the carry out of the")
            a("\t * low half, which is unsigned there even though c is not.")
            a("\t * a5-a7 are dead by this point - the limb they held is stored. */")
            a(f"\tmovi.n\ta7, {mult}")
            a("\tmull\ta10, a8, a7")
            a("\tmuluh\ta11, a8, a7")
            a("\tmull\ta6, a9, a7")
            a("\tadd.n\ta11, a11, a6")
            a("\tmov.n\ta8, a10")
            a("\tmov.n\ta9, a11")
        a(f"\tl32i\ta10, a1, {H64 + dst * 8}")
        a(f"\tl32i\ta11, a1, {H64 + dst * 8 + 4}")
        a("\tadd.n\ta10, a10, a8")
        a("\tadd.n\ta11, a11, a9")
        a(f"\tbgeu\ta10, a8, {lab}b")
        a("\taddi.n\ta11, a11, 1")
        a(f"{lab}b:")
        a(f"\ts32i\ta10, a1, {H64 + dst * 8}")
        a(f"\ts32i\ta11, a1, {H64 + dst * 8 + 4}")
        a("")

    a("\t/* Every limb is an int32 by now, so only the low words are stored. */")
    for k in range(10):
        a(f"\tl32i\ta5, a1, {H64 + k * 8}")
        a(f"\ts32i\ta5, a2, {k * 4}")
    a("\tretw.n")
    a("\t.size fe25519_mul_xtensa, .-fe25519_mul_xtensa")
    return "\n".join(L) + "\n"


def emit_c():
    """The same term table as portable C, so the PARSE can be tested on a host.

    This is not the assembly and cannot vouch for it. It vouches for the table
    the assembly is generated from, which is where a transposed index would
    hide."""
    L = ["/* GENERATED by tools/gen_fe25519_mul.py --c - the term table only. */",
         "#include <stdint.h>",
         "void fe25519_mul_model(int32_t h[10], const int32_t f[10], const int32_t g[10]) {",
         "    int64_t t[10]; int64_t c;"]
    for j in range(1, 10):
        L.append(f"    int32_t g19_{j} = 19 * g[{j}];")
    for i in sorted(F2SLOT):
        L.append(f"    int32_t f2_{i} = 2 * f[{i}];")
    for k, terms in parse():
        parts = []
        for fk, i, gk, j in terms:
            fe = f"f2_{i}" if fk == "f2" else f"f[{i}]"
            ge = f"g19_{j}" if gk == "g19" else f"g[{j}]"
            parts.append(f"(int64_t){fe} * {ge}")
        L.append(f"    t[{k}] = " + " + ".join(parts) + ";")
    for src, shift, dst, mult in CARRIES:
        bias = 1 << (shift - 1)
        L.append(f"    c = (t[{src}] + {bias}) >> {shift};"
                 f" t[{dst}] += c * {mult};"
                 f" t[{src}] -= c * ((uint64_t)1 << {shift});")
    for k in range(10):
        L.append(f"    h[{k}] = (int32_t)t[{k}];")
    L.append("}")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    sys.stdout.write(emit_c() if "--c" in sys.argv else emit_asm())
