/* ed25519 verification, vendored from libsodium and compiled for speed.
 *
 * Same ref10 code the platform libsodium runs, built as a single translation
 * unit with -O3 -fwhole-program so the field arithmetic can inline. The
 * platform copy is compiled -Os as one shared library, which leaves
 * fe25519_mul a 3 KB out-of-line call in the innermost loop.
 *
 * ed25519_ref10.c and the headers under fe_25_5/ and private/ are UNMODIFIED
 * upstream files, so they can be diffed against the release; the shims in
 * crypto_verify_32.h, utils.h and private/common.h supply the four macros and
 * declarations those files want from the rest of libsodium. SHA-512,
 * crypto_verify_32 and sodium_is_zero are still the platform's - hashing 117
 * bytes is microseconds and not worth vendoring. */

#include <string.h>

#include "ed25519_fast.h"

/* The handwritten Xtensa fe25519_mul, built by env:mcbench_asm.
 *
 * The vendored headers stay byte-identical to upstream, so the swap is done
 * with the preprocessor rather than by editing them: upstream's definition is
 * renamed out of the way while the header is included - it survives as
 * fe25519_mul_c and is what lc_fe25519_difftest() checks the assembly against -
 * and every call site after the header resolves to the assembly instead.
 *
 * EXPERIMENTS.md E6/E7 for why this targets fe25519_mul and what it is worth:
 * the multiplier is already at its floor, and the whole margin is in the carry
 * idiom, which GCC spends 8 instructions on per accumulation and this spends 6. */
#ifdef LC_FE25519_ASM
#define fe25519_mul fe25519_mul_c
#endif

#include "vendor/private/ed25519_ref10.h"

#ifdef LC_FE25519_ASM
#undef fe25519_mul
extern void fe25519_mul_xtensa(int32_t h[10], const int32_t f[10],
                               const int32_t g[10]);
#define fe25519_mul(h, f, g) fe25519_mul_xtensa((h), (f), (g))
#endif

extern int  crypto_verify_32(const unsigned char *x, const unsigned char *y);
extern int  crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                               unsigned long long inlen);
extern int  crypto_sign_verify_detached(const unsigned char *sig, const unsigned char *m,
                                        unsigned long long mlen, const unsigned char *pk);

/* Longest message this hashes without the streaming API. GRANDPA's localized
 * payload is 53 bytes; anything longer falls back to the platform's verify,
 * which is correct and merely slower. */
#define FAST_MSG_MAX 192

#ifdef LC_ED25519_WHOLE_PROGRAM
__attribute__((externally_visible))
#endif
int
lc_ed25519_verify_fast(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                       const uint8_t pk[32])
{
    unsigned char buf[64 + FAST_MSG_MAX];
    unsigned char h[64];
    unsigned char rcheck[32];
    ge25519_p3    A;
    ge25519_p2    R;

    if (msg_len > FAST_MSG_MAX) {
        return crypto_sign_verify_detached(sig, msg, (unsigned long long) msg_len, pk) == 0;
    }

    /* Upstream's checks, in upstream's order. */
    if (sc25519_is_canonical(sig + 32) == 0 || ge25519_has_small_order(sig) != 0) {
        return 0;
    }
    if (ge25519_is_canonical(pk) == 0 || ge25519_has_small_order(pk) != 0) {
        return 0;
    }
    if (ge25519_frombytes_negate_vartime(&A, pk) != 0) {
        return 0;
    }

    memcpy(buf, sig, 32);
    memcpy(buf + 32, pk, 32);
    memcpy(buf + 64, msg, msg_len);
    crypto_hash_sha512(h, buf, (unsigned long long) (64 + msg_len));
    sc25519_reduce(h);

    ge25519_double_scalarmult_vartime(&R, h, &A, sig + 32);
    ge25519_tobytes(rcheck, &R);

    /* Upstream also ORs in a pointer-aliasing guard and a redundant
     * sodium_memcmp; rcheck is a local here, so it cannot alias sig. */
    return crypto_verify_32(rcheck, sig) == 0;
}

#include "vendor/ed25519_ref10.c"

/* ---------- precomputed per-key tables ----------
 *
 * See ed25519_fast.h for what these are and why. This lives after ref10.c so it
 * can use its file-static ge25519_madd/ge25519_msub/slide_vartime, which are the
 * whole point: the table is in ge25519_precomp form (affine, Z implied 1), so
 * the scalar loop can use the cheaper addition ref10 already reserves for its
 * own fixed base-point table. */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(((lc_ed25519_pretab *) 0)->v)
                   == LC_ED25519_PRETAB_POINTS * sizeof(ge25519_precomp),
               "lc_ed25519_pretab must be a byte-for-byte ge25519_precomp[8]");
#endif

#ifdef LC_ED25519_WHOLE_PROGRAM
__attribute__((externally_visible))
#endif
int
lc_ed25519_pretab_build(lc_ed25519_pretab *out, const uint8_t pk[32])
{
    ge25519_p3      A, A2, u;
    ge25519_p1p1    t;
    ge25519_cached  c;
    ge25519_precomp pc;
    int             i;

    /* Exactly the decode the verifier does, including the negation: what goes
     * in the table is -A, because that is the point ref10 accumulates. */
    if (ge25519_frombytes_negate_vartime(&A, pk) != 0) {
        return 0;
    }

    ge25519_p3_to_precomp(&pc, &A);
    memcpy(out->v[0], &pc, sizeof pc);

    ge25519_p3_dbl(&t, &A);
    ge25519_p1p1_to_p3(&A2, &t);

    u = A;
    for (i = 1; i < LC_ED25519_PRETAB_POINTS; i++) {
        ge25519_p3_to_cached(&c, &u);
        ge25519_add(&t, &A2, &c);
        ge25519_p1p1_to_p3(&u, &t);              /* u = (2i+1)A */
        ge25519_p3_to_precomp(&pc, &u);
        memcpy(out->v[i], &pc, sizeof pc);
    }
    return 1;
}

/* Do two tables hold the same eight POINTS?
 *
 * Not memcmp: ref10 field elements are not canonical, so the same point has
 * many limb representations and only the reduced encoding is comparable. This
 * is what lets test/run_pre.sh check the generated tables against ref10's own
 * arithmetic - two independent implementations of the same points, compared
 * where they are required to agree and nowhere else. */
#ifdef LC_ED25519_WHOLE_PROGRAM
__attribute__((externally_visible))
#endif
int
lc_ed25519_pretab_equal(const lc_ed25519_pretab *a, const lc_ed25519_pretab *b)
{
    unsigned char ea[32], eb[32];
    int           i, j;

    for (i = 0; i < LC_ED25519_PRETAB_POINTS; i++) {
        for (j = 0; j < 3; j++) {
            fe25519_tobytes(ea, a->v[i][j]);
            fe25519_tobytes(eb, b->v[i][j]);
            if (memcmp(ea, eb, 32) != 0) {
                return 0;
            }
        }
    }
    return 1;
}

/* ge25519_double_scalarmult_vartime with the eight odd multiples of A supplied
 * rather than rebuilt, and in Duif form so the A side can use madd/msub.
 *
 * Line for line ref10's loop below the table build, with ge25519_add ->
 * ge25519_madd and ge25519_sub -> ge25519_msub on the A side. Those two forms
 * compute the same point; madd is the version that knows the addend's Z is 1,
 * which saves the fe25519_mul(r->X, p->Z, q->Z) that ge25519_add needs. */
static void
ge25519_double_scalarmult_vartime_pre(ge25519_p2 *r, const unsigned char *a,
                                      const ge25519_precomp Ai[LC_ED25519_PRETAB_POINTS],
                                      const unsigned char *b)
{
    static const ge25519_precomp Bi[8] = {
#include "vendor/fe_25_5/base2.h"
    };
    signed char  aslide[256];
    signed char  bslide[256];
    ge25519_p1p1 t;
    ge25519_p3   u;
    int          i;

    slide_vartime(aslide, a);
    slide_vartime(bslide, b);

    ge25519_p2_0(r);

    for (i = 255; i >= 0; --i) {
        if (aslide[i] || bslide[i]) {
            break;
        }
    }

    for (; i >= 0; --i) {
        ge25519_p2_dbl(&t, r);

        if (aslide[i] > 0) {
            ge25519_p1p1_to_p3(&u, &t);
            ge25519_madd(&t, &u, &Ai[aslide[i] / 2]);
        } else if (aslide[i] < 0) {
            ge25519_p1p1_to_p3(&u, &t);
            ge25519_msub(&t, &u, &Ai[(-aslide[i]) / 2]);
        }

        if (bslide[i] > 0) {
            ge25519_p1p1_to_p3(&u, &t);
            ge25519_madd(&t, &u, &Bi[bslide[i] / 2]);
        } else if (bslide[i] < 0) {
            ge25519_p1p1_to_p3(&u, &t);
            ge25519_msub(&t, &u, &Bi[(-bslide[i]) / 2]);
        }

        ge25519_p1p1_to_p2(r, &t);
    }
}

#ifdef LC_ED25519_WHOLE_PROGRAM
__attribute__((externally_visible))
#endif
int
lc_ed25519_verify_pre(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                      const uint8_t pk[32], const lc_ed25519_pretab *tab)
{
    unsigned char   buf[64 + FAST_MSG_MAX];
    unsigned char   h[64];
    unsigned char   rcheck[32];
    ge25519_precomp Ai[LC_ED25519_PRETAB_POINTS];
    ge25519_p2      R;

    if (tab == NULL || msg_len > FAST_MSG_MAX) {
        return lc_ed25519_verify_fast(sig, msg, msg_len, pk);
    }

    /* Upstream's checks, in upstream's order, minus the one the table replaces.
     * Both key checks stay: they are byte-level tests costing a fraction of the
     * 0.2% the whole screening phase takes, and keeping them means a bad key is
     * still rejected here rather than only by whatever generated the table.
     *
     * ge25519_frombytes_negate_vartime is the one that is gone, and it is the
     * only check whose outcome is not re-derived. It cannot reject a key that
     * has a table: tools/gen_checkpoint.py refuses to emit a table for a key
     * that does not decode, so its verdict for this key is already known to be
     * "accepted". */
    if (sc25519_is_canonical(sig + 32) == 0 || ge25519_has_small_order(sig) != 0) {
        return 0;
    }
    if (ge25519_is_canonical(pk) == 0 || ge25519_has_small_order(pk) != 0) {
        return 0;
    }

    memcpy(buf, sig, 32);
    memcpy(buf + 32, pk, 32);
    memcpy(buf + 64, msg, msg_len);
    crypto_hash_sha512(h, buf, (unsigned long long) (64 + msg_len));
    sc25519_reduce(h);

    /* Copied rather than pointed at, for two reasons. It is what makes reading
     * the table as ge25519_precomp well defined instead of a struct-vs-array
     * type pun, and it moves 960 bytes out of memory-mapped flash into stack
     * RAM before a loop that touches it ~43 times. It costs less than 0.05% of
     * a verification, and the ge25519_cached Ai[8] it replaces was 1280 bytes
     * of stack in the same place. */
    memcpy(Ai, tab->v, sizeof Ai);

    ge25519_double_scalarmult_vartime_pre(&R, h, Ai, sig + 32);
    ge25519_tobytes(rcheck, &R);

    return crypto_verify_32(rcheck, sig) == 0;
}

/* After ref10, so the batch code can use its file-static helpers. */
#include "ed25519_batch.c"

#ifdef LC_ED25519_PROFILE
/* Where a verification's time actually goes, split by phase.
 *
 * This is step 1 of ASSEMBLY.md's spike - an exclusive breakdown on the device -
 * and it had never been run, so every claim about which part of verification is
 * worth optimising has been an estimate. It matters most for the two phases that
 * depend ONLY on the public key: decompressing A, and building the eight-entry
 * table of odd multiples of A. There are 600 authorities and they are fixed for
 * an era, so anything spent there is spent 403 times per justification to
 * recompute 600 constants.
 *
 * Each entry loops internally so the call overhead is amortised, and each one
 * consumes its result so nothing can be optimised away. The caller times them. */

extern int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                              unsigned long long inlen);

#ifdef LC_ED25519_WHOLE_PROGRAM
__attribute__((externally_visible))
#endif
uint32_t
lc_prof_phase(int phase, const uint8_t pk[32], const uint8_t sig[64],
              const uint8_t *msg, size_t msg_len, uint32_t iters)
{
    unsigned char buf[64 + 192], h[64], rcheck[32];
    ge25519_p3     A, A2, u;
    ge25519_p2     R;
    ge25519_cached Ai[8];
    ge25519_p1p1   t;
    uint32_t       i, sink = 0;
    int            k;

    ge25519_frombytes_negate_vartime(&A, pk);
    memcpy(buf, sig, 32);
    memcpy(buf + 32, pk, 32);
    memcpy(buf + 64, msg, msg_len);
    crypto_hash_sha512(h, buf, (unsigned long long) (64 + msg_len));
    sc25519_reduce(h);

    for (i = 0; i < iters; i++) {
        switch (phase) {
        case 0:     /* the wrapper's canonicality and small-order screening */
            sink += sc25519_is_canonical(sig + 32) + ge25519_has_small_order(sig)
                  + ge25519_is_canonical(pk) + ge25519_has_small_order(pk);
            break;
        case 1:     /* SHA-512 over the 117 bytes production actually hashes */
            crypto_hash_sha512(h, buf, (unsigned long long) (64 + msg_len));
            sink += h[0];
            break;
        case 2:     /* sc25519_reduce */
            sc25519_reduce(h);
            sink += h[0];
            break;
        case 3:     /* decompress A - depends only on the public key */
            sink += ge25519_frombytes_negate_vartime(&A, pk) + 1;
            break;
        case 4:     /* build Ai[8] - depends only on the public key */
            ge25519_p3_to_cached(&Ai[0], &A);
            ge25519_p3_dbl(&t, &A);
            ge25519_p1p1_to_p3(&A2, &t);
            for (k = 1; k < 8; k++) {
                ge25519_add(&t, &A2, &Ai[k - 1]);
                ge25519_p1p1_to_p3(&u, &t);
                ge25519_p3_to_cached(&Ai[k], &u);
            }
            sink += (uint32_t) Ai[7].Z[0];
            break;
        case 5:     /* the whole double scalar multiplication, table included */
            ge25519_double_scalarmult_vartime(&R, h, &A, sig + 32);
            sink += (uint32_t) R.Z[0];
            break;
        case 6:     /* tobytes + compare */
            ge25519_tobytes(rcheck, &R);
            sink += rcheck[0];
            break;
        case 7:     /* a whole verification, for the denominator */
            sink += lc_ed25519_verify_fast(sig, msg, msg_len, pk);
            break;
        }
    }
    return sink;
}
#endif

#ifdef LC_FE25519_ASM
/* Differential test for the assembly, run on the device before anything is
 * timed. The host cannot do this one: the whole point is the instruction
 * encoding, and there is no Xtensa on the host.
 *
 * The inputs cover ref10's DOCUMENTED precondition, not the range the verifier
 * happens to produce - |f_i| <= 1.65*2^26 on even limbs and 1.65*2^25 on odd -
 * because fe25519_add and fe25519_sub can hand a multiply anything inside that,
 * and a carry bug that only shows up near the top of the range is exactly the
 * kind that survives a corpus test and then diverges on one block in a year.
 * Every eighth case pins every limb to a signed extreme for the same reason. */
/* The field kernel on its own, which is the measurement ASSEMBLY.md's spike
 * asked for first and nobody had run. End-to-end timing cannot distinguish "the
 * kernel did not get faster" from "the kernel got faster and is a smaller share
 * of verification than assumed", and those call for opposite next steps.
 *
 * Each iteration feeds the previous result back in, so nothing can be hoisted
 * out of the loop, and the returned checksum keeps the whole chain live. */
#ifdef LC_ED25519_WHOLE_PROGRAM
__attribute__((externally_visible))
#endif
uint32_t
lc_fe25519_mulbench(uint32_t iters, int use_asm)
{
    fe25519 a, b, c;
    uint32_t i;
    int k;

    for (k = 0; k < 10; k++) {
        a[k] = (k % 2 == 0) ? 33554431 - k : -16777215 + k;
        b[k] = (k % 2 == 0) ? -33554430 + k : 16777214 - k;
    }
    if (use_asm) {
        for (i = 0; i < iters; i++) { fe25519_mul_xtensa(c, a, b); a[0] = c[0]; a[1] = c[1]; }
    } else {
        for (i = 0; i < iters; i++) { fe25519_mul_c(c, a, b); a[0] = c[0]; a[1] = c[1]; }
    }
    return (uint32_t) (c[0] ^ c[3] ^ c[6] ^ c[9]);
}

/* One call of each, side by side, so a fault can be localised to a single
 * invocation with known inputs instead of a sweep. */
#ifdef LC_ED25519_WHOLE_PROGRAM
__attribute__((externally_visible))
#endif
void
lc_fe25519_mul_pair(int32_t out_c[10], int32_t out_asm[10],
                    const int32_t f[10], const int32_t g[10])
{
    fe25519_mul_c(out_c, f, g);
    fe25519_mul_xtensa(out_asm, f, g);
}

#ifdef LC_ED25519_WHOLE_PROGRAM
__attribute__((externally_visible))
#endif
uint32_t
lc_fe25519_difftest(uint32_t iters, uint32_t seed)
{
    uint32_t st = seed ? seed : 1;
    uint32_t bad = 0;
    fe25519 f, g, a, b;
    uint32_t i;
    int k;

#define NEXT() (st ^= st << 13, st ^= st >> 17, st ^= st << 5, st)

    for (i = 0; i < iters; i++) {
        int extreme = (i % 8) == 0;
        for (k = 0; k < 10; k++) {
            int32_t lim = (k % 2 == 0) ? 110703411 : 55351705;   /* 1.65*2^26, 1.65*2^25 */
            f[k] = extreme ? ((NEXT() & 1) ? lim : -lim)
                           : (int32_t) (NEXT() % (uint32_t) (2 * lim)) - lim;
            g[k] = extreme ? ((NEXT() & 1) ? lim : -lim)
                           : (int32_t) (NEXT() % (uint32_t) (2 * lim)) - lim;
        }
        if (i < 4) {                        /* zero, one, and the two aliases */
            memset(f, 0, sizeof f);
            memset(g, 0, sizeof g);
            if (i & 1) f[0] = 1;
            if (i & 2) g[0] = 1;
        }

        fe25519_mul_c(a, f, g);
        fe25519_mul_xtensa(b, f, g);
        if (memcmp(a, b, sizeof a) != 0) bad++;

        /* The C API permits h == f and h == g, and the assembly only gets away
         * with reading its inputs lazily because it writes h last. */
        memcpy(a, f, sizeof f);
        memcpy(b, f, sizeof f);
        fe25519_mul_c(a, a, g);
        fe25519_mul_xtensa(b, b, g);
        if (memcmp(a, b, sizeof a) != 0) bad++;

        memcpy(a, g, sizeof g);
        memcpy(b, g, sizeof g);
        fe25519_mul_c(a, f, a);
        fe25519_mul_xtensa(b, f, b);
        if (memcmp(a, b, sizeof a) != 0) bad++;
    }
#undef NEXT
    return bad;
}
#endif
