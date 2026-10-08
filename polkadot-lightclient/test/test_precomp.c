/* The precomputed per-authority tables: are they the right points, and does
 * using them change any verdict?
 *
 * lc_ed25519_verify_pre() skips ge25519_frombytes_negate_vartime() and the
 * eight-entry table build - 9.4% of a verification, measured on the device in
 * EXPERIMENTS.md E10 - and takes the result from src/checkpoint_precomp.c
 * instead. Those tables are produced by tools/gen_checkpoint.py, in Python,
 * with big-integer modular arithmetic that shares not one line with ref10. So
 * there are two things to establish and they are separable:
 *
 *   1. The generated tables hold the same POINTS ref10 derives from the same
 *      keys. Compared as reduced encodings, because ref10's field elements are
 *      not canonical and two correct tables can differ bit for bit.
 *
 *   2. Verification driven by a table accepts and rejects exactly what
 *      libsodium's crypto_sign_verify_detached does - over the 403 real
 *      precommits, every single-bit mutation of a signature and a key, the
 *      small-order and non-canonical encodings, and deterministic garbage.
 *
 * Composed, those two say the shipped path is consensus-identical: (1) the
 * table in flash is the table ref10 would have built, (2) a verification given
 * that table decides what libsodium decides.
 *
 * The third section is the one that would catch a table that was merely
 * plausible: hand the verifier the WRONG authority's table and every signature
 * must fail. Without it, a table full of zeros could pass sections 1 and 2 if
 * section 1 were also broken.
 *
 *   sh test/run_pre.sh
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include "fixtures/ed_corpus.h"
#include "../src/checkpoint.h"
#include "../src/checkpoint_precomp.h"
#include "../lib/ed25519_fast/src/ed25519_fast.h"

int crypto_sign_verify_detached(const unsigned char *sig, const unsigned char *m,
                                unsigned long long mlen, const unsigned char *pk);

#define MSG    ED_CORPUS_MSG
#define MSGLEN (sizeof ED_CORPUS_MSG)
#define N      ED_CORPUS_N

static int tests = 0, failures = 0;

static void check(int cond, const char *fmt, ...)
{
    va_list ap;
    tests++;
    if (!cond) failures++;
    printf("  %s ", cond ? "\033[32mpass\033[0m" : "\033[31mFAIL\033[0m");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

static void section(const char *s) { printf("\n\033[1m%s\033[0m\n", s); }

static uint32_t rng_state = 0x9e3779b9u;
static uint8_t rnd_byte(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return (uint8_t) (rng_state >> 24);
}
static void rnd_fill(uint8_t *p, size_t n) { while (n--) *p++ = rnd_byte(); }

/* ---------------------------------------------------------------- section 1 */

static void tables_are_the_right_points(void)
{
    lc_ed25519_pretab built;
    unsigned          i, ok = 0, undecodable = 0;

    section("generated tables vs ref10's own arithmetic");

    check(CHECKPOINT_PRECOMP_SET_ID == CHECKPOINT_SET_ID,
          "precomp set_id %llu matches checkpoint set_id %llu",
          (unsigned long long) CHECKPOINT_PRECOMP_SET_ID,
          (unsigned long long) CHECKPOINT_SET_ID);
    check(CHECKPOINT_PRECOMP_COUNT == CHECKPOINT_AUTHORITIES,
          "precomp holds %u tables for %u authorities",
          (unsigned) CHECKPOINT_PRECOMP_COUNT, (unsigned) CHECKPOINT_AUTHORITIES);

    for (i = 0; i < CHECKPOINT_AUTHORITIES; i++) {
        const uint8_t *pk = CHECKPOINT_AUTHORITY_KEYS + i * 32u;
        if (!lc_ed25519_pretab_build(&built, pk)) { undecodable++; continue; }
        if (lc_ed25519_pretab_equal(&built, &CHECKPOINT_AUTHORITY_PRECOMP[i])) {
            ok++;
        } else if (ok + undecodable < 4) {
            printf("       MISMATCH at authority %u\n", i);
        }
    }
    check(undecodable == 0, "every authority key decodes (%u did not)", undecodable);
    check(ok == CHECKPOINT_AUTHORITIES,
          "all %u generated tables hold the same 8 points ref10 derives "
          "(%u matched)", (unsigned) CHECKPOINT_AUTHORITIES, ok);
}

/* ---------------------------------------------------------------- section 2 */

static uint32_t agreed, disagreed;

/* One input, both ways.
 *
 * When the key does not decode there is no table to give, and the claim being
 * checked is different but just as necessary: the reference must reject it. A
 * key lc_ed25519_pretab_build() refuses is a key the shipped verifier would
 * have refused at ge25519_frombytes_negate_vartime, so refusing to build must
 * never be the more permissive answer. */
static void agree(const char *what, const uint8_t *sig, const uint8_t *pk)
{
    lc_ed25519_pretab tab;
    int ref = crypto_sign_verify_detached(sig, MSG, MSGLEN, pk) == 0;
    int got;

    agreed++;
    if (!lc_ed25519_pretab_build(&tab, pk)) {
        if (ref) {
            disagreed++;
            printf("       DISAGREE [%s] no table built but reference ACCEPTS\n", what);
        }
        return;
    }
    got = lc_ed25519_verify_pre(sig, MSG, MSGLEN, pk, &tab);
    if (ref != got) {
        disagreed++;
        if (disagreed <= 6)
            printf("       DISAGREE [%s] reference=%d table=%d\n", what, ref, got);
    }
}

/* Encodings that are the interesting failures: the identity, small-order
 * points, and values at and past p. Same list src/mcbench.cpp and
 * test/test_ed25519.c use. */
static const uint8_t EDGE[][32] = {
    { 0x00 },
    { 0x01 },
    { 0xe0,0xeb,0x7a,0x7c,0x3b,0x41,0xb8,0xae,0x16,0x56,0xe3,0xfa,
      0xf1,0x9f,0xc4,0x6a,0xda,0x09,0x8d,0xeb,0x9c,0x32,0xb1,0xfd,
      0x86,0x62,0x05,0x16,0x5f,0x49,0xb8,0x00 },
    { 0x5f,0x9c,0x95,0xbc,0xa3,0x50,0x8c,0x24,0xb1,0xd0,0xb1,0x55,
      0x9c,0x83,0xef,0x5b,0x04,0x44,0x5c,0xc4,0x58,0x1c,0x8e,0x86,
      0xd8,0x22,0x4e,0xdd,0xd0,0x9f,0x11,0x57 },
    { 0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f },
    { 0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f },
    { 0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff },
    { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff },
};
#define N_EDGE (sizeof EDGE / sizeof EDGE[0])

static void same_verdicts(void)
{
    uint8_t  sig[64], pk[32];
    unsigned i, b;

    section("table-driven verification vs libsodium");

    for (i = 0; i < N; i++) agree("corpus", ED_CORPUS_SIG[i], ED_CORPUS_PK[i]);

    /* Every single-bit mutation of one signature and one key. A table changes
     * where A comes from, so a key bit flip is the mutation that matters most:
     * it must still be caught, and by the same rule. */
    for (b = 0; b < 512; b++) {
        memcpy(sig, ED_CORPUS_SIG[3], 64);
        sig[b >> 3] ^= (uint8_t) (1u << (b & 7));
        agree("sig-bitflip", sig, ED_CORPUS_PK[3]);
    }
    for (b = 0; b < 256; b++) {
        memcpy(pk, ED_CORPUS_PK[4], 32);
        pk[b >> 3] ^= (uint8_t) (1u << (b & 7));
        agree("pk-bitflip", ED_CORPUS_SIG[4], pk);
    }

    for (i = 0; i < N_EDGE; i++) {
        agree("edge-pk", ED_CORPUS_SIG[0], EDGE[i]);
        memcpy(sig, ED_CORPUS_SIG[0], 64); memcpy(sig, EDGE[i], 32);
        agree("edge-R", sig, ED_CORPUS_PK[0]);
        memcpy(sig, ED_CORPUS_SIG[0], 64); memcpy(sig + 32, EDGE[i], 32);
        agree("edge-S", sig, ED_CORPUS_PK[0]);
    }

    /* S, S+L and S+2L reduce to the same scalar; only the canonical one is a
     * signature. The table path keeps sc25519_is_canonical, so this must hold. */
    {
        static const uint8_t L[32] = {
            0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,
            0xde,0xf9,0xde,0x14,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };
        int k;
        for (k = 1; k <= 2; k++) {
            unsigned carry = 0, j;
            memcpy(sig, ED_CORPUS_SIG[0], 64);
            for (j = 0; j < 32; j++) {
                unsigned v = sig[32 + j] + (unsigned) L[j] * (unsigned) k + carry;
                sig[32 + j] = (uint8_t) v;
                carry = v >> 8;
            }
            agree("S+kL", sig, ED_CORPUS_PK[0]);
        }
    }

    /* Signature and key from different authorities: the forgery an authority
     * that actually holds a key would try. */
    for (i = 0; i + 1 < 64; i++)
        agree("swapped-key", ED_CORPUS_SIG[i], ED_CORPUS_PK[i + 1]);

    rng_state = 0x9e3779b9u;
    for (i = 0; i < 600; i++) {
        rnd_fill(sig, 64);
        rnd_fill(pk, 32);
        agree("garbage", sig, pk);
    }

    check(disagreed == 0,
          "table-driven and libsodium agree on %u inputs: the %u real "
          "precommits, all 512 signature bit flips, all 256 key bit flips, "
          "%u edge encodings in each of three positions, S+L and S+2L, 63 "
          "swapped-key forgeries and 600 random inputs (%u disagreements)",
          agreed, (unsigned) N, (unsigned) N_EDGE, disagreed);
}

/* ---------------------------------------------------------------- section 3 */

static void table_is_load_bearing(void)
{
    unsigned i, accepted = 0, rejected = 0;
    lc_ed25519_pretab zero;

    section("a wrong table must reject");

    /* One authority's signature against a different authority's table. If the
     * table were ignored - or if lc_ed25519_verify_pre quietly fell back to
     * decoding the key - these would all pass and sections 1 and 2 would still
     * look fine.
     *
     * The corpus is a real justification from set 3585 and the checkpoint is
     * set 3587, so ED_CORPUS_PK[0] is very likely still an authority and its
     * own table is skipped; that is a table that SHOULD accept. */
    for (i = 0; i < CHECKPOINT_AUTHORITIES && i < 64; i++) {
        lc_ed25519_pretab tab;
        const uint8_t *pk = CHECKPOINT_AUTHORITY_KEYS + i * 32u;
        if (memcmp(pk, ED_CORPUS_PK[0], 32) == 0) continue;
        if (!lc_ed25519_pretab_build(&tab, pk))
            continue;
        if (lc_ed25519_verify_pre(ED_CORPUS_SIG[0], MSG, MSGLEN,
                                  ED_CORPUS_PK[0], &tab)) accepted++;
        else rejected++;
    }
    check(accepted == 0, "%u valid signatures checked against another "
          "authority's table, all rejected (%u accepted)", rejected, accepted);

    memset(&zero, 0, sizeof zero);
    check(!lc_ed25519_verify_pre(ED_CORPUS_SIG[0], MSG, MSGLEN,
                                 ED_CORPUS_PK[0], &zero),
          "an all-zero table rejects a valid signature");

    /* NULL is documented as "exactly lc_ed25519_verify_fast", and grandpa.c
     * relies on it: an authority set with no tables must behave as before. */
    {
        unsigned same = 0;
        for (i = 0; i < N; i++)
            same += lc_ed25519_verify_pre(ED_CORPUS_SIG[i], MSG, MSGLEN,
                                          ED_CORPUS_PK[i], NULL) == 1;
        check(same == N, "a NULL table falls back and still verifies all %u "
              "precommits (%u)", (unsigned) N, same);
    }
}

int main(void)
{
    printf("\033[1mprecomputed authority tables\033[0m\n");
    tables_are_the_right_points();
    same_verdicts();
    table_is_load_bearing();
    printf("\n%d tests, %d failures\n", tests, failures);
    return failures != 0;
}
