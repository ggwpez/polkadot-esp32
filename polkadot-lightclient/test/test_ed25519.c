/* Ed25519 batch verification: correctness against the per-signature verifier,
 * and a host benchmark.
 *
 * This runs on the development machine in well under a second, against 403 real
 * Polkadot GRANDPA precommits frozen into test/fixtures/ed_corpus.h. That is
 * the point of it: the board and the RFC2217 bridge are a two-minute round
 * trip, so anything that can be settled here should be settled here, and the
 * device benchmark (src/batchbench.cpp) is reserved for the question only the
 * board can answer, which is wall-clock time on an ESP32.
 *
 * The reference is test/host/ref_verify.c, a transcription of libsodium's
 * crypto_sign_verify_detached. src/edbench.cpp has already shown that path
 * agreeing with the framework's prebuilt libsodium on 1,617 inputs, so
 * agreement here is agreement with the verifier the firmware ships.
 *
 * The interesting tests are the negative ones and, more than those, the one
 * that asserts a DISAGREEMENT: the cofactored batch equation accepts a class of
 * signature libsodium rejects, and torsion_divergence() constructs a member of
 * that class so the gap is a measured fact rather than a footnote.
 *
 *   sh test/run_ed.sh
 */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "fixtures/ed_corpus.h"
#include "../lib/ed25519_fast/src/ed25519_batch.h"
#include "../lib/ed25519_fast/src/vendor/private/ed25519_ref10.h"

int lc_ed25519_verify_fast(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                           const uint8_t pk[32]);
int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                       unsigned long long inlen);
int crypto_sign_verify_detached(const unsigned char *sig, const unsigned char *m,
                                unsigned long long mlen, const unsigned char *pk);

#define MSG      ED_CORPUS_MSG
#define MSGLEN   (sizeof ED_CORPUS_MSG)
#define N        ED_CORPUS_N

static int tests = 0, failures = 0;

static void check(int cond, const char *fmt, ...)
{
    va_list ap;
    tests++;
    if (!cond) failures++;
    /* Passes are the boring majority; print them compactly. */
    printf("  %s ", cond ? "\033[32mpass\033[0m" : "\033[31mFAIL\033[0m");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

static void section(const char *s) { printf("\n\033[1m%s\033[0m\n", s); }

static double now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double) t.tv_sec + 1e-9 * (double) t.tv_nsec;
}

/* Deterministic, so a failure is reproducible. Not a CSPRNG and not pretending
 * to be: the seeds it makes are only ever fed to the batch, and the tests that
 * care about seed quality say so. */
static uint32_t rng_state = 0x9e3779b9u;
static uint8_t rnd_byte(void)
{
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 17;
    rng_state ^= rng_state << 5;
    return (uint8_t) rng_state;
}
static void rnd_fill(uint8_t *p, size_t n) { while (n--) *p++ = rnd_byte(); }

static void seed_of(uint8_t seed[32], uint32_t k)
{
    memset(seed, 0, 32);
    seed[0] = (uint8_t) k; seed[1] = (uint8_t) (k >> 8);
    seed[2] = (uint8_t) (k >> 16); seed[3] = (uint8_t) (k >> 24);
    seed[4] = 0xa5;
}

/* A batch over n signatures drawn from `sigs`/`pks`. */
static int batch_of(const uint8_t *sigs, const uint8_t *pks, size_t n,
                    const uint8_t *msg, size_t msg_len, uint32_t seedk)
{
    uint8_t seed[32];
    seed_of(seed, seedk);
    return lc_ed25519_verify_batch(sigs, pks, n, msg, msg_len, seed);
}

/* ---------- 1. the host shim, so nothing below is built on sand ---------- */

static void sha512_kat(void)
{
    static const struct { unsigned n; const char *hex; } v[] = {
        { 0,   "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
               "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e" },
        { 3,   "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
               "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f" },
        { 111, "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef86818196921760"
               "b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2" },
        { 112, "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32"
               "bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca" },
        /* 117 = 64 + 53, the length this actually hashes in production. */
        { 117, "c0c27aea8dbe169c4cf25176cbf12db708fd6303db8cf94a1cfb402c1680d3d6"
               "8f39bc5b9a10970dd5373cb0fe1cb36fa50e33165140d72933ba87af9d5d1ffe" },
        { 128, "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a24"
               "3667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321" },
    };
    unsigned char in[256], out[64];
    char got[129];
    unsigned k;
    int bad = 0;

    for (k = 0; k < sizeof v / sizeof v[0]; k++) {
        memset(in, 'a', sizeof in);
        if (v[k].n == 3) memcpy(in, "abc", 3);
        crypto_hash_sha512(out, in, v[k].n);
        for (int i = 0; i < 64; i++) sprintf(got + 2 * i, "%02x", out[i]);
        if (strcmp(got, v[k].hex) != 0) bad++;
    }
    check(bad == 0, "SHA-512 matches %u published vectors (0 = 111 = 112 = 128 byte "
                    "block boundaries, 117 = the production length)",
          (unsigned) (sizeof v / sizeof v[0]));
}

/* ---------- 2. the corpus is what it claims to be ---------- */

static void corpus_kat(void)
{
    unsigned i, ok = 0;

    for (i = 0; i < N; i++)
        ok += (unsigned) lc_ed25519_verify_fast(ED_CORPUS_SIG[i], MSG, MSGLEN,
                                                ED_CORPUS_PK[i]);
    check(ok == N, "all %u captured precommits verify individually (%u ok)", N, ok);

    /* The same bytes through libsodium's own entry point. If these ever part
     * company the fast path has drifted from the shipped semantics. */
    ok = 0;
    for (i = 0; i < N; i++)
        ok += crypto_sign_verify_detached(ED_CORPUS_SIG[i], MSG, MSGLEN,
                                          ED_CORPUS_PK[i]) == 0;
    check(ok == N, "the reference verifier agrees on all %u", N);

    for (i = 1; i < N; i++) {
        if (memcmp(ED_CORPUS_PK[i - 1], ED_CORPUS_PK[i], 32) == 0) break;
    }
    check(i == N, "no repeated signer in the corpus");
}

/* ---------- 3. the digit recoding ---------- */

/* sum_j d[j] * 2^(w*j) must equal the scalar. Checked in the open, because a
 * carry bug here would corrupt one window in a way the batch might absorb. */
static void recode_roundtrip(void)
{
    /* Reimplemented rather than exported: this is checking the idea, and a
     * shared helper would let a bug agree with itself. */
    const int w = LC_BATCH_W;
    const int ndigits = (256 + LC_BATCH_W - 1) / LC_BATCH_W;
    int bad = 0, trial;

    for (trial = 0; trial < 4000; trial++) {
        uint8_t  s[32];
        int32_t  digit[64];
        uint32_t acc[9];
        int      j;

        rnd_fill(s, 32);
        s[31] &= 0x0f;                        /* below 2^252, as a scalar is */

        {   /* recode */
            uint32_t mask = (1u << w) - 1u;
            int32_t  half = 1 << (w - 1), carry = 0;
            for (j = 0; j < ndigits; j++) {
                int      bit = j * w, byte = bit >> 3;
                uint32_t word = s[byte];
                int32_t  d;
                if (byte + 1 < 32) word |= (uint32_t) s[byte + 1] << 8;
                if (byte + 2 < 32) word |= (uint32_t) s[byte + 2] << 16;
                d = (int32_t) ((word >> (bit & 7)) & mask) + carry;
                if (d >= half) { d -= (int32_t) (1u << w); carry = 1; }
                else           { carry = 0; }
                digit[j] = d;
            }
            if (carry) { bad++; continue; }   /* must never happen for s < 2^252 */
        }

        /* Reconstruct into a 288-bit little-endian accumulator. */
        memset(acc, 0, sizeof acc);
        for (j = ndigits - 1; j >= 0; j--) {
            int      t;
            int64_t  carry64;
            for (t = 0; t < w; t++) {         /* acc <<= 1 */
                uint32_t c = 0;
                for (int q = 0; q < 9; q++) {
                    uint32_t nc = acc[q] >> 31;
                    acc[q] = (acc[q] << 1) | c;
                    c = nc;
                }
            }
            carry64 = digit[j];               /* acc += digit, signed */
            for (int q = 0; q < 9 && carry64; q++) {
                int64_t v = (int64_t) acc[q] + carry64;
                acc[q] = (uint32_t) v;
                carry64 = v >> 32;
            }
        }
        for (j = 0; j < 32; j++)
            if ((uint8_t) (acc[j / 4] >> (8 * (j % 4))) != s[j]) { bad++; break; }
    }
    check(bad == 0, "signed-digit recoding round-trips 4000 scalars at w=%d "
                    "(%d bad)", LC_BATCH_W, bad);
}

/* ---------- 4. the batch accepts what it should ---------- */

static void batch_accepts(void)
{
    check(batch_of((const uint8_t *) ED_CORPUS_SIG, (const uint8_t *) ED_CORPUS_PK,
                   N, MSG, MSGLEN, 1),
          "batch accepts all %u real precommits", N);

    check(batch_of((const uint8_t *) ED_CORPUS_SIG, (const uint8_t *) ED_CORPUS_PK,
                   0, MSG, MSGLEN, 1),
          "an empty batch passes (nothing failed)");

    /* Every size, so a chunk boundary cannot hide. LC_BATCH_CHUNK counts
     * points and each signature is two of them, so the folds land at
     * multiples of LC_BATCH_CHUNK/2 signatures. */
    {
        unsigned n, bad = 0;
        for (n = 1; n <= N; n++)
            if (!batch_of((const uint8_t *) ED_CORPUS_SIG,
                          (const uint8_t *) ED_CORPUS_PK, n, MSG, MSGLEN, n))
                bad++;
        check(bad == 0, "batch accepts every prefix length 1..%u, so no chunk "
                        "boundary is mishandled (%u bad)", N, bad);
    }

    /* The result must not depend on the weights, only on the signatures. */
    {
        uint32_t k, bad = 0;
        for (k = 0; k < 200; k++)
            if (!batch_of((const uint8_t *) ED_CORPUS_SIG,
                          (const uint8_t *) ED_CORPUS_PK, 64, MSG, MSGLEN,
                          0x1000 + k))
                bad++;
        check(bad == 0, "a good batch passes under 200 different weight seeds "
                        "(%u bad)", bad);
    }
}

/* ---------- 5. single-bit corruption ---------- */

/* One flipped bit anywhere in a justification's signatures must sink the whole
 * batch. This is the property the light client's safety rests on, so it is
 * checked exhaustively over a signature and a key rather than sampled. */
static void bitflips(void)
{
    static uint8_t sigs[N][64], pks[N][32];
    unsigned       i, bit, bad, missed;
    uint8_t        msg[MSGLEN];

    memcpy(sigs, ED_CORPUS_SIG, sizeof sigs);
    memcpy(pks,  ED_CORPUS_PK,  sizeof pks);

    /* every bit of one signature, with that signature sitting inside a full
     * 403-signature batch */
    missed = 0;
    for (bit = 0; bit < 64 * 8; bit++) {
        unsigned victim = 7;
        sigs[victim][bit / 8] ^= (uint8_t) (1u << (bit % 8));
        if (batch_of((const uint8_t *) sigs, (const uint8_t *) pks, N, MSG, MSGLEN, bit))
            missed++;
        sigs[victim][bit / 8] ^= (uint8_t) (1u << (bit % 8));
    }
    check(missed == 0, "all 512 single-bit flips of one signature inside a full "
                       "batch are caught (%u missed)", missed);

    missed = 0;
    for (bit = 0; bit < 32 * 8; bit++) {
        unsigned victim = 300;
        pks[victim][bit / 8] ^= (uint8_t) (1u << (bit % 8));
        if (batch_of((const uint8_t *) sigs, (const uint8_t *) pks, N, MSG, MSGLEN, bit))
            missed++;
        pks[victim][bit / 8] ^= (uint8_t) (1u << (bit % 8));
    }
    check(missed == 0, "all 256 single-bit flips of one public key inside a full "
                       "batch are caught (%u missed)", missed);

    /* every bit of the signed message */
    missed = 0;
    for (bit = 0; bit < MSGLEN * 8; bit++) {
        memcpy(msg, MSG, MSGLEN);
        msg[bit / 8] ^= (uint8_t) (1u << (bit % 8));
        if (batch_of((const uint8_t *) ED_CORPUS_SIG, (const uint8_t *) ED_CORPUS_PK,
                     N, msg, MSGLEN, bit))
            missed++;
    }
    check(missed == 0, "all %u single-bit flips of the payload are caught - a "
                       "wrong set_id or round cannot slip through (%u missed)",
          (unsigned) MSGLEN * 8, missed);

    /* one flipped bit in each of many different positions in the batch, to show
     * position within the chunking does not matter */
    missed = 0;
    for (i = 0; i < N; i++) {
        unsigned b = (i * 37) % 512;
        sigs[i][b / 8] ^= (uint8_t) (1u << (b % 8));
        if (batch_of((const uint8_t *) sigs, (const uint8_t *) pks, N, MSG, MSGLEN, i))
            missed++;
        sigs[i][b / 8] ^= (uint8_t) (1u << (b % 8));
    }
    check(missed == 0, "a flipped bit is caught at every one of the %u positions "
                       "in the batch (%u missed)", N, missed);

    /* and the same corruption seen by the individual verifier, so this is
     * agreement and not merely two independent rejections */
    bad = 0;
    for (bit = 0; bit < 64 * 8; bit++) {
        uint8_t s[64];
        memcpy(s, ED_CORPUS_SIG[7], 64);
        s[bit / 8] ^= (uint8_t) (1u << (bit % 8));
        if (lc_ed25519_verify_fast(s, MSG, MSGLEN, ED_CORPUS_PK[7])) bad++;
    }
    check(bad == 0, "the individual verifier rejects the same 512 flips (%u "
                    "accepted)", bad);
}

/* ---------- 6. batch and individual agree, input by input ---------- */

/* The eight small-order encodings and the non-canonical field elements: the
 * inputs where a verifier drifts from consensus instead of merely failing. */
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

static uint32_t agreed, disagreed;

static void agree(const char *what, const uint8_t *sig, const uint8_t *pk)
{
    int ref = lc_ed25519_verify_fast(sig, MSG, MSGLEN, pk);
    int bat = batch_of(sig, pk, 1, MSG, MSGLEN, agreed + 1);

    agreed++;
    if (ref != bat) {
        disagreed++;
        if (disagreed <= 6)
            printf("       DISAGREE [%s] individual=%d batch=%d\n", what, ref, bat);
    }
}

static void agreement(void)
{
    uint8_t sig[64], pk[32];
    unsigned i;

    agreed = disagreed = 0;

    for (i = 0; i < N; i++) agree("corpus", ED_CORPUS_SIG[i], ED_CORPUS_PK[i]);

    for (i = 0; i < 64 * 8; i++) {
        memcpy(sig, ED_CORPUS_SIG[0], 64);
        sig[i / 8] ^= (uint8_t) (1u << (i % 8));
        agree("sig-bitflip", sig, ED_CORPUS_PK[0]);
    }
    for (i = 0; i < 32 * 8; i++) {
        memcpy(pk, ED_CORPUS_PK[0], 32);
        pk[i / 8] ^= (uint8_t) (1u << (i % 8));
        agree("pk-bitflip", ED_CORPUS_SIG[0], pk);
    }

    /* small-order and non-canonical encodings, substituted for the key, for R
     * and for S in turn */
    for (i = 0; i < N_EDGE; i++) {
        agree("edge-pk", ED_CORPUS_SIG[0], EDGE[i]);
        memcpy(sig, ED_CORPUS_SIG[0], 64); memcpy(sig, EDGE[i], 32);
        agree("edge-R", sig, ED_CORPUS_PK[0]);
        memcpy(sig, ED_CORPUS_SIG[0], 64); memcpy(sig + 32, EDGE[i], 32);
        agree("edge-S", sig, ED_CORPUS_PK[0]);
    }

    /* a valid signature with a non-canonical S: S, S+L and S+2L all reduce to
     * the same scalar, and libsodium rejects the ones that are not canonical */
    {
        static const uint8_t L[32] = {
            0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,0xd6,0x9c,0xf7,0xa2,
            0xde,0xf9,0xde,0x14,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };
        int      k;
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

    /* deterministic garbage: overwhelmingly rejected by both, and the point is
     * that they reject it for the same inputs */
    rng_state = 0x9e3779b9u;
    for (i = 0; i < 600; i++) {
        rnd_fill(sig, 64);
        rnd_fill(pk, 32);
        agree("garbage", sig, pk);
    }

    check(disagreed == 0, "batch and individual agree on %u inputs: the corpus, "
                          "every bit flip of a signature and a key, small-order "
                          "and non-canonical encodings, S+L, S+2L, and 600 "
                          "random inputs (%u disagreements)", agreed, disagreed);
}

/* ---------- 7. the known disagreement, constructed on purpose ---------- */

/* The one place the two verifiers part company, built so it cannot be
 * forgotten. The batch equation is multiplied by the cofactor 8, so a residual
 * R + hA - sB that is a non-zero point of order 2 vanishes from it. libsodium
 * compares encodings and sees the difference.
 *
 * Any authority can produce this from its own key: sign as usual but commit to
 * R = rB + T instead of rB. The signature is then valid under the cofactored
 * rule and invalid under the cofactorless one.
 *
 * If this test starts reporting agreement, the batch has become cofactorless
 * (good, and the header's caveat should go) or the individual verifier has
 * become cofactored (bad). Either way it is not a silent change. */
static void torsion_divergence(void)
{
    /* y = p-1, x = 0: the point of order 2. */
    static const uint8_t T_BYTES[32] = {
        0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f };
    uint8_t        a[32], r[32], pk[32], sig[64], h[64], buf[64 + MSGLEN];
    ge25519_p3     A, Rp, T;
    ge25519_p1p1   t;
    ge25519_cached c;
    int            ref, bat, plain_ref, plain_bat;

    rng_state = 0x5bf03635u;
    rnd_fill(a, 32); a[31] &= 0x0f;
    rnd_fill(r, 32); r[31] &= 0x0f;

    ge25519_scalarmult_base(&A, a);
    ge25519_p3_tobytes(pk, &A);

    /* First a plain signature with the same key, to show the construction is
     * sound and only the torsion term is doing the work. */
    ge25519_scalarmult_base(&Rp, r);
    ge25519_p3_tobytes(sig, &Rp);
    memcpy(buf, sig, 32); memcpy(buf + 32, pk, 32); memcpy(buf + 64, MSG, MSGLEN);
    crypto_hash_sha512(h, buf, 64 + MSGLEN);
    sc25519_reduce(h);
    sc25519_muladd(sig + 32, h, a, r);
    plain_ref = lc_ed25519_verify_fast(sig, MSG, MSGLEN, pk);
    plain_bat = batch_of(sig, pk, 1, MSG, MSGLEN, 99);
    check(plain_ref == 1 && plain_bat == 1,
          "the freshly generated control signature verifies both ways "
          "(individual=%d batch=%d)", plain_ref, plain_bat);

    /* Now R = rB + T. */
    check(ge25519_frombytes(&T, T_BYTES) == 0, "the order-2 point decodes");
    ge25519_p3_to_cached(&c, &T);
    ge25519_add(&t, &Rp, &c);
    ge25519_p1p1_to_p3(&Rp, &t);
    ge25519_p3_tobytes(sig, &Rp);

    memcpy(buf, sig, 32); memcpy(buf + 32, pk, 32); memcpy(buf + 64, MSG, MSGLEN);
    crypto_hash_sha512(h, buf, 64 + MSGLEN);
    sc25519_reduce(h);
    sc25519_muladd(sig + 32, h, a, r);       /* s = r + h*a, unchanged */

    ref = lc_ed25519_verify_fast(sig, MSG, MSGLEN, pk);
    bat = batch_of(sig, pk, 1, MSG, MSGLEN, 100);

    check(ref == 0, "libsodium rejects the torsion-shifted signature");
    check(bat == 1, "the cofactored batch ACCEPTS it - this is the documented "
                    "semantic gap, not a bug in the test");

    /* It survives being hidden among honest ones, which is how it would arrive. */
    {
        static uint8_t sigs[N][64], pks[N][32];
        memcpy(sigs, ED_CORPUS_SIG, sizeof sigs);
        memcpy(pks,  ED_CORPUS_PK,  sizeof pks);
        memcpy(sigs[123], sig, 64);
        memcpy(pks[123], pk, 32);
        bat = batch_of((const uint8_t *) sigs, (const uint8_t *) pks, N,
                       MSG, MSGLEN, 101);
        check(bat == 1, "and it is still accepted inside a full %u-signature "
                        "batch, so weight it should not carry would be counted", N);
    }
}

/* ---------- 8. forgeries the batch must catch ---------- */

/* A residual that is not pure torsion has to be caught for every weight seed,
 * not most of them: that is the 2^-128 half of the argument, and it is the half
 * that actually protects the light client. */
static void forgeries(void)
{
    static uint8_t sigs[N][64], pks[N][32];
    unsigned k, missed = 0;

    memcpy(sigs, ED_CORPUS_SIG, sizeof sigs);
    memcpy(pks,  ED_CORPUS_PK,  sizeof pks);

    /* swap two signatures: both are individually valid, neither is valid for
     * the key it is now paired with */
    {
        uint8_t tmp[64];
        memcpy(tmp, sigs[10], 64);
        memcpy(sigs[10], sigs[11], 64);
        memcpy(sigs[11], tmp, 64);
    }
    for (k = 0; k < 300; k++)
        if (batch_of((const uint8_t *) sigs, (const uint8_t *) pks, N, MSG, MSGLEN,
                     0x7000 + k))
            missed++;
    check(missed == 0, "two swapped signatures are caught under 300 weight seeds "
                       "(%u missed)", missed);

    /* a signature duplicated onto another authority's slot */
    memcpy(sigs, ED_CORPUS_SIG, sizeof sigs);
    memcpy(sigs[200], sigs[201], 64);
    missed = 0;
    for (k = 0; k < 300; k++)
        if (batch_of((const uint8_t *) sigs, (const uint8_t *) pks, N, MSG, MSGLEN,
                     0x8000 + k))
            missed++;
    check(missed == 0, "a signature replayed under the wrong key is caught under "
                       "300 weight seeds (%u missed)", missed);

    /* the whole justification re-signed for a different round: every signature
     * valid, all of them over the wrong payload */
    {
        uint8_t other[MSGLEN];
        memcpy(other, MSG, MSGLEN);
        other[37] ^= 1;                       /* round is bytes 37..44 */
        missed = 0;
        for (k = 0; k < 100; k++)
            if (batch_of((const uint8_t *) ED_CORPUS_SIG, (const uint8_t *) ED_CORPUS_PK,
                         N, other, MSGLEN, 0x9000 + k))
                missed++;
        check(missed == 0, "the corpus is rejected against a neighbouring round "
                           "under 100 weight seeds (%u missed)", missed);
    }
}

/* ---------- 9. the streaming API ---------- */

static void streaming_api(void)
{
    lc_ed25519_batch *b = malloc(lc_batch_sizeof());
    uint8_t seed[32], sig[64];
    unsigned i;
    int rc;

    seed_of(seed, 4242);

    check(lc_batch_init(b, MSG, MSGLEN, seed) == 1, "init accepts a %u-byte message",
          (unsigned) MSGLEN);
    for (i = 0; i < N; i++)
        if (!lc_batch_add(b, ED_CORPUS_SIG[i], ED_CORPUS_PK[i])) break;
    check(i == N, "all %u signatures are accepted by add()", N);
    check(lc_batch_final(b) == 1, "final() passes");

    /* A rejected add is sticky: the caller may stop reading the stream. */
    lc_batch_init(b, MSG, MSGLEN, seed);
    lc_batch_add(b, ED_CORPUS_SIG[0], ED_CORPUS_PK[0]);
    memcpy(sig, ED_CORPUS_SIG[1], 64);
    memset(sig + 32, 0xff, 32);               /* S is not canonical */
    rc = lc_batch_add(b, sig, ED_CORPUS_PK[1]);
    check(rc == 0, "add() rejects a non-canonical S immediately, without any "
                   "group arithmetic");
    check(lc_batch_add(b, ED_CORPUS_SIG[2], ED_CORPUS_PK[2]) == 0,
          "and every later add() reports failure too");
    check(lc_batch_final(b) == 0, "final() stays failed");

    check(lc_batch_init(b, MSG, LC_BATCH_MSG_MAX + 1, seed) == 0,
          "init refuses a message longer than LC_BATCH_MSG_MAX, so the caller "
          "falls back instead of silently truncating");
    check(lc_batch_final(b) == 0, "and that batch cannot pass");

    free(b);
}

/* ---------- 10. how fast ---------- */

static void benchmark(void)
{
    const int rounds = 5;
    double    ind = 1e9, bat = 1e9;
    int       r;
    unsigned  i;
    uint8_t   seed[32];
    volatile int sink = 0;

    seed_of(seed, 7);
    for (r = 0; r < rounds; r++) {
        double t0 = now();
        for (i = 0; i < N; i++)
            sink += lc_ed25519_verify_fast(ED_CORPUS_SIG[i], MSG, MSGLEN,
                                           ED_CORPUS_PK[i]);
        double d = now() - t0;
        if (d < ind) ind = d;

        t0 = now();
        sink += lc_ed25519_verify_batch((const uint8_t *) ED_CORPUS_SIG,
                                        (const uint8_t *) ED_CORPUS_PK, N,
                                        MSG, MSGLEN, seed);
        d = now() - t0;
        if (d < bat) bat = d;
    }

    printf("\n\033[1mhost timing\033[0m  (best of %d, %u signatures, "
           "w=%d chunk=%d, state %.1f KB)\n",
           rounds, N, LC_BATCH_W, LC_BATCH_CHUNK, lc_batch_sizeof() / 1024.0);
    printf("  individual  %7.2f ms   %6.1f us/sig\n", ind * 1e3, ind * 1e6 / N);
    printf("  batch       %7.2f ms   %6.1f us/sig   %.2fx\n",
           bat * 1e3, bat * 1e6 / N, ind / bat);
    printf("  (host only - the number that decides anything is on the board)\n");
    (void) sink;
}

int main(void)
{
    printf("\033[1med25519 batch verification\033[0m  "
           "%u signatures, %u-byte payload, round %llu, set %llu\n",
           N, (unsigned) MSGLEN, (unsigned long long) ED_CORPUS_ROUND,
           (unsigned long long) ED_CORPUS_SET_ID);

    section("host reference");            sha512_kat();
    section("the corpus");                corpus_kat();
    section("digit recoding");            recode_roundtrip();
    section("batch accepts");             batch_accepts();
    section("single-bit corruption");     bitflips();
    section("agreement with libsodium");  agreement();
    section("known divergence");          torsion_divergence();
    section("forgeries");                 forgeries();
    section("streaming API");             streaming_api();
    benchmark();

    printf("\n%d tests, \033[1m%d failures\033[0m\n", tests, failures);
    return failures != 0;
}
