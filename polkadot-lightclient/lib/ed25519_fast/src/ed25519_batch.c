/* Batch ed25519 verification - see ed25519_batch.h for what it computes and
 * for the cofactor caveat.
 *
 * This file is #included at the end of ed25519_fast.c rather than compiled on
 * its own, for the same reason ed25519_ref10.c is: one translation unit lets
 * the field arithmetic inline, and it puts ref10's file-static helpers
 * (ge25519_p3_0, ge25519_p3_dbl) in scope without patching upstream.
 *
 * Structure: a bucket multi-scalar multiplication (Pippenger) over chunks. Each
 * signature contributes two weighted points; when LC_BATCH_CHUNK points have
 * accumulated the chunk is reduced to a single point and folded into a running
 * total, so peak memory is a tunable constant rather than a function of the
 * justification size. */

#include <stdlib.h>

#include "ed25519_batch.h"

/* Under -fwhole-program every definition here would be internal to the
 * translation unit, and the firmware links against these from outside it. */
#ifdef LC_ED25519_WHOLE_PROGRAM
#define LC_BATCH_API __attribute__((externally_visible))
#else
#define LC_BATCH_API
#endif

#define NBUCKETS (1 << (LC_BATCH_W - 1))
#define NDIGITS  ((256 + LC_BATCH_W - 1) / LC_BATCH_W)

/* Points are held in Duif form (y+x, y-x, 2dxy), which is 120 bytes against a
 * ge25519_cached's 160 and takes ge25519_madd rather than ge25519_add in the
 * bucket loop - three field multiplications instead of four, on the operation
 * that dominates the whole batch.
 *
 * Normally converting to this form costs an inversion per point, which would
 * eat the saving many times over. It is free here because every point entering
 * a batch comes straight out of ge25519_frombytes, which sets Z = 1 and
 * T = X*Y. So x and y are already X and Y, and 2dxy is one multiply by d2.
 * lc_batch_add() is the only producer and the invariant is asserted there. */
struct lc_ed25519_batch {
    ge25519_precomp pts[LC_BATCH_CHUNK];
    int8_t         dig[LC_BATCH_CHUNK][NDIGITS];
    ge25519_p3     bucket[NBUCKETS];
    ge25519_p3     acc;            /* running MSM total over folded chunks */
    unsigned char  ssum[32];       /* sum(z_i * s_i) mod L */
    unsigned char  seed[32];
    unsigned char  zbuf[64];       /* four 16-byte weights per hash */
    unsigned char  msgbuf[64 + LC_BATCH_MSG_MAX];
    uint32_t       zctr;
    unsigned       zleft;
    size_t         msg_len;
    unsigned       npts;
    unsigned       chunk;     /* fold at this many points; <= LC_BATCH_CHUNK */
    int            zchecked;
    int            failed;
};

LC_BATCH_API
size_t lc_batch_sizeof(void) { return sizeof(struct lc_ed25519_batch); }

/* Reported by the library rather than read from the header, so a benchmark
 * cannot print a tuning the library was not actually built with. */
LC_BATCH_API
void lc_batch_config(int *w, int *chunk)
{
    if (w)     *w     = LC_BATCH_W;
    if (chunk) *chunk = LC_BATCH_CHUNK;
}

/* ---------- small helpers over ref10 ---------- */

static void p3_neg(ge25519_p3 *p)
{
    fe25519_neg(p->X, p->X);
    fe25519_neg(p->T, p->T);
}

/* r += q and r -= q, for the two point forms this needs.
 *
 * These are add-2008-hwcd-3, which is complete on this curve, so neither needs
 * a special case for r == q or for either side being the identity - and empty
 * buckets are the identity. Worth the two multiplications a dedicated doubling
 * would save, since doublings are under 1% of a batch. */
static void p3_add(ge25519_p3 *r, const ge25519_cached *q)
{
    ge25519_p1p1 t;
    ge25519_add(&t, r, q);
    ge25519_p1p1_to_p3(r, &t);
}

static void p3_sub(ge25519_p3 *r, const ge25519_cached *q)
{
    ge25519_p1p1 t;
    ge25519_sub(&t, r, q);
    ge25519_p1p1_to_p3(r, &t);
}

static void p3_madd(ge25519_p3 *r, const ge25519_precomp *q)
{
    ge25519_p1p1 t;
    ge25519_madd(&t, r, q);
    ge25519_p1p1_to_p3(r, &t);
}

static void p3_msub(ge25519_p3 *r, const ge25519_precomp *q)
{
    ge25519_p1p1 t;
    ge25519_msub(&t, r, q);
    ge25519_p1p1_to_p3(r, &t);
}

/* Duif form of a point that is known to have Z = 1 and T = X*Y - see the note
 * on struct lc_ed25519_batch. ge25519_p3_to_precomp does the same thing for the
 * general case at the cost of a field inversion. */
static void p3_z1_to_precomp(ge25519_precomp *pi, const ge25519_p3 *p)
{
    fe25519_add(pi->yplusx, p->Y, p->X);
    fe25519_sub(pi->yminusx, p->Y, p->X);
    fe25519_mul(pi->xy2d, p->T, d2);
}

/* Is Z exactly 1? Only used to assert the invariant above. */
static int p3_z_is_one(const ge25519_p3 *p)
{
    unsigned char s[32];
    unsigned char acc;
    int i;

    fe25519_tobytes(s, p->Z);
    acc = (unsigned char) (s[0] ^ 1);
    for (i = 1; i < 32; i++) acc |= s[i];
    return acc == 0;
}

static void p3_dbl(ge25519_p3 *r)
{
    ge25519_p1p1 t;
    ge25519_p3_dbl(&t, r);
    ge25519_p1p1_to_p3(r, &t);
}

static int p3_is_identity(const ge25519_p3 *p)
{
    unsigned char s[32];
    unsigned char acc;
    int i;

    /* The identity encodes as y = 1, sign 0: 0x01 then 31 zero bytes. */
    ge25519_p3_tobytes(s, p);
    acc = (unsigned char) (s[0] ^ 1);
    for (i = 1; i < 32; i++) acc |= s[i];
    return acc == 0;
}

/* Signed-digit recoding, base 2^LC_BATCH_W, digits in [-2^(w-1), 2^(w-1)).
 * Scalars here are always below L < 2^253 and NDIGITS*w >= 256, so the carry
 * chain always has a digit left to land in. */
static void recode(int8_t out[NDIGITS], const unsigned char s[32])
{
    const int      w    = LC_BATCH_W;
    const uint32_t mask = (1u << w) - 1u;
    const int32_t  half = 1 << (w - 1);
    int32_t        carry = 0;
    int            j;

    for (j = 0; j < NDIGITS; j++) {
        int      bit  = j * w;
        int      byte = bit >> 3;
        uint32_t word = (uint32_t) s[byte];
        int32_t  dg;

        if (byte + 1 < 32) word |= (uint32_t) s[byte + 1] << 8;
        if (byte + 2 < 32) word |= (uint32_t) s[byte + 2] << 16;
        dg = (int32_t) ((word >> (bit & 7)) & mask) + carry;
        if (dg >= half) { dg -= (int32_t) (1u << w); carry = 1; }
        else            { carry = 0; }
        out[j] = (int8_t) dg;
    }
}

/* ---------- weights ---------- */

/* 128-bit weights, expanded from the seed four at a time. Below 2^128 they are
 * trivially canonical scalars, and 128 bits is the standard batch security
 * parameter: forging past the check needs a collision in that space. */
static void next_weight(struct lc_ed25519_batch *b, unsigned char z[32])
{
    unsigned char in[36];

    if (b->zleft == 0) {
        memcpy(in, b->seed, 32);
        in[32] = (unsigned char) (b->zctr);
        in[33] = (unsigned char) (b->zctr >> 8);
        in[34] = (unsigned char) (b->zctr >> 16);
        in[35] = (unsigned char) (b->zctr >> 24);
        b->zctr++;
        crypto_hash_sha512(b->zbuf, in, sizeof in);
        b->zleft = 4;
    }
    memset(z, 0, 32);
    memcpy(z, b->zbuf + 16 * (4 - b->zleft), 16);
    b->zleft--;
}

/* ---------- the multi-scalar multiplication ---------- */

/* Reduce the buffered chunk to a single point and add it to b->acc.
 *
 * Each chunk is reduced on its own and only then folded in: the windows of one
 * chunk are combined by shifting the running sum left by w between them, and
 * that shift must not touch what earlier chunks already contributed. */
static void fold_chunk(struct lc_ed25519_batch *b)
{
    ge25519_p3     sum, total, running;
    ge25519_cached c;
    unsigned       i;
    int            j, k, t;

    if (b->npts == 0) return;

    ge25519_p3_0(&sum);

    /* Most significant window first. */
    for (j = NDIGITS - 1; j >= 0; j--) {
        for (k = 0; k < NBUCKETS; k++) ge25519_p3_0(&b->bucket[k]);

        for (i = 0; i < b->npts; i++) {
            int dg = b->dig[i][j];
            if (dg > 0)      p3_madd(&b->bucket[dg - 1], &b->pts[i]);
            else if (dg < 0) p3_msub(&b->bucket[-dg - 1], &b->pts[i]);
        }

        /* sum_k (k+1) * bucket[k] by the running-sum trick: 2*NBUCKETS
         * additions rather than a scalar multiplication per bucket. */
        ge25519_p3_0(&running);
        ge25519_p3_0(&total);
        for (k = NBUCKETS - 1; k >= 0; k--) {
            ge25519_p3_to_cached(&c, &b->bucket[k]);
            p3_add(&running, &c);
            ge25519_p3_to_cached(&c, &running);
            p3_add(&total, &c);
        }

        if (j != NDIGITS - 1)
            for (t = 0; t < LC_BATCH_W; t++) p3_dbl(&sum);
        ge25519_p3_to_cached(&c, &total);
        p3_add(&sum, &c);
    }

    ge25519_p3_to_cached(&c, &sum);
    p3_add(&b->acc, &c);
    b->npts = 0;
}

/* ---------- public API ---------- */

LC_BATCH_API
int lc_batch_init(lc_ed25519_batch *b, const uint8_t *msg, size_t msg_len,
                  const uint8_t seed[32])
{
    if (msg_len > LC_BATCH_MSG_MAX) {
        memset(b, 0, sizeof *b);
        b->failed = 1;
        return 0;
    }
    memset(b, 0, sizeof *b);
    ge25519_p3_0(&b->acc);
    b->chunk = LC_BATCH_CHUNK;
    memcpy(b->seed, seed, 32);
    memcpy(b->msgbuf + 64, msg, msg_len);
    b->msg_len = msg_len;
    return 1;
}

LC_BATCH_API
int lc_batch_add(lc_ed25519_batch *b, const uint8_t sig[64], const uint8_t pk[32])
{
    ge25519_p3    R, A;
    unsigned char h[64], z[32], hz[32];

    if (b->failed) return 0;

    /* libsodium's per-signature checks, in libsodium's order. Anything these
     * reject is rejected identically by the reference verifier. */
    if (sc25519_is_canonical(sig + 32) == 0)   goto bad;
    if (ge25519_has_small_order(sig) != 0)     goto bad;
    if (ge25519_is_canonical(pk) == 0)         goto bad;
    if (ge25519_has_small_order(pk) != 0)      goto bad;
    if (ge25519_frombytes_negate_vartime(&A, pk) != 0) goto bad;

    /* Two checks the reference gets for free and this does not. The reference
     * re-encodes the recomputed R and compares bytes, so a non-canonical R
     * encoding, or one that is not a curve point at all, can never match. Here
     * R is decoded and used, so both have to be rejected explicitly or the
     * batch would accept signatures libsodium does not. */
    if (ge25519_is_canonical(sig) == 0)        goto bad;
    if (ge25519_frombytes(&R, sig) != 0)       goto bad;

    /* h = SHA-512(R || A || M) mod L */
    memcpy(b->msgbuf, sig, 32);
    memcpy(b->msgbuf + 32, pk, 32);
    crypto_hash_sha512(h, b->msgbuf, (unsigned long long) (64 + b->msg_len));
    sc25519_reduce(h);

    next_weight(b, z);

    /* ssum += z * s, and the A weight is z*h. */
    sc25519_muladd(b->ssum, z, sig + 32, b->ssum);
    sc25519_mul(hz, z, h);

    /* frombytes_negate_vartime returns -A; the batch equation wants +A. */
    p3_neg(&A);

    /* The Duif conversion below is only valid for Z = 1, which is what both
     * decoders produce for every input. The invariant is structural rather than
     * data-dependent, so checking the first point of the batch is enough to
     * catch a refactor; checking all of them would cost a field reduction per
     * point for no more information. If it ever fails this must go back to
     * ge25519_p3_to_precomp and pay for the inversion. */
    if (!b->zchecked) {
        b->zchecked = 1;
        if (!p3_z_is_one(&R) || !p3_z_is_one(&A)) goto bad;
    }

    if (b->npts + 2 > b->chunk) fold_chunk(b);

    p3_z1_to_precomp(&b->pts[b->npts], &R);
    recode(b->dig[b->npts], z);
    b->npts++;
    p3_z1_to_precomp(&b->pts[b->npts], &A);
    recode(b->dig[b->npts], hz);
    b->npts++;

    return 1;

bad:
    b->failed = 1;
    return 0;
}

LC_BATCH_API
void lc_batch_set_chunk(lc_ed25519_batch *b, unsigned points)
{
    if (points >= 2 && points <= LC_BATCH_CHUNK) b->chunk = points & ~1u;
}

LC_BATCH_API
int lc_batch_final(lc_ed25519_batch *b)
{
    ge25519_p3     sb;
    ge25519_cached c;
    int            i, ok;

    if (b->failed) return 0;

    fold_chunk(b);

    /* acc - (sum z_i s_i) * B, then clear the cofactor. */
    ge25519_scalarmult_base(&sb, b->ssum);
    ge25519_p3_to_cached(&c, &sb);
    p3_sub(&b->acc, &c);
    for (i = 0; i < 3; i++) p3_dbl(&b->acc);

    ok = p3_is_identity(&b->acc);
    if (!ok) b->failed = 1;
    return ok;
}

LC_BATCH_API
int lc_ed25519_verify_batch(const uint8_t *sigs, const uint8_t *pks, size_t n,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t seed[32])
{
    lc_ed25519_batch *b = (lc_ed25519_batch *) malloc(sizeof *b);
    size_t            i;
    int               ok;

    if (b == NULL) return 0;
    if (!lc_batch_init(b, msg, msg_len, seed)) { free(b); return 0; }

    for (i = 0; i < n; i++) {
        if (!lc_batch_add(b, sigs + i * 64, pks + i * 32)) break;
    }
    ok = lc_batch_final(b);
    free(b);
    return ok;
}
