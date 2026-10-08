#ifndef ED25519_FAST_H
#define ED25519_FAST_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

int lc_ed25519_verify_fast(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                           const uint8_t pk[32]);

/* ---------- precomputed per-key tables ----------
 *
 * Verifying sig(A, m) needs the eight odd multiples A, 3A, ... 15A of the
 * decoded public key, and ref10 rebuilds them from the 32 encoded bytes on
 * every single call: a field inversion to decompress A, then a double and
 * seven additions. Measured on the ESP32 that is 1642 us of a 17534 us
 * verification - 9.4% - and it depends on nothing but the key.
 *
 * A GRANDPA justification is ~403 signatures by 600 authorities that are fixed
 * for the whole era, so those 9.4% are spent recomputing 600 constants that
 * were already known when src/checkpoint.h was generated. This is the table
 * that lets them be computed once, and tools/gen_checkpoint.py emits it into
 * src/checkpoint_precomp.h.
 *
 * The entries are ge25519_precomp (yplusx, yminusx, xy2d - affine, Z implied
 * to be 1), not ge25519_cached, for two reasons: it is 120 bytes per point
 * instead of 160, and ge25519_madd/ge25519_msub can then be used in the scalar
 * loop in place of ge25519_add/ge25519_sub, which drops one fe25519_mul from
 * every one of the ~43 additions a 256-bit sliding-window scalar makes.
 *
 * SEMANTICS: this changes no accept/reject decision. The table holds the same
 * eight POINTS ref10 would have built; only their coordinate representatives
 * differ (Z = 1 rather than whatever the addition chain produced), and the
 * result is compared after ge25519_tobytes, which reduces canonically. The
 * limbs are written in the same signed, balanced radix-2^25.5 form as ref10's
 * own precomputed table in fe_25_5/base2.h, which the very same
 * ge25519_madd/ge25519_msub consume - half the magnitude the plain split would
 * give, and far inside the |f_i| <= 1.65*2^26 precondition. The wrapper's
 * canonicality and small-order screening still runs on every input. */
#define LC_ED25519_PRETAB_POINTS 8

typedef struct {
    /* [point][0]=yplusx [1]=yminusx [2]=xy2d, each a 10-limb fe25519. */
    int32_t v[LC_ED25519_PRETAB_POINTS][3][10];
} lc_ed25519_pretab;

/* Builds the table for `pk`. Returns 1, or 0 if `pk` does not decode - which
 * is the same condition ge25519_frombytes_negate_vartime rejects, so a key
 * this refuses is a key the verifier would have refused anyway.
 *
 * The device does not need this to use a generated table; it exists so the
 * tests can derive a table with ref10's own arithmetic and check the generated
 * one against it, and so a future NVS-loaded authority set can build its own. */
int lc_ed25519_pretab_build(lc_ed25519_pretab *out, const uint8_t pk[32]);

/* 1 if the two tables hold the same eight points. Compares reduced encodings,
 * not limbs: ref10's field elements are not canonical, so two correct tables
 * for one key can differ bit for bit. */
int lc_ed25519_pretab_equal(const lc_ed25519_pretab *a, const lc_ed25519_pretab *b);

/* lc_ed25519_verify_fast with the key's table supplied. `tab` must be the
 * table for exactly this `pk`; passing NULL is exactly lc_ed25519_verify_fast. */
int lc_ed25519_verify_pre(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                          const uint8_t pk[32], const lc_ed25519_pretab *tab);

#ifdef __cplusplus
}
#endif
#endif
