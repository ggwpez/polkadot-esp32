/* Batch ed25519 verification for signatures that all sign the same message.
 *
 * A GRANDPA justification is ~400 precommits over one identical 53-byte
 * payload. Verified one at a time that is ~400 independent double-scalar
 * multiplications. Verified as a batch it is one multi-scalar multiplication
 * over ~800 points, which is where the asymptotic win is: the cost per
 * signature falls from ~330 group operations to ~45.
 *
 * The check is
 *
 *     sum(z_i * R_i)  +  sum(z_i * h_i * A_i)  -  sum(z_i * s_i) * B  ==  O
 *
 * with fresh random 128-bit z_i, which holds if and only if every individual
 * equation holds, except with negligible probability - see the caveat below.
 *
 * The answer is one bit for the whole batch, not per signature. That is what
 * GRANDPA needs: a justification carrying any invalid signature is rejected
 * outright, so no attribution is required. grandpa.c already relies on exactly
 * this when it defers signature checks to another core.
 *
 * SEMANTIC CAVEAT - read before shipping this.
 *
 * The batch equation is cofactored: the sum is multiplied by 8 before the
 * comparison, which is what makes the random-weight argument sound over the
 * full group. libsodium's per-signature check is cofactorless. The two agree on
 * every input except one class: a signature whose residual R + hA - sB is a
 * non-zero point of order 1, 2, 4 or 8. libsodium rejects those; a cofactored
 * batch accepts them. Any authority can construct one deliberately (sign with
 * R = rB + T for a torsion point T), so the difference is reachable, not
 * theoretical. lc_batch_expect_disagreement() in test/test_ed25519.c builds one
 * and asserts the disagreement, so it stays a measured, documented fact.
 *
 * Callers that need libsodium's exact accept set must not use this. See
 * EXPERIMENTS.md for the cost of the alternatives.
 *
 * Everything else - non-canonical scalars, non-canonical point encodings,
 * small-order R or A, points off the curve - is rejected here exactly as
 * libsodium rejects it, in libsodium's order.
 */
#ifndef ED25519_BATCH_H
#define ED25519_BATCH_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bucket window in bits, and how many points one chunk holds. Two points per
 * signature, so LC_BATCH_CHUNK 128 buffers 64 signatures before folding them
 * into the running total. Both are tunables: raising them trades RAM for
 * speed, and EXPERIMENTS.md records what each setting measured. */
#ifndef LC_BATCH_W
#define LC_BATCH_W 6
#endif
#ifndef LC_BATCH_CHUNK
#define LC_BATCH_CHUNK 128
#endif

/* Longest message this will batch. GRANDPA's payload is 53 bytes. */
#define LC_BATCH_MSG_MAX 192

/* Opaque, and big: roughly 30 KB at the default tuning. Heap-allocate it,
 * do not put one on an ESP32 task stack. lc_batch_sizeof() is there so a
 * caller can print what it is about to ask for. */
typedef struct lc_ed25519_batch lc_ed25519_batch;

size_t lc_batch_sizeof(void);

/* The tuning the library was compiled with. Ask for it rather than reading the
 * macros: if the -D flags reach one translation unit and not another, this is
 * what shows it. */
void lc_batch_config(int *w, int *chunk);

/* `msg` must stay valid and unchanged until lc_batch_final() returns.
 * `seed` must be unpredictable to whoever supplied the signatures; a batch
 * verified with a seed the prover can guess is not verified at all. Returns 0
 * if msg_len exceeds LC_BATCH_MSG_MAX, in which case the batch is unusable and
 * the caller must verify individually. */
int lc_batch_init(lc_ed25519_batch *b, const uint8_t *msg, size_t msg_len,
                  const uint8_t seed[32]);

/* Returns 1 if the signature passed every per-signature check and was folded
 * in, 0 if it is already known bad. A 0 is sticky: the batch can only fail from
 * there, and the caller may stop reading. */
int lc_batch_add(lc_ed25519_batch *b, const uint8_t sig[64], const uint8_t pk[32]);

/* Fold at `points` buffered points instead of LC_BATCH_CHUNK. A benchmark aid:
 * it sweeps the time/RAM trade-off without a rebuild, but the state is still
 * sized by LC_BATCH_CHUNK, so production should set that at build time and
 * leave this alone. Values outside [2, LC_BATCH_CHUNK] are ignored. */
void lc_batch_set_chunk(lc_ed25519_batch *b, unsigned points);

/* Returns 1 if every signature added verifies, 0 otherwise. An empty batch
 * returns 1, matching "no signature failed". */
int lc_batch_final(lc_ed25519_batch *b);

/* One-shot form. sigs is n*64 bytes, pks is n*32. Allocates the state. */
int lc_ed25519_verify_batch(const uint8_t *sigs, const uint8_t *pks, size_t n,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t seed[32]);

#ifdef __cplusplus
}
#endif
#endif
