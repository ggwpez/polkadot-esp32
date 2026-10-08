/* Crypto primitives used by the verification core.
 *
 * Both implementations are libsodium: on the ESP32 it is the copy bundled with
 * the Arduino framework, on the host it is the system libsodium.so. Declaring
 * the two symbols we need here (rather than including <sodium.h>) is what lets
 * the core build on a host that has the shared library but no dev headers. The
 * prototypes must match libsodium's exactly. */
#ifndef LC_CRYPTO_H
#define LC_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LC_HASH_LEN 32

/* blake2b-256, the hash used everywhere in Substrate: trie nodes, block hashes. */
void lc_blake2b256(uint8_t out[LC_HASH_LEN], const uint8_t *in, size_t len);

/* Returns 1 if `sig` is a valid ed25519 signature over `msg` by `pk`, else 0.
 * Never aborts, never leaks which check failed. */
int lc_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                      const uint8_t pk[32]);

/* ---------- precomputed per-key tables ----------
 *
 * The eight odd multiples of a public key are 9.4% of a verification on the
 * ESP32 (EXPERIMENTS.md E10) and depend on nothing but the key, of which a
 * GRANDPA era has 600 fixed ones. tools/gen_checkpoint.py precomputes them into
 * src/checkpoint_precomp.c; these two calls are how the verification loop
 * reaches them.
 *
 * The tables stay a `const void *` up here on purpose. Their layout is ref10's
 * and belongs to lib/ed25519_fast; grandpa.c only ever carries the pointer from
 * the authority set to the verifier, and lc_crypto.c is the one place that
 * knows what it points at. That is also why there is no stride to get wrong.
 *
 * This changes no accept/reject decision - see lib/ed25519_fast/src/
 * ed25519_fast.h - and NULL everywhere is exactly the old path, which is how
 * the host tests and any build without LC_USE_FAST_ED25519 run. */

/* &((const lc_ed25519_pretab *) tables)[index], or NULL if tables is NULL or
 * this build has no fast verifier to use it. */
const void *lc_ed25519_tab_at(const void *tables, size_t index);

/* lc_ed25519_verify with the key's precomputed table. `tab` must be the table
 * for exactly this `pk`; NULL is exactly lc_ed25519_verify. */
int lc_ed25519_verify_tab(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                          const uint8_t pk[32], const void *tab);

#ifdef __cplusplus
}
#endif
#endif
