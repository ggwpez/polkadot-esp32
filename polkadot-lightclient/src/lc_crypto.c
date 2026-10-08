#include "lc_crypto.h"

/* libsodium, declared rather than #included - see lc_crypto.h. */
extern int crypto_generichash_blake2b(unsigned char *out, size_t outlen,
                                      const unsigned char *in, unsigned long long inlen,
                                      const unsigned char *key, size_t keylen);
extern int crypto_sign_verify_detached(const unsigned char *sig, const unsigned char *m,
                                       unsigned long long mlen, const unsigned char *pk);

void lc_blake2b256(uint8_t out[LC_HASH_LEN], const uint8_t *in, size_t len)
{
    crypto_generichash_blake2b(out, LC_HASH_LEN, in, (unsigned long long)len, 0, 0);
}

/* With LC_USE_FAST_ED25519, verification goes through the ref10 copy vendored in
 * lib/ed25519_fast instead of the platform's prebuilt libsodium. Same algorithm,
 * same upstream source, same checks in the same order - built as one translation
 * unit so the field arithmetic can inline, which is worth 1.06x at -Os
 * (EXPERIMENTS.md E7).
 *
 * This is a consensus-critical substitution, so it is a flag rather than a
 * silent default, and it is backed by measurement rather than by the two being
 * "the same code": env:mcbench checks the two against each other on 1,577
 * inputs on the device - all 403 real precommits, all 512 signature bit flips,
 * all 256 key bit flips, swapped-key and swapped-signature forgeries, the
 * small-order and non-canonical encodings for both R and A, an out-of-range S,
 * and deterministic garbage - with zero disagreements.
 *
 * The host test build does NOT define this. test/run.sh links the system
 * libsodium and should keep exercising it, because that is the second
 * independent implementation the corpus is checked against. */
#ifdef LC_USE_FAST_ED25519
#include "ed25519_fast.h"

int lc_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                      const uint8_t pk[32])
{
    return lc_ed25519_verify_fast(sig, msg, msg_len, pk);
}

const void *lc_ed25519_tab_at(const void *tables, size_t index)
{
    return tables ? &((const lc_ed25519_pretab *) tables)[index] : NULL;
}

int lc_ed25519_verify_tab(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                          const uint8_t pk[32], const void *tab)
{
    return lc_ed25519_verify_pre(sig, msg, msg_len, pk,
                                 (const lc_ed25519_pretab *) tab);
}
#else
/* No fast verifier, so no table can be used: the platform's prebuilt libsodium
 * has no entry point that takes one. Refusing to hand out a pointer here is
 * what makes the whole feature disappear from a build without the flag, rather
 * than having every caller test for it. */
const void *lc_ed25519_tab_at(const void *tables, size_t index)
{
    (void) tables; (void) index;
    return NULL;
}

int lc_ed25519_verify_tab(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                          const uint8_t pk[32], const void *tab)
{
    (void) tab;
    return lc_ed25519_verify(sig, msg, msg_len, pk);
}

int lc_ed25519_verify(const uint8_t sig[64], const uint8_t *msg, size_t msg_len,
                      const uint8_t pk[32])
{
    return crypto_sign_verify_detached(sig, msg, (unsigned long long)msg_len, pk) == 0;
}
#endif
