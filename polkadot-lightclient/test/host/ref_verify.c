/* libsodium's crypto_sign_verify_detached, for host builds only.
 *
 * A transcription of sign/ed25519/ref10/open.c on top of the ref10 primitives
 * vendored in lib/ed25519_fast. It exists so the host harness has the same
 * reference the device has: on the ESP32 this symbol comes from the framework's
 * prebuilt liblibsodium.a, and src/edbench.cpp has already shown the vendored
 * ref10 path agreeing with that prebuilt copy on 1,617 inputs. So agreement
 * here means agreement with the shipped verifier.
 *
 * The checks and their order are upstream's and must stay that way: they decide
 * which signatures exist as far as consensus is concerned. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../lib/ed25519_fast/src/vendor/private/ed25519_ref10.h"

extern int crypto_verify_32(const unsigned char *x, const unsigned char *y);
extern int crypto_hash_sha512(unsigned char *out, const unsigned char *in,
                              unsigned long long inlen);
extern int sodium_memcmp(const void *b1_, const void *b2_, size_t len);

int
crypto_sign_verify_detached(const unsigned char *sig, const unsigned char *m,
                            unsigned long long mlen, const unsigned char *pk)
{
    unsigned char *buf;
    unsigned char  h[64];
    unsigned char  rcheck[32];
    ge25519_p3     A;
    ge25519_p2     R;
    int            rc;

    if ((sig[63] & 240) != 0 && sc25519_is_canonical(sig + 32) == 0) {
        return -1;
    }
    if (ge25519_has_small_order(sig) != 0) {
        return -1;
    }
    if (ge25519_is_canonical(pk) == 0 || ge25519_has_small_order(pk) != 0) {
        return -1;
    }
    if (ge25519_frombytes_negate_vartime(&A, pk) != 0) {
        return -1;
    }

    /* Upstream hashes with the streaming API; one buffer is the same bytes. */
    buf = (unsigned char *) malloc((size_t) mlen + 64);
    if (buf == NULL) {
        return -1;
    }
    memcpy(buf, sig, 32);
    memcpy(buf + 32, pk, 32);
    memcpy(buf + 64, m, (size_t) mlen);
    crypto_hash_sha512(h, buf, mlen + 64);
    free(buf);
    sc25519_reduce(h);

    ge25519_double_scalarmult_vartime(&R, h, &A, sig + 32);
    ge25519_tobytes(rcheck, &R);

    rc = crypto_verify_32(rcheck, sig) | (-(rcheck == sig)) |
         sodium_memcmp(sig, rcheck, 32);
    return rc;
}
