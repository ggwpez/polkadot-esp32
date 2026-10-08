/* GRANDPA finality verification.
 *
 * A justification is a round number plus a commit (target block) plus a list of
 * precommits, each an ed25519 signature by a known authority. If authorities
 * holding strictly more than 2/3 of the total weight signed the same target,
 * that block is final and no honest chain can ever revert it.
 *
 * The justification is ~53 KB and is consumed as a stream: each precommit is a
 * fixed 132-byte record that is verified and discarded, so peak RAM is a few
 * hundred bytes regardless of the authority count.
 *
 * What is trusted going in: the authority set and its set_id.
 * What comes out: a block hash, and nothing else on the wire is believed. */
#ifndef GRANDPA_H
#define GRANDPA_H

#include <stddef.h>
#include <stdint.h>
#include "lc_reader.h"
#include "lc_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GRANDPA_MAX_AUTHORITIES 1024

typedef struct {
    const uint8_t *keys;        /* count * 32 bytes, sorted ascending */
    const uint64_t *weights;    /* count entries */
    size_t count;
    uint64_t total_weight;
    uint64_t threshold;         /* strictly-more-than-2/3 weight */
    uint64_t set_id;
    /* Optional: `count` precomputed per-authority tables, in the same order as
     * `keys`, as produced by tools/gen_checkpoint.py. Saves 9.4% of every
     * signature check and changes no verdict; NULL is the unchanged path. See
     * lc_crypto.h. Kept opaque here - this file has no business knowing what a
     * field element looks like. */
    const void *precomp;
} grandpa_authority_set;

typedef struct {
    /* The block the justification commits to. Only meaningful if finalized. */
    uint8_t  target_hash[LC_HASH_LEN];
    uint32_t target_number;
    uint64_t round;

    uint64_t weight;            /* accumulated weight of counted votes */
    uint32_t n_precommits;      /* records present in the justification */
    uint32_t n_valid;           /* signatures verified and counted */
    uint32_t n_bad_sig;         /* signature did not verify -> justification rejected */
    uint32_t n_unknown_signer;  /* signer is not in our authority set */
    uint32_t n_duplicate;       /* authority voted more than once */
    uint32_t n_other_target;    /* voted for a descendant, not the commit target */
    uint32_t n_deferred;        /* signature checks handed to a pool, if any */

    int finalized;              /* 1 only if the block is proven final */

    /* One precommit record that verified, kept so the device can re-run the
     * signature check on its own hardware with a deliberately wrong set_id or
     * round and confirm it fails. 132 bytes to prove the trust root is actually
     * load-bearing, rather than taking the host tests' word for it. */
    uint8_t  sample[132];
    int      have_sample;
} grandpa_result;

/* Optional progress hook; called every `n` verified signatures. May be NULL. */
typedef void (*grandpa_progress_fn)(uint32_t done, uint32_t total, void *ctx);

/* Optional: farms the ed25519 checks out to another core.
 *
 * The verification loop itself stays single-threaded and in stream order. Every
 * cheap check - vote target, authority lookup, duplicate - happens exactly where
 * it happens without a pool. Only the signature check may be deferred, and that
 * is where all of the cost is.
 *
 * Deferring is sound because one bad signature already rejects the whole
 * justification, so a deferred result needs no per-signature attribution: if
 * `join` reports zero failures then every submitted signature verified, and if
 * it reports any, nothing is accepted regardless of which ones they were.
 *
 * `submit` returns 1 if it took the work, 0 if the caller must verify inline
 * instead (a full pool must say 0 rather than block - that is what lets the
 * submitting core absorb the overflow with cycles it would otherwise spend
 * waiting on the network). It must copy `sig` and `pk`, which point into a
 * record buffer that is reused on the next iteration. `msg` stays valid until
 * `join` returns.
 *
 * `join` waits for every outstanding check and returns how many FAILED. The
 * verifier always calls it before returning, including on error paths, because
 * `msg` points at its stack. */
typedef struct {
    /* `tab` is the signer's precomputed table or NULL, already resolved by the
     * caller. Unlike `sig` and `pk` it needs no copying: it points into the
     * authority set, which outlives the whole verification. */
    int      (*submit)(void *ctx, const uint8_t sig[64], const uint8_t *msg,
                       size_t msg_len, const uint8_t pk[32], const void *tab);
    uint32_t (*join)(void *ctx);
    void *ctx;
} grandpa_sig_pool;

typedef enum {
    GRANDPA_OK = 0,
    GRANDPA_ERR_TRUNCATED,      /* stream ended mid-record */
    GRANDPA_ERR_TOO_MANY,       /* more precommits than authorities */
    GRANDPA_ERR_BAD_SIGNATURE,  /* at least one signature failed to verify */
    GRANDPA_ERR_INSUFFICIENT,   /* valid weight did not reach the threshold */
    GRANDPA_ERR_SET_TOO_LARGE
} grandpa_status;

/* Verifies a FinalityProof as returned by grandpa_proveFinality:
 *     { block: Hash, justification: Vec<u8>, unknown_headers: Vec<Header> }
 *
 * The caller does NOT say which block it wants. Whatever the justification
 * commits to is what gets proven, and the caller checks the result. A node that
 * answers with a different (still final) block is answering honestly, and
 * ancestry-walking to reach the requested block is exactly the complexity this
 * avoids. */
grandpa_status grandpa_verify_finality_proof(lc_reader *r,
                                             const grandpa_authority_set *set,
                                             grandpa_result *out,
                                             grandpa_progress_fn progress,
                                             void *progress_ctx);

/* As above, but may hand signature checks to `pool`. `pool` NULL is exactly
 * grandpa_verify_finality_proof, and that is how the host tests reach this
 * code, so the single-core path stays the tested one. */
grandpa_status grandpa_verify_finality_proof_ex(lc_reader *r,
                                                const grandpa_authority_set *set,
                                                grandpa_result *out,
                                                grandpa_progress_fn progress,
                                                void *progress_ctx,
                                                const grandpa_sig_pool *pool);

/* The bytes an authority actually signs, 53 of them:
 *   0x01 || target_hash || target_number(u32 LE) || round(u64 LE) || set_id(u64 LE)
 * 0x01 is the Precommit variant of GRANDPA's Message enum. Getting set_id or
 * the variant byte wrong makes every signature fail, silently and uniformly. */
#define GRANDPA_PAYLOAD_LEN 53
void grandpa_localized_payload(uint8_t out[GRANDPA_PAYLOAD_LEN],
                               const uint8_t target_hash[LC_HASH_LEN],
                               uint32_t target_number, uint64_t round,
                               uint64_t set_id);

const char *grandpa_strerror(grandpa_status s);

#ifdef __cplusplus
}
#endif
#endif
