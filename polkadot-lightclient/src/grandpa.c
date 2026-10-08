#include "grandpa.h"
#include <string.h>

void grandpa_localized_payload(uint8_t out[GRANDPA_PAYLOAD_LEN],
                               const uint8_t target_hash[LC_HASH_LEN],
                               uint32_t target_number, uint64_t round,
                               uint64_t set_id)
{
    out[0] = 1;                                  /* Message::Precommit */
    memcpy(out + 1, target_hash, LC_HASH_LEN);
    for (int i = 0; i < 4; i++) out[33 + i] = (uint8_t)(target_number >> (8 * i));
    for (int i = 0; i < 8; i++) out[37 + i] = (uint8_t)(round >> (8 * i));
    for (int i = 0; i < 8; i++) out[45 + i] = (uint8_t)(set_id >> (8 * i));
}

/* Authority keys are sorted at generation time, so this is a binary search over
 * 600 entries rather than a scan repeated for every one of ~400 signatures. */
static int find_authority(const grandpa_authority_set *set, const uint8_t id[32])
{
    size_t lo = 0, hi = set->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = memcmp(set->keys + mid * 32, id, 32);
        if (c == 0) return (int)mid;
        if (c < 0) lo = mid + 1;
        else       hi = mid;
    }
    return -1;
}

grandpa_status grandpa_verify_finality_proof(lc_reader *r,
                                             const grandpa_authority_set *set,
                                             grandpa_result *out,
                                             grandpa_progress_fn progress,
                                             void *progress_ctx)
{
    return grandpa_verify_finality_proof_ex(r, set, out, progress, progress_ctx, 0);
}

grandpa_status grandpa_verify_finality_proof_ex(lc_reader *r,
                                                const grandpa_authority_set *set,
                                                grandpa_result *out,
                                                grandpa_progress_fn progress,
                                                void *progress_ctx,
                                                const grandpa_sig_pool *pool)
{
    memset(out, 0, sizeof *out);
    if (set->count > GRANDPA_MAX_AUTHORITIES) return GRANDPA_ERR_SET_TOO_LARGE;

    uint8_t voted[GRANDPA_MAX_AUTHORITIES / 8];
    memset(voted, 0, sizeof voted);

    /* FinalityProof.block - the node's idea of which block this is about. We do
     * not use it; the commit inside the justification is the authoritative
     * statement and it is what the signatures cover. */
    if (!lc_skip(r, LC_HASH_LEN)) return GRANDPA_ERR_TRUNCATED;

    uint64_t just_len;
    if (!lc_read_compact(r, &just_len)) return GRANDPA_ERR_TRUNCATED;

    if (!lc_read_u64(r, &out->round)) return GRANDPA_ERR_TRUNCATED;
    if (!lc_read(r, out->target_hash, LC_HASH_LEN)) return GRANDPA_ERR_TRUNCATED;
    if (!lc_read_u32(r, &out->target_number)) return GRANDPA_ERR_TRUNCATED;

    uint64_t n;
    if (!lc_read_compact(r, &n)) return GRANDPA_ERR_TRUNCATED;
    /* One vote per authority is the most a valid justification can carry, and it
     * bounds the work an untrusted peer can make us do. */
    if (n > set->count) return GRANDPA_ERR_TOO_MANY;
    out->n_precommits = (uint32_t)n;

    uint8_t payload[GRANDPA_PAYLOAD_LEN];
    grandpa_localized_payload(payload, out->target_hash, out->target_number,
                              out->round, set->set_id);

    /* Weight of the votes whose signature check is still outstanding. It is
     * added to out->weight only once join() has confirmed all of them, so a
     * result is never optimistic even for an instant. */
    uint64_t deferred_weight = 0;
    /* Votes that passed every cheap check and had their signature either
     * verified here or handed to the pool. Drives the progress hook, which can
     * no longer key off n_valid because deferred votes do not land there until
     * the end. */
    uint32_t accepted = 0;
    grandpa_status rc = GRANDPA_OK;

    for (uint64_t i = 0; i < n; i++) {
        uint8_t rec[132];       /* target_hash 32, target_number 4, sig 64, id 32 */
        if (!lc_read(r, rec, sizeof rec)) { rc = GRANDPA_ERR_TRUNCATED; break; }

        const uint8_t *vote_hash = rec;
        const uint8_t *vote_num  = rec + 32;
        const uint8_t *sig       = rec + 36;
        const uint8_t *id        = rec + 100;

        /* GRANDPA lets an authority precommit to a descendant of the commit
         * target; such a vote still supports finality but is proven via
         * votes_ancestries, which M1 does not carry. Skipping them can only
         * lower the counted weight, so this fails closed. */
        if (memcmp(vote_hash, out->target_hash, LC_HASH_LEN) != 0 ||
            memcmp(vote_num, payload + 33, 4) != 0) {
            out->n_other_target++;
            continue;
        }

        int idx = find_authority(set, id);
        if (idx < 0) { out->n_unknown_signer++; continue; }
        if (voted[idx >> 3] >> (idx & 7) & 1) { out->n_duplicate++; continue; }

        /* The seat is claimed here rather than after the signature check, so
         * that a deferred vote still blocks a second vote from the same
         * authority while its check is in flight. Claiming a seat whose
         * signature then turns out to be bad costs nothing: a single bad
         * signature rejects the whole justification, so no later record can be
         * counted anyway. */
        voted[idx >> 3] |= (uint8_t)(1u << (idx & 7));
        accepted++;

        /* Likewise the sample is taken at claim time. It is only ever read on
         * the GRANDPA_OK path, where every claimed record did verify. */
        if (!out->have_sample) {
            memcpy(out->sample, rec, sizeof out->sample);
            out->have_sample = 1;
        }

        /* The authority index the duplicate check already cost us is exactly
         * what selects the precomputed table, so this lookup is free. */
        const void *tab = lc_ed25519_tab_at(set->precomp, (size_t) idx);

        if (pool && pool->submit(pool->ctx, sig, payload, sizeof payload, id, tab)) {
            out->n_deferred++;
            deferred_weight += set->weights[idx];
        } else if (lc_ed25519_verify_tab(sig, payload, sizeof payload, id, tab)) {
            out->weight += set->weights[idx];
            out->n_valid++;
        } else {
            out->n_bad_sig++;
        }

        if (progress && (accepted & 31) == 0)
            progress(accepted, (uint32_t)n, progress_ctx);
    }

    /* Unconditional, on every path out of the loop: the workers are still
     * dereferencing `payload`, which lives on this stack frame. */
    if (pool) {
        uint32_t bad = pool->join(pool->ctx);
        out->n_bad_sig += bad;
        out->n_valid += out->n_deferred - bad;
        /* Deferred weight counts only if every deferred check passed. When one
         * did not, the justification is rejected below and the weight is never
         * looked at. */
        if (!bad) out->weight += deferred_weight;
    }

    if (rc != GRANDPA_OK) return rc;

    /* A justification carrying a signature that does not verify is malformed,
     * not merely under-weight. Substrate rejects these outright and so do we -
     * accepting them would mean tolerating a prover that is provably lying. */
    if (out->n_bad_sig) return GRANDPA_ERR_BAD_SIGNATURE;
    if (out->weight < set->threshold) return GRANDPA_ERR_INSUFFICIENT;

    out->finalized = 1;
    (void)just_len;
    return GRANDPA_OK;
}

const char *grandpa_strerror(grandpa_status s)
{
    switch (s) {
    case GRANDPA_OK:                return "ok";
    case GRANDPA_ERR_TRUNCATED:     return "justification truncated";
    case GRANDPA_ERR_TOO_MANY:      return "more precommits than authorities";
    case GRANDPA_ERR_BAD_SIGNATURE: return "invalid signature in justification";
    case GRANDPA_ERR_INSUFFICIENT:  return "insufficient weight for finality";
    case GRANDPA_ERR_SET_TOO_LARGE: return "authority set too large";
    }
    return "unknown";
}
