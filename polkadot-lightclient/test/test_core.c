/* Host tests for the verification core, run against real Polkadot data captured
 * by tools/gen_fixtures.py. Same C files the firmware builds, same libsodium,
 * so a pass here means the maths is right and only transport is left.
 *
 * The negative tests matter more than the positive one. A light client that
 * accepts a good proof is easy; the property worth testing is that it never
 * returns a value that was not actually in the trie. */
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "../src/scale.h"
#include "../src/trie.h"
#include "../src/grandpa.h"
#include "../src/lc_reader.h"
#include "../src/fmt.h"
#ifndef LC_FIXTURE_HEADER
#define LC_FIXTURE_HEADER "fixtures/fixtures.h"
#endif
#ifndef LC_FIXTURE_DIR
#define LC_FIXTURE_DIR "test/fixtures"
#endif
#include LC_FIXTURE_HEADER

#define MAX_PROOF_NODES 64

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

static uint8_t *slurp(const char *path, size_t *len)
{
#ifdef LC_EMBED_FIXTURES
    /* QEMU runs the same tests with captured bytes in flash, without a host
     * filesystem or semihosting. Return writable copies for tamper tests. */
    #include "qemu_fixtures.inc"
    for (size_t i = 0; i < sizeof(qemu_fixtures) / sizeof(qemu_fixtures[0]); i++) {
        if (strcmp(path, qemu_fixtures[i].name) == 0) {
            *len = qemu_fixtures[i].size;
            uint8_t *b = malloc(*len);
            if (!b) abort();
            memcpy(b, qemu_fixtures[i].bytes, *len);
            return b;
        }
    }
    fprintf(stderr, "missing embedded fixture: %s\n", path);
    abort();
#else
    char full[512];
    snprintf(full, sizeof full, LC_FIXTURE_DIR "/%s", path);
    FILE *f = fopen(full, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", full); exit(2); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc((size_t)n);
    if (fread(b, 1, (size_t)n, f) != (size_t)n) exit(2);
    fclose(f);
    *len = (size_t)n;
    return b;
#endif
}

/* Proof files are u32 count, then per node u32 len + bytes. */
static size_t unpack_nodes(const uint8_t *buf, size_t len,
                           const uint8_t **data, size_t *sizes, size_t cap)
{
    size_t pos = 0;
    uint32_t count = (uint32_t)(buf[0] | buf[1] << 8 | buf[2] << 16 | buf[3] << 24);
    pos = 4;
    if (count > cap) exit(2);
    for (uint32_t i = 0; i < count; i++) {
        uint32_t n = (uint32_t)(buf[pos] | buf[pos+1] << 8 | buf[pos+2] << 16 | buf[pos+3] << 24);
        pos += 4;
        data[i] = buf + pos;
        sizes[i] = n;
        pos += n;
        if (pos > len) exit(2);
    }
    return count;
}

static uint64_t le64(const uint8_t *b, size_t n)
{
    uint64_t v = 0;
    for (size_t i = 0; i < n && i < 8; i++) v |= (uint64_t)b[i] << (8 * i);
    return v;
}


/* ---------- shared fixture state ---------- */
static uint8_t *fp_buf, *hdr_buf, *paras_buf, *ah_buf, *auth_buf;
static size_t fp_len, hdr_len, paras_len, ah_len, auth_len;
static grandpa_authority_set AUTH;

static void load_fixtures(void)
{
    fp_buf    = slurp("finality_proof.bin", &fp_len);
    hdr_buf   = slurp("relay_header.bin",   &hdr_len);
    paras_buf = slurp("paras_proof.bin",    &paras_len);
    ah_buf    = slurp("ah_proof.bin",       &ah_len);
    auth_buf  = slurp("authorities.bin",    &auth_len);

    uint32_t n = (uint32_t)(auth_buf[0] | auth_buf[1] << 8 | auth_buf[2] << 16 | auth_buf[3] << 24);
    AUTH.count = n;
    AUTH.keys = auth_buf + 4;
    /* Weights follow the keys in the file at an offset that is not a multiple
     * of 8, so they are copied into an aligned array rather than cast in place.
     * The generated checkpoint.h declares a real uint64_t array and has no such
     * problem; this is purely about reading the fixture. */
    {
        const uint8_t *w = auth_buf + 4 + (size_t)n * 32;
        uint64_t *aligned = malloc((size_t)n * sizeof(uint64_t));
        for (uint32_t i = 0; i < n; i++) aligned[i] = le64(w + (size_t)i * 8, 8);
        AUTH.weights = aligned;
    }
    AUTH.total_weight = FX_TOTAL_WEIGHT;
    AUTH.threshold = FX_THRESHOLD;
    AUTH.set_id = FX_SET_ID;
}

/* Byte offset of precommit[i] inside finality_proof.bin, found by decoding the
 * same prefix the verifier decodes. */
static size_t precommit_offset(uint32_t i)
{
    lc_mem_reader m;
    lc_mem_reader_init(&m, fp_buf, fp_len);
    uint64_t tmp; uint32_t t32; uint8_t h[32];
    lc_skip(&m.base, 32);
    lc_read_compact(&m.base, &tmp);
    lc_read_u64(&m.base, &tmp);
    lc_read(&m.base, h, 32);
    lc_read_u32(&m.base, &t32);
    lc_read_compact(&m.base, &tmp);
    return m.pos + (size_t)i * 132;
}

static grandpa_status run_grandpa(const uint8_t *buf, size_t len,
                                  const grandpa_authority_set *set,
                                  grandpa_result *res)
{
    lc_mem_reader m;
    lc_mem_reader_init(&m, buf, len);
    return grandpa_verify_finality_proof(&m.base, set, res, 0, 0);
}

/* ---------- 1. SCALE ---------- */
static void test_scale(void)
{
    section("1. SCALE codec");

    /* The four compact encodings, at and around their boundaries. */
    const uint32_t vals[] = { 0, 1, 63, 64, 16383, 16384, 1073741823, 1073741824, 0xffffffffu };
    int roundtrip_ok = 1;
    size_t expect_len[] = { 1, 1, 1, 2, 2, 4, 4, 5, 5 };
    for (size_t i = 0; i < sizeof vals / sizeof *vals; i++) {
        uint8_t enc[8];
        size_t n = scale_encode_compact(enc, vals[i]);
        scale_rd r; scale_init(&r, enc, n);
        uint64_t back = scale_compact(&r);
        if (back != vals[i] || n != expect_len[i] || r.pos != n) {
            roundtrip_ok = 0;
            printf("       %u -> %zu bytes -> %llu\n", vals[i], n, (unsigned long long)back);
        }
    }
    check(roundtrip_ok, "compact encode/decode round-trips across all four modes");

    /* A truncated buffer must set the error flag, not read past the end. */
    uint8_t trunc[1] = { 0xfe };            /* 4-byte mode, but only 1 byte present */
    scale_rd r; scale_init(&r, trunc, 1);
    scale_compact(&r);
    check(!scale_ok(&r), "truncated compact sets the error flag");

    scale_init(&r, trunc, 1);
    scale_take(&r, 99);
    check(!scale_ok(&r), "over-long take sets the error flag");

    /* Real relay header from the fixture. */
    lc_header h;
    int ok = scale_decode_header(hdr_buf, hdr_len, &h);
    check(ok, "decodes the live relay header");
    check(ok && h.number == FX_RELAY_NUMBER, "header number is #%u (expected #%u)",
          ok ? h.number : 0, FX_RELAY_NUMBER);
    check(ok && h.encoded_len == hdr_len,
          "digest walk consumes the header exactly (%zu of %zu bytes)",
          ok ? h.encoded_len : 0, hdr_len);
    check(ok && memcmp(h.state_root, FX_RELAY_STATE_ROOT, 32) == 0,
          "state_root matches the fixture");
}

/* ---------- 2. header binding ---------- */
static void test_header_binding(void)
{
    section("2. header binding (blake2b re-encode check)");

    uint8_t got[32];
    lc_blake2b256(got, hdr_buf, hdr_len);
    check(memcmp(got, FX_RELAY_HASH, 32) == 0,
          "blake2b(header) == the hash GRANDPA committed to");

    /* This is the check that makes a header trustworthy at all: flip one bit
     * anywhere in it and the binding must fail. */
    int all_detected = 1;
    for (size_t i = 0; i < hdr_len; i++) {
        hdr_buf[i] ^= 0x01;
        lc_blake2b256(got, hdr_buf, hdr_len);
        if (memcmp(got, FX_RELAY_HASH, 32) == 0) all_detected = 0;
        hdr_buf[i] ^= 0x01;
    }
    check(all_detected, "every single-bit change to the header breaks the binding (%zu positions)",
          hdr_len);
}

/* ---------- 3. GRANDPA ---------- */
static void test_grandpa(void)
{
    section("3. GRANDPA justification");

    grandpa_result res;
    grandpa_status s = run_grandpa(fp_buf, fp_len, &AUTH, &res);

    check(s == GRANDPA_OK, "verifies the live justification (%s)", grandpa_strerror(s));
    check(res.finalized, "reports finalized");
    check(res.target_number == FX_RELAY_NUMBER, "commits to #%u", res.target_number);
    check(memcmp(res.target_hash, FX_RELAY_HASH, 32) == 0, "commit hash matches the fixture");
    check(res.round == FX_ROUND, "round %llu", (unsigned long long)res.round);
    check(res.weight >= FX_THRESHOLD, "weight %llu of %llu, threshold %llu",
          (unsigned long long)res.weight, (unsigned long long)FX_TOTAL_WEIGHT,
          (unsigned long long)FX_THRESHOLD);
    printf("       %u precommits: %u counted, %u unknown signer, %u duplicate, "
           "%u for another target\n",
           res.n_precommits, res.n_valid, res.n_unknown_signer, res.n_duplicate,
           res.n_other_target);

    /* Negative: the set_id is bound into every signed payload, so a device
     * following a stale authority set sees zero valid votes rather than
     * silently accepting a justification from a different set. */
    grandpa_authority_set stale = AUTH;
    stale.set_id = AUTH.set_id + 1;
    s = run_grandpa(fp_buf, fp_len, &stale, &res);
    check(s == GRANDPA_ERR_BAD_SIGNATURE || s == GRANDPA_ERR_INSUFFICIENT,
          "wrong set_id is rejected (%s, %u valid)", grandpa_strerror(s), res.n_valid);
    check(res.n_valid == 0, "wrong set_id yields zero valid signatures");

    /* Negative: a forged signature. */
    size_t sig_off = precommit_offset(0) + 36;
    fp_buf[sig_off] ^= 0x01;
    s = run_grandpa(fp_buf, fp_len, &AUTH, &res);
    fp_buf[sig_off] ^= 0x01;
    check(s == GRANDPA_ERR_BAD_SIGNATURE, "a single flipped signature bit is rejected (%s)",
          grandpa_strerror(s));

    /* Negative: a valid vote re-attributed to a different authority, to check
     * that a signature is bound to the key that made it.
     *
     * The substituted id has to be one that has not voted yet, otherwise the
     * duplicate check fires first and the signature is never examined - which
     * is correct behaviour but tests nothing. Rewriting the FIRST record
     * guarantees no earlier vote can have claimed the id. */
    size_t id_off = precommit_offset(0) + 100;
    uint8_t saved_id[32];
    memcpy(saved_id, fp_buf + id_off, 32);
    const uint8_t *other = AUTH.keys;
    if (memcmp(other, saved_id, 32) == 0) other = AUTH.keys + 32;
    memcpy(fp_buf + id_off, other, 32);
    s = run_grandpa(fp_buf, fp_len, &AUTH, &res);
    memcpy(fp_buf + id_off, saved_id, 32);
    check(s == GRANDPA_ERR_BAD_SIGNATURE,
          "a vote re-attributed to another authority is rejected (%s)",
          grandpa_strerror(s));

    /* And the converse: a signer we have never heard of adds no weight. */
    memcpy(fp_buf + id_off, "\x01\x02\x03\x04\x05\x06\x07\x08"
                            "\x01\x02\x03\x04\x05\x06\x07\x08"
                            "\x01\x02\x03\x04\x05\x06\x07\x08"
                            "\x01\x02\x03\x04\x05\x06\x07\x08", 32);
    s = run_grandpa(fp_buf, fp_len, &AUTH, &res);
    memcpy(fp_buf + id_off, saved_id, 32);
    check(res.n_unknown_signer == 1 && res.n_valid == FX_PRECOMMITS - 1,
          "an unknown signer is ignored, not counted (%u unknown, %u valid)",
          res.n_unknown_signer, res.n_valid);

    /* Negative: an authority voting twice must be counted once. Duplicating a
     * whole record keeps the signature valid, so only the seen-set stops it. */
    uint8_t *dup = malloc(fp_len);
    memcpy(dup, fp_buf, fp_len);
    memcpy(dup + precommit_offset(1), dup + precommit_offset(0), 132);
    s = run_grandpa(dup, fp_len, &AUTH, &res);
    check(res.n_duplicate == 1, "a repeated authority is counted once (%u duplicate)",
          res.n_duplicate);
    free(dup);

    /* Cut inside the final signed vote. Proofs can carry unused ancestry and
     * headers after the votes, so trimming the tail need not truncate anything
     * this verifier relies on (the Paseo capture has such a suffix). */
    s = run_grandpa(fp_buf, precommit_offset(FX_PRECOMMITS) - 1, &AUTH, &res);
    check(s == GRANDPA_ERR_TRUNCATED, "a truncated justification is rejected (%s)",
          grandpa_strerror(s));

    /* Negative: claiming more precommits than there are authorities is refused
     * before any signature work, so a peer cannot make us verify forever. */
    check(run_grandpa(fp_buf, 32, &AUTH, &res) == GRANDPA_ERR_TRUNCATED,
          "an empty body is rejected");
}

/* ---------- 3b. GRANDPA through a signature pool ---------- */

/* A stand-in for the device's second core. It does the same work the real pool
 * does - copy the signature and key out of the record buffer, verify later,
 * report only a failure COUNT - but on one thread, so the equivalence it proves
 * is about the accounting rather than about the threading.
 *
 * `cap` bounds how many checks it will hold; a full pool drains rather than
 * blocking, which is what a real worker would have done by then. `refuse_every`
 * makes every Nth submit fail, exercising the caller's inline fallback
 * interleaved with deferral. */
typedef struct {
    uint8_t sig[64], pk[32];
    const uint8_t *msg;
    size_t msg_len;
} pool_job;

typedef struct {
    pool_job *jobs;
    size_t    cap, n;
    uint32_t  failed;
    uint32_t  refuse_every, seen;
    uint32_t  submitted;        /* how many checks the pool actually took */
    uint32_t  bad_tab;          /* submits that arrived with a table pointer */
} test_pool;

static uint32_t tp_drain(test_pool *p)
{
    uint32_t bad = 0;
    for (size_t i = 0; i < p->n; i++) {
        pool_job *j = &p->jobs[i];
        if (!lc_ed25519_verify(j->sig, j->msg, j->msg_len, j->pk)) bad++;
    }
    p->n = 0;
    return bad;
}

static int tp_submit(void *ctx, const uint8_t sig[64], const uint8_t *msg,
                     size_t msg_len, const uint8_t pk[32], const void *tab)
{
    test_pool *p = ctx;
    /* AUTH carries no precomputed tables and this build has no verifier that
     * could use one, so anything but NULL here means lc_ed25519_tab_at() has
     * started inventing pointers. */
    if (tab != NULL) p->bad_tab++;
    p->seen++;
    if (p->cap == 0) return 0;
    if (p->refuse_every && (p->seen % p->refuse_every) == 0) return 0;
    if (p->n == p->cap) p->failed += tp_drain(p);
    memcpy(p->jobs[p->n].sig, sig, 64);
    memcpy(p->jobs[p->n].pk, pk, 32);
    p->jobs[p->n].msg = msg;
    p->jobs[p->n].msg_len = msg_len;
    p->n++;
    p->submitted++;
    return 1;
}

static uint32_t tp_join(void *ctx)
{
    test_pool *p = ctx;
    p->failed += tp_drain(p);
    return p->failed;
}

static void tp_init(test_pool *p, size_t cap, uint32_t refuse_every)
{
    memset(p, 0, sizeof *p);
    p->cap = cap;
    p->refuse_every = refuse_every;
    p->jobs = cap ? malloc(cap * sizeof *p->jobs) : 0;
}

static grandpa_status run_grandpa_pooled(const uint8_t *buf, size_t len,
                                         const grandpa_authority_set *set,
                                         grandpa_result *res,
                                         size_t cap, uint32_t refuse_every,
                                         uint32_t *submitted)
{
    test_pool p;
    tp_init(&p, cap, refuse_every);
    grandpa_sig_pool pool = { tp_submit, tp_join, &p };

    lc_mem_reader m;
    lc_mem_reader_init(&m, buf, len);
    grandpa_status s = grandpa_verify_finality_proof_ex(&m.base, set, res, 0, 0, &pool);

    if (submitted) *submitted = p.submitted;
    if (p.bad_tab)
        check(0, "pool submit got %u precomputed-table pointers from an "
                 "authority set that has none", p.bad_tab);
    free(p.jobs);
    return s;
}

/* Every field a caller can observe must come out the same whether the checks
 * ran inline or on the pool. `weight` is compared only when the proof was
 * accepted: on a rejection the pooled run deliberately drops the deferred
 * weight rather than reporting a total that was never fully verified. */
static int same_result(grandpa_status sa, const grandpa_result *a,
                       grandpa_status sb, const grandpa_result *b,
                       const char **why)
{
#define DIFF(field, msg) do { if ((a->field) != (b->field)) { *why = msg; return 0; } } while (0)
    if (sa != sb)                  { *why = "status"; return 0; }
    DIFF(finalized,        "finalized");
    DIFF(target_number,    "target_number");
    DIFF(round,            "round");
    DIFF(n_precommits,     "n_precommits");
    DIFF(n_valid,          "n_valid");
    DIFF(n_bad_sig,        "n_bad_sig");
    DIFF(n_unknown_signer, "n_unknown_signer");
    DIFF(n_duplicate,      "n_duplicate");
    DIFF(n_other_target,   "n_other_target");
    DIFF(have_sample,      "have_sample");
    if (memcmp(a->target_hash, b->target_hash, 32) != 0) { *why = "target_hash"; return 0; }
    if (a->have_sample && memcmp(a->sample, b->sample, 132) != 0) { *why = "sample"; return 0; }
    if (sa == GRANDPA_OK) DIFF(weight, "weight");
    return 1;
#undef DIFF
}

/* The pool configurations worth distinguishing. Each one puts the verifier on a
 * different mix of deferred and inline checks. */
static const struct { const char *name; size_t cap; uint32_t refuse_every; }
POOL_MODES[] = {
    { "always refuses (pool present, nothing deferred)", 0,   0 },
    { "defers everything, one join at the end",          512, 0 },
    { "small pool, drains repeatedly mid-stream",        8,   0 },
    { "mixed: every 3rd check falls back to inline",     512, 3 },
};
#define N_POOL_MODES (sizeof POOL_MODES / sizeof *POOL_MODES)

/* Runs one scenario through every pool mode and compares against the inline
 * result. Returns 1 if all modes agreed. */
static int pool_agrees(const uint8_t *buf, size_t len,
                       const grandpa_authority_set *set, const char *what)
{
    grandpa_result ref;
    grandpa_status sref = run_grandpa(buf, len, set, &ref);

    int ok = 1;
    for (size_t m = 0; m < N_POOL_MODES; m++) {
        grandpa_result got;
        uint32_t submitted = 0;
        grandpa_status s = run_grandpa_pooled(buf, len, set, &got,
                                              POOL_MODES[m].cap,
                                              POOL_MODES[m].refuse_every,
                                              &submitted);
        const char *why = "";
        if (!same_result(sref, &ref, s, &got, &why)) {
            ok = 0;
            printf("       %s: mode \"%s\" differs on %s\n", what, POOL_MODES[m].name, why);
        }
        if (got.n_deferred != submitted) {
            ok = 0;
            printf("       %s: mode \"%s\" reports %u deferred, pool took %u\n",
                   what, POOL_MODES[m].name, got.n_deferred, submitted);
        }
    }
    return ok;
}

static void test_grandpa_pool(void)
{
    section("3b. GRANDPA with signature checks deferred to a pool");

    check(pool_agrees(fp_buf, fp_len, &AUTH, "live justification"),
          "the live justification verifies identically in all %d pool modes",
          (int)N_POOL_MODES);

    /* The one that would bite hardest if the accounting were optimistic: a
     * justification whose signatures all fail must still report zero valid,
     * because main.cpp keys the "authority set has rotated" hint off exactly
     * that. */
    grandpa_authority_set stale = AUTH;
    stale.set_id = AUTH.set_id + 1;
    check(pool_agrees(fp_buf, fp_len, &stale, "wrong set_id"),
          "a wrong set_id is rejected identically in all pool modes");

    grandpa_result res;
    uint32_t submitted = 0;
    grandpa_status s = run_grandpa_pooled(fp_buf, fp_len, &stale, &res, 512, 0, &submitted);
    check(s == GRANDPA_ERR_BAD_SIGNATURE && res.n_valid == 0 && !res.finalized,
          "fully deferred, every signature bad: %u valid, %u bad, %s",
          res.n_valid, res.n_bad_sig, grandpa_strerror(s));

    /* A single forged signature has to survive being deferred: the pool reports
     * only a count, never which one, and a count of one is enough. */
    size_t sig_off = precommit_offset(0) + 36;
    fp_buf[sig_off] ^= 0x01;
    int forged_ok = pool_agrees(fp_buf, fp_len, &AUTH, "forged signature");
    s = run_grandpa_pooled(fp_buf, fp_len, &AUTH, &res, 512, 0, 0);
    fp_buf[sig_off] ^= 0x01;
    check(forged_ok && s == GRANDPA_ERR_BAD_SIGNATURE,
          "one flipped bit is caught even when every check is deferred (%s)",
          grandpa_strerror(s));

    /* A vote re-attributed to another authority, deferred. */
    size_t id_off = precommit_offset(0) + 100;
    uint8_t saved_id[32];
    memcpy(saved_id, fp_buf + id_off, 32);
    const uint8_t *other = AUTH.keys;
    if (memcmp(other, saved_id, 32) == 0) other = AUTH.keys + 32;
    memcpy(fp_buf + id_off, other, 32);
    int reattr_ok = pool_agrees(fp_buf, fp_len, &AUTH, "re-attributed vote");
    memcpy(fp_buf + id_off, saved_id, 32);
    check(reattr_ok, "a re-attributed vote is rejected identically in all pool modes");

    /* An unknown signer never reaches the pool at all - the cheap checks stay
     * inline and in stream order, which is the whole point of the split. */
    memcpy(fp_buf + id_off, "\x01\x02\x03\x04\x05\x06\x07\x08"
                            "\x01\x02\x03\x04\x05\x06\x07\x08"
                            "\x01\x02\x03\x04\x05\x06\x07\x08"
                            "\x01\x02\x03\x04\x05\x06\x07\x08", 32);
    int unknown_ok = pool_agrees(fp_buf, fp_len, &AUTH, "unknown signer");
    s = run_grandpa_pooled(fp_buf, fp_len, &AUTH, &res, 512, 0, &submitted);
    memcpy(fp_buf + id_off, saved_id, 32);
    check(unknown_ok && res.n_unknown_signer == 1 && submitted == FX_PRECOMMITS - 1,
          "an unknown signer is dropped before the pool sees it (%u unknown, %u submitted)",
          res.n_unknown_signer, submitted);

    /* A duplicate authority, deferred: the seat is claimed when the record is
     * read, so the second vote is refused while the first is still in flight. */
    uint8_t *dup = malloc(fp_len);
    memcpy(dup, fp_buf, fp_len);
    memcpy(dup + precommit_offset(1), dup + precommit_offset(0), 132);
    int dup_ok = pool_agrees(dup, fp_len, &AUTH, "duplicate authority");
    s = run_grandpa_pooled(dup, fp_len, &AUTH, &res, 512, 0, 0);
    free(dup);
    check(dup_ok && res.n_duplicate == 1,
          "a repeated authority is refused mid-flight, not double-counted (%u duplicate)",
          res.n_duplicate);

    /* Truncation mid-stream is the path where join() matters most: the payload
     * the workers are reading lives on the verifier's stack frame, so it has to
     * be joined before that frame goes away. Under ASan a missing join here is
     * a use-after-return, not a subtle miscount. */
    check(pool_agrees(fp_buf, fp_len - 200, &AUTH, "truncated justification"),
          "a truncation mid-stream joins the pool before returning");
}

/* ---------- 4. trie: relay -> Asset Hub ---------- */
static const uint8_t *ah_header;
static size_t ah_header_len;
static uint8_t ah_hash[32], ah_state_root[32];

static void test_trie_relay(void)
{
    section("4. trie proof: relay state_root -> Paras::Heads(1000)");

    const uint8_t *nd[MAX_PROOF_NODES]; size_t sz[MAX_PROOF_NODES];
    size_t n = unpack_nodes(paras_buf, paras_len, nd, sz, MAX_PROOF_NODES);

    trie_node_ref storage[MAX_PROOF_NODES];
    trie_proof p;
    trie_proof_init(&p, storage, MAX_PROOF_NODES);
    for (size_t i = 0; i < n; i++) trie_proof_add(&p, nd[i], sz[i]);

    const uint8_t *val; size_t vlen;
    trie_result r = trie_lookup(FX_RELAY_STATE_ROOT, FX_KEY_PARAS_HEADS,
                                sizeof FX_KEY_PARAS_HEADS, &p, &val, &vlen);
    check(r == TRIE_FOUND, "Paras::Heads(1000) verified from %zu nodes (%s)",
          n, trie_strerror(r));
    if (r != TRIE_FOUND) return;

    /* HeadData is a Vec<u8>, so the header is behind a compact length prefix.
     * Decoding from byte 0 instead yields a plausible-looking wrong header. */
    scale_rd sr; scale_init(&sr, val, vlen);
    ah_header = scale_vec_bytes(&sr, &ah_header_len);
    check(ah_header != 0, "HeadData decodes as a length-prefixed Vec<u8>");
    if (!ah_header) return;

    lc_blake2b256(ah_hash, ah_header, ah_header_len);
    lc_header h;
    int ok = scale_decode_header(ah_header, ah_header_len, &h);
    memcpy(ah_state_root, h.state_root, 32);

    check(ok, "the Asset Hub header inside decodes");
    check(ok && h.number == FX_AH_NUMBER, "Asset Hub #%u (expected #%u)",
          ok ? h.number : 0, FX_AH_NUMBER);
    check(memcmp(ah_hash, FX_AH_HASH, 32) == 0, "Asset Hub block hash matches the fixture");
    check(memcmp(ah_state_root, FX_AH_STATE_ROOT, 32) == 0,
          "Asset Hub state_root matches the fixture");

    /* Negative: a state root we did not prove has no node to start from. */
    uint8_t bogus[32];
    memcpy(bogus, FX_RELAY_STATE_ROOT, 32);
    bogus[0] ^= 0xff;
    r = trie_lookup(bogus, FX_KEY_PARAS_HEADS, sizeof FX_KEY_PARAS_HEADS, &p, &val, &vlen);
    check(r == TRIE_ERR_MISSING_NODE, "a wrong state root finds no root node (%s)",
          trie_strerror(r));

    /* Negative: every node must be load-bearing. Dropping any one of them
     * should break the walk rather than being quietly tolerated. */
    size_t load_bearing = 0;
    for (size_t skip = 0; skip < n; skip++) {
        trie_proof q; trie_node_ref qs[MAX_PROOF_NODES];
        trie_proof_init(&q, qs, MAX_PROOF_NODES);
        for (size_t i = 0; i < n; i++) if (i != skip) trie_proof_add(&q, nd[i], sz[i]);
        if (trie_lookup(FX_RELAY_STATE_ROOT, FX_KEY_PARAS_HEADS,
                        sizeof FX_KEY_PARAS_HEADS, &q, &val, &vlen) != TRIE_FOUND)
            load_bearing++;
    }
    check(load_bearing == n, "all %zu proof nodes are load-bearing (%zu detected)",
          n, load_bearing);
}

/* ---------- 5. trie: Asset Hub storage ---------- */
static void test_trie_asset_hub(void)
{
    section("5. trie proof: Asset Hub state_root -> storage values");

    const uint8_t *nd[MAX_PROOF_NODES]; size_t sz[MAX_PROOF_NODES];
    size_t n = unpack_nodes(ah_buf, ah_len, nd, sz, MAX_PROOF_NODES);

    trie_node_ref storage[MAX_PROOF_NODES];
    trie_proof p;
    trie_proof_init(&p, storage, MAX_PROOF_NODES);
    for (size_t i = 0; i < n; i++) trie_proof_add(&p, nd[i], sz[i]);

    struct { const char *name; const uint8_t *key; uint64_t expect; } targets[] = {
        { "System::Number",          FX_KEY_AH_SYSTEM_NUMBER,  FX_VAL_AH_SYSTEM_NUMBER },
        { "Timestamp::Now",          FX_KEY_AH_TIMESTAMP_NOW,  FX_VAL_AH_TIMESTAMP_NOW },
        { "Balances::TotalIssuance", FX_KEY_AH_TOTAL_ISSUANCE, FX_VAL_AH_TOTAL_ISSUANCE },
    };
    const size_t NT = sizeof targets / sizeof *targets;

    for (size_t t = 0; t < NT; t++) {
        const uint8_t *val; size_t vlen;
        trie_result r = trie_lookup(ah_state_root, targets[t].key, 32, &p, &val, &vlen);
        check(r == TRIE_FOUND && le64(val, vlen) == targets[t].expect,
              "%-24s = %llu", targets[t].name,
              r == TRIE_FOUND ? (unsigned long long)le64(val, vlen) : 0ull);
    }

    /* The number proven from Asset Hub's own state must agree with the number in
     * the header we proved from the relay chain. Two independent paths. */
    {
        const uint8_t *val; size_t vlen;
        trie_lookup(ah_state_root, FX_KEY_AH_SYSTEM_NUMBER, 32, &p, &val, &vlen);
        check(le64(val, vlen) == FX_AH_NUMBER,
              "AH System::Number agrees with the header proven from the relay chain");
    }

    /* A key that is genuinely absent must be reported absent, not as an error
     * and never as an empty value. */
    {
        uint8_t missing[32];
        memcpy(missing, FX_KEY_AH_SYSTEM_NUMBER, 32);
        missing[31] ^= 0xff;
        const uint8_t *val; size_t vlen;
        trie_result r = trie_lookup(ah_state_root, missing, 32, &p, &val, &vlen);
        check(r == TRIE_ABSENT || r == TRIE_ERR_MISSING_NODE,
              "an unproven key is not reported as found (%s)", trie_strerror(r));
    }

    section("6. tamper resistance: no corruption may yield a wrong value");

    /* The property under test is not "tampering is detected" - a node that is
     * not on a given key's path is legitimately ignored - but the stronger
     * "tampering never produces a value that was not in the trie". */
    size_t silent_wrong = 0, broken = 0, trials = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t *copy = malloc(sz[i]);
        memcpy(copy, nd[i], sz[i]);
        for (size_t b = 0; b < sz[i]; b++) {
            uint8_t *mut = malloc(sz[i]);
            memcpy(mut, copy, sz[i]);
            mut[b] ^= 0x01;

            trie_proof q; trie_node_ref qs[MAX_PROOF_NODES];
            trie_proof_init(&q, qs, MAX_PROOF_NODES);
            for (size_t k = 0; k < n; k++)
                trie_proof_add(&q, k == i ? mut : nd[k], sz[k]);

            for (size_t t = 0; t < NT; t++) {
                const uint8_t *val; size_t vlen;
                trie_result r = trie_lookup(ah_state_root, targets[t].key, 32, &q, &val, &vlen);
                trials++;
                if (r == TRIE_FOUND) {
                    if (le64(val, vlen) != targets[t].expect || vlen > 16) silent_wrong++;
                } else {
                    broken++;
                }
            }
            free(mut);
        }
        free(copy);
    }
    check(silent_wrong == 0,
          "%zu single-bit tampers x %zu keys = %zu lookups, %zu wrong values returned",
          n ? trials / NT : 0, NT, trials, silent_wrong);
    printf("       %zu of %zu lookups were broken outright; the rest hit a node "
           "off that key's path\n", broken, trials);

    /* Forging a value directly: rewrite the bytes a leaf holds. The node hash
     * changes, so it stops being reachable from the state root. */
    {
        size_t victim = 0, best = 0;
        for (size_t i = 0; i < n; i++) if (sz[i] > best) { best = sz[i]; victim = i; }
        uint8_t *mut = malloc(sz[victim]);
        memcpy(mut, nd[victim], sz[victim]);
        for (size_t b = sz[victim] > 8 ? sz[victim] - 8 : 0; b < sz[victim]; b++)
            mut[b] = 0xff;

        trie_proof q; trie_node_ref qs[MAX_PROOF_NODES];
        trie_proof_init(&q, qs, MAX_PROOF_NODES);
        for (size_t k = 0; k < n; k++) trie_proof_add(&q, k == victim ? mut : nd[k], sz[k]);

        int forged_accepted = 0;
        for (size_t t = 0; t < NT; t++) {
            const uint8_t *val; size_t vlen;
            if (trie_lookup(ah_state_root, targets[t].key, 32, &q, &val, &vlen) == TRIE_FOUND
                && le64(val, vlen) == 0xffffffffffffffffull)
                forged_accepted = 1;
        }
        check(!forged_accepted, "a forged value in the largest node is not accepted");
        free(mut);
    }

    /* Malformed node headers must be refused, not guessed at. 0x08 matches none
     * of the five node kinds. */
    {
        uint8_t bad[] = { 0x08, 0x00, 0x00 };
        trie_proof q; trie_node_ref qs[2];
        trie_proof_init(&q, qs, 2);
        trie_proof_add(&q, bad, sizeof bad);
        uint8_t root[32];
        lc_blake2b256(root, bad, sizeof bad);
        const uint8_t *val; size_t vlen;
        trie_result r = trie_lookup(root, FX_KEY_AH_SYSTEM_NUMBER, 32, &q, &val, &vlen);
        check(r == TRIE_ERR_MALFORMED, "an unknown node header is refused (%s)",
              trie_strerror(r));
    }

    /* A node that claims a partial key longer than it carries must not read
     * past its own buffer. */
    {
        uint8_t truncated[] = { 0x7f, 0xff, 0x01 };   /* leaf, extended length, no key */
        trie_proof q; trie_node_ref qs[2];
        trie_proof_init(&q, qs, 2);
        trie_proof_add(&q, truncated, sizeof truncated);
        uint8_t root[32];
        lc_blake2b256(root, truncated, sizeof truncated);
        const uint8_t *val; size_t vlen;
        trie_result r = trie_lookup(root, FX_KEY_AH_SYSTEM_NUMBER, 32, &q, &val, &vlen);
        check(r == TRIE_ERR_MALFORMED, "a node claiming more key than it holds is refused (%s)",
              trie_strerror(r));
    }
}

/* ---------- 7. display formatting ----------
 *
 * Nothing here can make the device believe a false value, but it decides what a
 * human reads off the panel, and a balance with a misplaced separator is a
 * number that gets misreported. The grouping is also the one piece of string
 * handling that writes into fixed buffers on every cycle. */
static void group_is(const char *in, const char *want)
{
    char got[48];
    fmt_group(in, got, sizeof got);
    check(strcmp(got, want) == 0, "group \"%s\" -> \"%s\" (got \"%s\")", in, want, got);
}

static void compact_is(const char *in, const char *want)
{
    char got[24];
    fmt_compact(in, got, sizeof got);
    check(strcmp(got, want) == 0, "compact \"%s\" -> \"%s\" (got \"%s\")", in, want, got);
}

static void test_fmt(void)
{
    section("7. display formatting");

    /* Every position relative to a group boundary, so an off-by-one in the
     * separator test shows up rather than hiding in the middle of a group. */
    group_is("0", "0");
    group_is("999", "999");
    group_is("1000", "1,000");
    group_is("12345", "12,345");
    group_is("999999", "999,999");
    group_is("1000000", "1,000,000");
    group_is("32765746", "32,765,746");
    group_is("18446744073709551615", "18,446,744,073,709,551,615");

    /* Only the integer part is grouped; the fraction and any unit pass through
     * so that a planck balance stays exact to the last digit. */
    group_is("1712345678.1234567890", "1,712,345,678.1234567890");
    group_is("0.0000000001", "0.0000000001");
    group_is("1234 DOT", "1,234 DOT");

    /* A short buffer must truncate, not overrun - ASan is what makes this an
     * assertion about memory and not just about the string. */
    {
        char tiny[6];
        fmt_group("1234567", tiny, sizeof tiny);
        check(strlen(tiny) == sizeof tiny - 1, "grouping into a short buffer truncates (\"%s\")",
              tiny);
    }

    /* The real total issuance out of the fixture, in DOT: what the panel shows
     * is a rounded-down rendering of the figure the trie proof produced. */
    compact_is("1700162803.9351716399", "1.70B");
    compact_is("1712345678.1234567890", "1.71B");
    compact_is("999", "999");
    compact_is("1000", "1.00K");
    compact_is("32765746", "32.76M");
    compact_is("1756468800000", "1.75T");
    /* Rounding down, so the glanceable figure never overstates what was proven. */
    compact_is("1999999999", "1.99B");

    /* Several results alive at once is the whole point of the rotating buffers,
     * and it is what a single printf in main.cpp relies on. */
    {
        char joined[128];
        snprintf(joined, sizeof joined, "%s %s %s %s %s %s",
                 fmt_num(1000), fmt_num(2000000), fmt_num(3), fmt_num(40000),
                 fmt_num(500000000), fmt_num(6));
        check(strcmp(joined, "1,000 2,000,000 3 40,000 500,000,000 6") == 0,
              "six fmt_num results survive one printf (%s)", joined);
    }
}

int main(void)
{
    printf("\033[1mPolkadot light client - verification core\033[0m\n");
    printf("fixtures: relay #%u, Asset Hub #%u, set_id %llu\n",
           FX_RELAY_NUMBER, FX_AH_NUMBER, (unsigned long long)FX_SET_ID);

    load_fixtures();
    test_scale();
    test_header_binding();
    test_grandpa();
    test_grandpa_pool();
    test_trie_relay();
    test_trie_asset_hub();
    test_fmt();

    printf("\n\033[1m%d tests, %d failures\033[0m\n", tests, failures);
    if (failures == 0)
        printf("\033[32mthe core verifies real Polkadot data and rejects every forgery tried\033[0m\n");
    return failures != 0;
}
