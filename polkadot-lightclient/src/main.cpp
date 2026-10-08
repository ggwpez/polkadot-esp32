#if __has_include("wifi.local.h")
#include "wifi.local.h"
#else
#include "wifi.local.h.example"
#endif
/* Polkadot light client - M1.
 *
 * Reads Asset Hub state on an ESP32 without trusting the RPC node it talks to.
 *
 *   GRANDPA justification (401+ ed25519 signatures)
 *     -> a relay block hash that a supermajority of authorities signed
 *   blake2b(re-encoded relay header) == that hash
 *     -> a relay state root we can trust
 *   trie proof of Paras::Heads(1000) against that root
 *     -> the Asset Hub header, and so the Asset Hub state root
 *   trie proof against the Asset Hub root
 *     -> the value
 *
 * The node is asked for all of this and believed for none of it. Every step
 * fails closed: on any bad signature, short weight, hash mismatch or broken
 * proof the device prints why and shows no value at all. */

#include <Arduino.h>
#include <WiFi.h>

#include "checkpoint.h"
#include "checkpoint_precomp.h"
#include "fmt.h"
#include "grandpa.h"
#include "lc_crypto.h"
#include "prefetch.h"
#include "sigpool.h"
#include "scale.h"
#include "transport.h"
#include "trie.h"
#include "ui.h"
#include "network.h"
#include "door.h"



/* The Arduino loop task gets 8 KB by default, and an mbedTLS handshake alone
 * wants most of that. Verification runs on this task too, so the default leaves
 * no margin - it overflowed the canary once the finality result grew. 16 KB is
 * cheap against 200 KB of free heap and the high-water mark is printed each
 * cycle so the real margin stays visible instead of being guessed at. */
SET_LOOP_TASK_STACK_SIZE(16384);

/* The device follows the chain rather than sampling it: the relay leg is a
 * WebSocket subscribed to chain_subscribeFinalizedHeads, and a cycle starts
 * when the node says a new block was finalized. There is no polling interval
 * any more.
 *
 * MIN_CYCLE_GAP_MS is a politeness knob, not a mechanism. At 0 the device
 * refreshes on every burst of heads, which is what a 5.3 s cycle against a 6 s
 * block makes possible; raise it if one public endpoint should not be asked for
 * a justification this often. PLAN 13 raises that as a power, thermal and
 * RPC-load question and it is still one. */
#ifndef MIN_CYCLE_GAP_MS
#define MIN_CYCLE_GAP_MS 0
#endif

/* How long the result stays on the panel before the next cycle may start.
 *
 * The result is the point of a cycle, and without this it is the shortest thing
 * on screen: a 5 s cycle against a 6 s block leaves the proven values up for
 * about a second before the next head wipes them, after four seconds of
 * watching a progress bar. Two seconds is a floor, not a period - a cycle that
 * happens to finish with three seconds to spare waits for none of it.
 *
 * It is not free. Five seconds of cycle plus two of dwell is longer than a 6 s
 * block, so the device gives up a block now and then. That is already handled
 * and already visible: heads that arrive during the hold queue on the socket,
 * the pumpHeads(0) at the top of the next cycle folds them into one, and the
 * cycle starts from the newest - never from a backlog. It says so when it
 * happens. Set to 0 to follow every block instead.
 *
 * Separate from MIN_CYCLE_GAP_MS on purpose: that one is about how often a
 * public endpoint should be asked for a justification, this one is about
 * whether a person can read the answer. One wait serves both, but they are not
 * the same question and should not be tuned through the same number. */
#ifndef RESULT_DWELL_MS
#define RESULT_DWELL_MS 2000
#endif

/* Heads arrive in bursts every 8-12 s, so silence this long means the
 * subscription is gone even though the socket looks open. Dropping it and
 * re-subscribing is cheap; waiting forever for a push that will never come is
 * the failure that looks exactly like a hung network. */
#ifndef HEAD_SILENCE_MS
#define HEAD_SILENCE_MS 60000
#endif

/* Static rather than heap: the sizes are known, and a device that runs for days
 * should not depend on the allocator still being able to find a large block.
 *
 * The header buffer is large because the block that schedules an authority set
 * change carries the whole next set - 600 keys, about 24 KB - in its digest. It
 * is one block in several thousand, but sizing for it means the device does not
 * fail once per session boundary. */
static uint8_t hdr_buf[32768];
static uint8_t paras_proof_buf[8192];
static uint8_t ah_proof_buf[8192];
static trie_node_ref proof_nodes[64];

/* The precomputed tables are a cache of the keys right above them, so a stale
 * one is a set of tables for authorities that no longer exist. That fails
 * closed - every signature would simply fail to verify - but it fails closed in
 * the field, looking exactly like the authority set having rotated, which is
 * the one failure mode this project has already spent a debugging session on.
 * set_id pins the two together at build time instead. */
#if defined(CHECKPOINT_HAVE_PRECOMP)
#if CHECKPOINT_PRECOMP_SET_ID != CHECKPOINT_SET_ID || \
    CHECKPOINT_PRECOMP_COUNT != CHECKPOINT_AUTHORITIES
#error "src/checkpoint_precomp.c is stale. Regenerate it: \
python3 tools/gen_checkpoint.py --precomp-only"
#endif
#endif

static const grandpa_authority_set AUTHORITIES = {
    CHECKPOINT_AUTHORITY_KEYS,
    CHECKPOINT_AUTHORITY_WEIGHTS,
    CHECKPOINT_AUTHORITIES,
    CHECKPOINT_TOTAL_WEIGHT,
    CHECKPOINT_THRESHOLD,
    CHECKPOINT_SET_ID,
#ifdef CHECKPOINT_HAVE_PRECOMP
    CHECKPOINT_AUTHORITY_PRECOMP,
#else
    NULL,
#endif
};

/* ---------- small helpers ---------- */

static void to_hex0x(const uint8_t *b, size_t n, char *out)
{
    static const char *H = "0123456789abcdef";
    out[0] = '0'; out[1] = 'x';
    for (size_t i = 0; i < n; i++) {
        out[2 + i * 2]     = H[b[i] >> 4];
        out[2 + i * 2 + 1] = H[b[i] & 0xf];
    }
    out[2 + n * 2] = 0;
}

/* Decimal string for a 128-bit little-endian value. Storage items are u128 far
 * more often than u64, and printing a truncated balance would be worse than
 * printing none. Long division over 32-bit limbs; xtensa has no __int128. */
static void format_u128(const uint8_t *v, size_t len, char *out, size_t cap)
{
    uint32_t limb[4] = { 0, 0, 0, 0 };
    if (len > 16) { snprintf(out, cap, "<%u bytes>", (unsigned)len); return; }
    for (size_t i = 0; i < len; i++) limb[i / 4] |= (uint32_t)v[i] << (8 * (i % 4));

    char rev[40];
    size_t n = 0;
    for (;;) {
        uint32_t rem = 0;
        int nonzero = 0;
        for (int i = 3; i >= 0; i--) {
            uint64_t cur = (uint64_t)rem << 32 | limb[i];
            limb[i] = (uint32_t)(cur / 10);
            rem = (uint32_t)(cur % 10);
            if (limb[i]) nonzero = 1;
        }
        rev[n++] = (char)('0' + rem);
        if (!nonzero) break;
    }
    if (n >= cap) { snprintf(out, cap, "<overflow>"); return; }
    for (size_t i = 0; i < n; i++) out[i] = rev[n - 1 - i];
    out[n] = 0;
}

/* Inserts a decimal point `dp` digits from the right, for planck -> DOT. */
static void format_fixed_point(const char *digits, int dp, char *out, size_t cap)
{
    int n = (int)strlen(digits);
    if (n <= dp) {
        snprintf(out, cap, "0.%0*d%s", dp - n, 0, digits);
    } else {
        snprintf(out, cap, "%.*s.%s", n - dp, digits, digits + n - dp);
    }
}

/* The cycle-wide progress bar, cut into one slice per step. These are measured
 * shares of a cycle, not equal steps - from a -DLC_NET_STATS capture on
 * 2026-08-31, where a 5,033 ms cycle spent 264 ms asking for the justification,
 * 4,082 ms streaming and verifying it, 196 ms binding the header, 203 ms on the
 * Paras::Heads proof, 28 ms reaching Asset Hub and 249 ms proving and reading
 * the values. PLAN.md 12 keeps the full table.
 *
 * Each boundary is named once and used twice - as one step's end and the next
 * one's start - so the slices cannot silently drift apart or overlap. Only
 * P_VERIFY..P_HEADER is filled gradually; every other step is one jump,
 * because none of them can count themselves.
 *
 * The self-test runs on the first cycle only and costs about 220 ms, which is
 * why it gets the last percent rather than a slice of its own. On every later
 * cycle the bar reaches P_SELFTEST and the proven view replaces it a frame
 * later, so the last percent is never seen standing still. */
enum {
    P_JUSTIF   = 0,
    P_VERIFY   = 5,
    P_HEADER   = 86,
    P_PARAS    = 90,
    P_AH       = 94,
    P_AHPROOF  = 95,
    P_SELFTEST = 99,
    P_DONE     = 100,
};

static void progress_dot(uint32_t done, uint32_t total, void *)
{
    Serial.print(".");        /* one dot per 32 signatures verified */
    char detail[24];
    snprintf(detail, sizeof detail, "%u of %u checked", (unsigned)done, (unsigned)total);
    ui_progress(done, total, detail);
    /* The verify loop used to block on the socket often enough to let IDLE1
     * run. It no longer does, so the yield has to be deliberate - the same
     * reason sigpool_task has one. This is the only point in the verification
     * that knows it is on FreeRTOS, which is why it is here and not in
     * grandpa.c. */
    delay(1);
}

/* ---------- one full trustless read ---------- */

struct Anchor {
    uint8_t relay_hash[32];
    uint32_t relay_number;
    uint8_t relay_state_root[32];
    uint8_t ah_hash[32];
    uint32_t ah_number;
    uint8_t ah_state_root[32];
    grandpa_result finality;
};

static void self_test_grandpa(const grandpa_result &g);
static void self_test_trie(const Anchor &a, const trie_proof &proof,
                           const uint8_t *expect_val, size_t expect_len);
extern int st_pass, st_fail;

/* Phase stopwatch. Built only with -DLC_NET_STATS: knowing that a refresh takes
 * sixteen seconds says nothing about which second to go after. */
#ifdef LC_NET_STATS
static uint32_t phase_t0;
static void phase(const char *what)
{
    uint32_t now = millis();
    if (what) Serial.printf("    [%6s ms] %s\n", fmt_num(now - phase_t0), what);
    phase_t0 = now;
}
#define PHASE(x) phase(x)
#else
#define PHASE(x) ((void)0)
#endif

/* `hint` is the block number the subscription pushed. It replaces the
 * chain_getFinalizedHead + chain_getHeader pair this used to open with - the
 * notification carries the header, so the number is simply in it - and it is
 * exactly as untrusted as that pair was: a hint about which block to ask for a
 * justification for. The justification is what decides whether it is final. */
static bool establish_anchor(RpcSession &s, Anchor *a, uint32_t hint)
{
    Serial.printf("  node finalized #%s\n", fmt_num(hint));

    /* --- 1. finality --- */
    char params[24];
    snprintf(params, sizeof params, "[%u]", hint);
    ui_stage("getting justification", P_JUSTIF, P_VERIFY);
#ifdef LC_NET_STATS
    lc_net_reset();
#endif
    if (s.call("grandpa_proveFinality", params) != LC_T_OK) {
        ui_failed("the node would not answer grandpa_proveFinality");
        return false;
    }
    if (rpc_seek_result_hex(s) != LC_T_OK) {
        Serial.println("  ! node returned no finality proof");
        ui_failed("the node returned no finality proof");
        return false;
    }

    /* Both cores, if they are available. The loop task and its prefetcher sit on
     * core 1; the signature worker goes on core 0, which otherwise only services
     * the radio. Either piece failing to start is not an error - it just means
     * this refresh verifies the slow way. See PLAN section 11 for the numbers. */
    PHASE("proveFinality, up to the first proof byte");

    RpcHexReader hr;
    rpc_hex_reader_init(&hr, &s);
    lc_reader *src = &hr.base;

    RpcPrefetch *pf = prefetch_start(&s, ARDUINO_RUNNING_CORE);
    if (pf) src = prefetch_reader(pf);
    sigpool *sp = sigpool_start(ARDUINO_RUNNING_CORE == 0 ? 1 : 0);

    grandpa_result g;
    /* The stage changes here, not just the bar. Streaming and verifying are
     * interleaved from this point - the prefetch task drains the socket while
     * the cores check signatures - and the signature checks are four fifths of
     * a cycle, so "getting justification" would be the label the panel wore for
     * almost all of it. That four fifths is also this step's slice of the bar,
     * and the only one the device can fill gradually: progress_dot() below
     * moves the bar inside it, and deliberately does not touch the stage. */
    ui_stage("verifying signatures", P_VERIFY, P_HEADER);
    Serial.print("  verifying justification ");
    uint32_t t0 = millis();
    grandpa_status gs = grandpa_verify_finality_proof_ex(src, &AUTHORITIES, &g,
                                                         progress_dot, 0,
                                                         sigpool_iface(sp));
    uint32_t verify_ms = millis() - t0;
    uint32_t worker_sigs = sigpool_worker_sigs(sp);
    Serial.println();

    sigpool_stop(sp);
    prefetch_stop(pf);
    PHASE("stream + verify the justification");

    if (!pf || !sp)
        Serial.printf("    (single-core fallback: %s%s%s)\n",
                      pf ? "" : "no prefetch buffer",
                      (!pf && !sp) ? ", " : "", sp ? "" : "no signature worker");

    if (gs != GRANDPA_OK) {
        Serial.printf("  ! FINALITY NOT PROVEN: %s\n", grandpa_strerror(gs));
        Serial.printf("    %s precommits, %s valid, weight %s of %s (need %s)\n",
                      fmt_num(g.n_precommits), fmt_num(g.n_valid), fmt_num(g.weight),
                      fmt_num(AUTHORITIES.total_weight),
                      fmt_num(AUTHORITIES.threshold));
        if (g.n_valid == 0 && g.n_precommits > 0)
            Serial.println("    zero valid signatures usually means the authority set has "
                           "rotated - regenerate checkpoint.h");
        /* The authority set going stale is the one failure a passer-by can act
         * on, and it looks like every other signature failure unless it is
         * called out by name. */
        if (g.n_valid == 0 && g.n_precommits > 0)
            ui_failed("no signature matched. the authority set has probably "
                      "rotated: regenerate checkpoint.h");
        else
            ui_failed(grandpa_strerror(gs));
        return false;       /* the caller closes the session; see loop() */
    }

    /* Only now, and only on success. A verifier that ran to the end consumes
     * the response exactly - measured, there is never a byte left behind it -
     * so this costs a millisecond and keeps the connection, where reconnecting
     * here used to cost a 2.2 s TLS handshake, more than every signature check
     * in the justification put together. After a failure the rest of the body
     * is still out there and draining it could take seconds, which is why that
     * path closes the socket instead. */
    s.skipBody();
    Serial.printf("  finality: #%s, %s/%s signatures, weight %s/%s in %s ms\n",
                  fmt_num(g.target_number), fmt_num(g.n_valid), fmt_num(g.n_precommits),
                  fmt_num(g.weight), fmt_num(AUTHORITIES.total_weight),
                  fmt_num(verify_ms));
    if (g.n_deferred)
        Serial.printf("    (%s checked on the second core, %s inline while it was busy)\n",
                      fmt_num(worker_sigs), fmt_num(g.n_valid - worker_sigs));
    if (g.n_other_target)
        Serial.printf("    (%s precommits voted for a descendant and were not counted)\n",
                      fmt_num(g.n_other_target));
#ifdef LC_NET_STATS
    Serial.printf("    net: %s ms to first byte, %s bytes in %s reads (largest %s), "
                  "%s ms streaming of which %s ms idle (%s B/s)\n",
                  fmt_num(lc_net.ttfb_ms), fmt_num(lc_net.bytes), fmt_num(lc_net.fills),
                  fmt_num(lc_net.max_read), fmt_num(lc_net.wait_ms), fmt_num(lc_net.stalls),
                  fmt_num(lc_net.wait_ms ? (uint64_t)lc_net.bytes * 1000 / lc_net.wait_ms : 0));
    lc_net_reset();
#endif

    memcpy(a->relay_hash, g.target_hash, 32);
    a->relay_number = g.target_number;
    a->finality = g;

    /* --- 2. bind the header to the hash the authorities signed --- */
    char hash_hex[70];
    to_hex0x(a->relay_hash, 32, hash_hex);
    ui_stage("binding the header", P_HEADER, P_PARAS);
    /* Normally already open - the justification was drained, not abandoned.
     * This used to reopen in place; on a WebSocket it must not. A fresh socket
     * carries no subscription, so healing it here would leave the device
     * connected and permanently deaf to the heads that start every cycle.
     * Failing sends it back to loop(), which opens and subscribes together. */
    if (!s.isOpen()) {
        ui_failed("lost the relay connection");
        return false;
    }
    PHASE("relay connection reused");

    size_t hlen;
    lc_transport_status ts = transport_fetch_header(s, hash_hex, hdr_buf, sizeof hdr_buf, &hlen);
    PHASE("fetch the finalized header");
    if (ts != LC_T_OK) {
        Serial.printf("  ! header fetch failed: %s\n", lc_transport_strerror(ts));
        ui_failed("header fetch failed");
        return false;
    }
    uint8_t computed[32];
    lc_blake2b256(computed, hdr_buf, hlen);
    if (memcmp(computed, a->relay_hash, 32) != 0) {
        Serial.println("  ! HEADER BINDING FAILED - the node's header is not the block "
                       "the authorities signed");
        ui_failed("header binding failed: this is not the block the "
                  "authorities signed");
        return false;
    }
    lc_header rh;
    if (!scale_decode_header(hdr_buf, hlen, &rh)) {
        Serial.println("  ! relay header did not decode");
        ui_failed("the relay header did not decode");
        return false;
    }
    memcpy(a->relay_state_root, rh.state_root, 32);
    Serial.printf("  header bound: %s bytes hash to the finalized block\n", fmt_num(hlen));

    /* --- 3. relay state -> Asset Hub header --- */
    char paras_key_hex[100];
    to_hex0x(STORAGE_KEY_PARAS_HEADS, sizeof STORAGE_KEY_PARAS_HEADS, paras_key_hex);
    const char *keys[1] = { paras_key_hex };

    ui_stage("proving Paras::Heads", P_PARAS, P_AH);
    trie_proof proof;
    trie_proof_init(&proof, proof_nodes, sizeof proof_nodes / sizeof *proof_nodes);
    ts = transport_fetch_read_proof(s, keys, 1, hash_hex,
                                    paras_proof_buf, sizeof paras_proof_buf, &proof);
    if (ts != LC_T_OK) {
        Serial.printf("  ! Paras::Heads proof fetch failed: %s\n", lc_transport_strerror(ts));
        ui_failed("could not fetch the Paras::Heads proof");
        return false;
    }

    PHASE("fetch the Paras::Heads proof");

    const uint8_t *head_data; size_t head_len;
    trie_result tr = trie_lookup(a->relay_state_root, STORAGE_KEY_PARAS_HEADS,
                                 sizeof STORAGE_KEY_PARAS_HEADS, &proof, &head_data, &head_len);
    if (tr != TRIE_FOUND) {
        Serial.printf("  ! Paras::Heads(1000) not proven: %s\n", trie_strerror(tr));
        ui_failed("Paras::Heads(1000) not proven from the relay state root");
        return false;
    }

    /* HeadData is a Vec<u8>: the header sits behind a compact length prefix.
     * Decoding from byte zero yields a header-shaped value that is wrong. */
    scale_rd sr;
    scale_init(&sr, head_data, head_len);
    size_t ah_len;
    const uint8_t *ah_header = scale_vec_bytes(&sr, &ah_len);
    lc_header ah;
    if (!ah_header || !scale_decode_header(ah_header, ah_len, &ah)) {
        Serial.println("  ! Asset Hub header did not decode");
        ui_failed("the Asset Hub header did not decode");
        return false;
    }
    lc_blake2b256(a->ah_hash, ah_header, ah_len);
    memcpy(a->ah_state_root, ah.state_root, 32);
    a->ah_number = ah.number;
    PHASE("walk it");
    Serial.printf("  Paras::Heads(1000) proven from %s nodes -> Asset Hub #%s\n",
                  fmt_num(proof.count), fmt_num(ah.number));
    return true;
}

static bool read_asset_hub(RpcSession &s, const Anchor &a, bool self_test)
{
    ui_stage("reaching Asset Hub", P_AH, P_AHPROOF);
    if (!s.isOpen() && s.open(ASSET_HUB_ENDPOINT) != LC_T_OK) {
        Serial.println("  ! could not reach Asset Hub");
        ui_failed("could not reach the Asset Hub RPC");
        return false;
    }

    PHASE("Asset Hub TLS handshake");

    struct Target { const char *name; const uint8_t *key; size_t key_len; int decimals; };
    const Target targets[] = {
        { "System::Number",          STORAGE_KEY_AH_SYSTEM_NUMBER,
          sizeof STORAGE_KEY_AH_SYSTEM_NUMBER,  0 },
        { "Timestamp::Now",          STORAGE_KEY_AH_TIMESTAMP_NOW,
          sizeof STORAGE_KEY_AH_TIMESTAMP_NOW,  0 },
        { "Balances::TotalIssuance", STORAGE_KEY_AH_TOTAL_ISSUANCE,
          sizeof STORAGE_KEY_AH_TOTAL_ISSUANCE, LC_TOKEN_DECIMALS },
    };
    const size_t NT = sizeof targets / sizeof *targets;

    char key_hex[NT][100];
    const char *keys[NT];
    for (size_t i = 0; i < NT; i++) {
        to_hex0x(targets[i].key, targets[i].key_len, key_hex[i]);
        keys[i] = key_hex[i];
    }
    char at_hex[70];
    to_hex0x(a.ah_hash, 32, at_hex);

    ui_stage("proving Asset Hub", P_AHPROOF, P_SELFTEST);
    trie_proof proof;
    trie_proof_init(&proof, proof_nodes, sizeof proof_nodes / sizeof *proof_nodes);
    lc_transport_status ts = transport_fetch_read_proof(s, keys, NT, at_hex,
                                                        ah_proof_buf, sizeof ah_proof_buf,
                                                        &proof);
    if (ts != LC_T_OK) {
        Serial.printf("  ! Asset Hub proof fetch failed: %s\n", lc_transport_strerror(ts));
        ui_failed("could not fetch the Asset Hub storage proof");
        return false;
    }

    PHASE("fetch the Asset Hub storage proof");
    Serial.printf("\n  proven against Asset Hub #%s (state root from relay #%s)\n",
                  fmt_num(a.ah_number), fmt_num(a.relay_number));
    char headline[32] = "";     /* the one value the screen has room for */
    for (size_t i = 0; i < NT; i++) {
        const uint8_t *v; size_t vlen;
        trie_result r = trie_lookup(a.ah_state_root, targets[i].key, targets[i].key_len,
                                    &proof, &v, &vlen);
        if (r != TRIE_FOUND) {
            Serial.printf("    %-24s  %s\n", targets[i].name, trie_strerror(r));
            continue;
        }
        char dec[48], grouped[72], shown[80];
        format_u128(v, vlen, dec, sizeof dec);
        if (targets[i].decimals) {
            char fp[64];
            format_fixed_point(dec, targets[i].decimals, fp, sizeof fp);
            /* The panel has 21 columns and the full figure needs 29, so what
             * it shows is rounded down to three significant figures. Serial
             * leads with the same short form and then gives every digit that
             * was actually proven, because that is the number this device
             * exists to be able to state exactly. */
            char brief[24];
            fmt_compact(fp, brief, sizeof brief);
            fmt_group(fp, grouped, sizeof grouped);
            snprintf(shown, sizeof shown, "%s " LC_TOKEN_SYMBOL "  (%s)", brief, grouped);
        } else {
            fmt_group(dec, shown, sizeof shown);
            if (i == 0)
                snprintf(headline, sizeof headline, "block %s", shown);
        }
        Serial.printf("    %-24s= %s\n", targets[i].name, shown);
    }

    /* Two independent paths to the same number: one proven from the relay
     * chain's state, one from Asset Hub's own. Disagreement would mean the
     * proofs were assembled from different blocks. */
    const uint8_t *v; size_t vlen;
    if (trie_lookup(a.ah_state_root, STORAGE_KEY_AH_SYSTEM_NUMBER,
                    sizeof STORAGE_KEY_AH_SYSTEM_NUMBER, &proof, &v, &vlen) == TRIE_FOUND) {
        uint32_t n = 0;
        for (size_t i = 0; i < vlen && i < 4; i++) n |= (uint32_t)v[i] << (8 * i);
        Serial.printf("    consistency: AH block number matches the relay-proven header: %s\n",
                      n == a.ah_number ? "yes" : "NO");

        if (self_test) {
            Serial.println("\n  self-test: nothing on the wire may be altered unnoticed");
            st_pass = st_fail = 0;
            ui_stage("on-device self-test", P_SELFTEST, P_DONE);
            self_test_grandpa(a.finality);
            self_test_trie(a, proof, v, vlen);
            Serial.printf("  self-test: %d passed, %d failed%s\n", st_pass, st_fail,
                          st_fail ? "  <-- VERIFICATION IS NOT SOUND ON THIS BUILD" : "");
        }

        /* Last, so that nothing reaches the screen until the signatures, the
         * header hash, both Merkle proofs and the self-test have all held, and
         * the two independent paths to the Asset Hub block number agree. */
        /* st_fail is deliberately sticky across cycles: a board that once
         * failed its own soundness check should never show a value again. */
        if (st_fail)
            ui_failed("on-device self-test FAILED: this build is not sound");
        else if (n != a.ah_number)
            ui_failed("the two paths to the Asset Hub block number disagree");
        else
            ui_proven(a.relay_number, a.ah_number, headline,
                      a.finality.n_valid, (uint32_t)CHECKPOINT_AUTHORITIES,
                      CHECKPOINT_SET_ID);
        if (st_fail || n != a.ah_number) return false;
        if (trie_lookup(a.ah_state_root, STORAGE_KEY_AH_TIMESTAMP_NOW,
                        sizeof STORAGE_KEY_AH_TIMESTAMP_NOW, &proof, &v, &vlen) != TRIE_FOUND || vlen != 8)
            return false;
        uint64_t stamp = 0;
        for (size_t i=0; i<8; i++) stamp |= (uint64_t)v[i] << (8*i);
        return door_read(s, a.ah_state_root, a.ah_hash, a.ah_number, stamp, a.relay_number);
    }
    /* Without System::Number there is nothing to cross-check the relay-proven
     * header against, so the read does not count as proven. */
    ui_failed("System::Number was not in the Asset Hub proof");
    return false;
}

/* ---------- on-device negative tests ----------
 *
 * The host suite already proves this code rejects forgeries, but it proves it
 * on a different CPU with a different libsodium. These run on the board, on
 * data that just came off the wire, and answer the only question that matters:
 * can anything the device was handed be altered without it noticing. */

int st_pass, st_fail;
static void expect(int cond, const char *what)
{
    if (cond) st_pass++; else st_fail++;
    Serial.printf("    %s %s\n", cond ? "ok  " : "FAIL", what);
}

/* Every field of the signed payload must be load-bearing: change any one of
 * them and a signature that was valid must stop verifying. If set_id were not
 * covered, a justification from a rotated authority set would be accepted. */
static void self_test_grandpa(const grandpa_result &g)
{
    if (!g.have_sample) { Serial.println("    (no sample precommit retained)"); return; }

    const uint8_t *sig = g.sample + 36;
    const uint8_t *id  = g.sample + 100;
    uint8_t payload[GRANDPA_PAYLOAD_LEN];

    grandpa_localized_payload(payload, g.target_hash, g.target_number, g.round,
                              CHECKPOINT_SET_ID);
    expect(lc_ed25519_verify(sig, payload, sizeof payload, id),
           "a retained precommit verifies against the real payload");

    grandpa_localized_payload(payload, g.target_hash, g.target_number, g.round,
                              CHECKPOINT_SET_ID + 1);
    expect(!lc_ed25519_verify(sig, payload, sizeof payload, id),
           "the same signature fails under a different set_id");

    grandpa_localized_payload(payload, g.target_hash, g.target_number, g.round + 1,
                              CHECKPOINT_SET_ID);
    expect(!lc_ed25519_verify(sig, payload, sizeof payload, id),
           "the same signature fails under a different round");

    grandpa_localized_payload(payload, g.target_hash, g.target_number + 1, g.round,
                              CHECKPOINT_SET_ID);
    expect(!lc_ed25519_verify(sig, payload, sizeof payload, id),
           "the same signature fails for a different block number");

    uint8_t flipped[32];
    memcpy(flipped, g.target_hash, 32);
    flipped[0] ^= 0x01;
    grandpa_localized_payload(payload, flipped, g.target_number, g.round, CHECKPOINT_SET_ID);
    expect(!lc_ed25519_verify(sig, payload, sizeof payload, id),
           "the same signature fails for a one-bit-different block hash");

#ifdef CHECKPOINT_HAVE_PRECOMP
    /* The precomputed tables, on the board, against a signature that just came
     * off the wire.
     *
     * test/run_pre.sh checks the generated tables against ref10's own
     * arithmetic and the resulting verdicts against libsodium, but it checks
     * the tables in the repository. What only the device can answer is whether
     * the bytes in THIS image are those tables - a truncated array, a stale
     * regeneration the set_id guard happened not to catch, or a partial flash
     * all look like correct source. The wrong-table case is the one that makes
     * this a test rather than a repetition: without it a table of zeros would
     * pass, because a signature the fast path already verified is verified
     * again by the fast path when no table is found. */
    {
        size_t lo = 0, hi = CHECKPOINT_AUTHORITIES;
        const void *tab = NULL, *other = NULL;
        size_t idx = 0;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            int c = memcmp(CHECKPOINT_AUTHORITY_KEYS + mid * 32, id, 32);
            if (c == 0) { idx = mid; tab = lc_ed25519_tab_at(CHECKPOINT_AUTHORITY_PRECOMP, mid); break; }
            if (c < 0) lo = mid + 1; else hi = mid;
        }
        other = lc_ed25519_tab_at(CHECKPOINT_AUTHORITY_PRECOMP,
                                  idx ? idx - 1 : CHECKPOINT_AUTHORITIES - 1);

        grandpa_localized_payload(payload, g.target_hash, g.target_number, g.round,
                                  CHECKPOINT_SET_ID);
        expect(tab != NULL, "the retained precommit's signer has a precomputed table");
        expect(tab && lc_ed25519_verify_tab(sig, payload, sizeof payload, id, tab),
               "it verifies through the precomputed table");
        expect(!lc_ed25519_verify_tab(sig, payload, sizeof payload, id, other),
               "it fails through another authority's table");
    }
#endif
}

/* Uses the proof that was just fetched and verified, so the "correct" answer is
 * known and any deviation is a real failure rather than a fixture mismatch. */
static void self_test_trie(const Anchor &a, const trie_proof &proof,
                           const uint8_t *expect_val, size_t expect_len)
{
    const uint8_t *v; size_t vlen;

    uint8_t bogus_root[32];
    memcpy(bogus_root, a.ah_state_root, 32);
    bogus_root[0] ^= 0xff;
    expect(trie_lookup(bogus_root, STORAGE_KEY_AH_SYSTEM_NUMBER,
                       sizeof STORAGE_KEY_AH_SYSTEM_NUMBER, &proof, &v, &vlen)
           == TRIE_ERR_MISSING_NODE,
           "a state root we did not prove has no reachable root node");

    uint8_t missing[32];
    memcpy(missing, STORAGE_KEY_AH_SYSTEM_NUMBER, 32);
    missing[31] ^= 0xff;
    trie_result r = trie_lookup(a.ah_state_root, missing, 32, &proof, &v, &vlen);
    expect(r != TRIE_FOUND, "a key the proof does not cover is not reported as found");

    /* Flip one bit in each proof node in turn. A node off this key's path is
     * legitimately ignored, so the property tested is the strong one: no
     * tampering may ever yield a value other than the real one. */
    size_t wrong = 0, broke = 0;
    for (size_t i = 0; i < proof.count; i++) {
        uint8_t *mutable_node = (uint8_t *)proof.nodes[i].data;
        uint8_t saved = mutable_node[proof.nodes[i].len / 2];
        mutable_node[proof.nodes[i].len / 2] ^= 0x01;

        trie_proof q;
        trie_node_ref qs[64];
        trie_proof_init(&q, qs, 64);
        for (size_t k = 0; k < proof.count; k++)
            trie_proof_add(&q, proof.nodes[k].data, proof.nodes[k].len);

        trie_result rr = trie_lookup(a.ah_state_root, STORAGE_KEY_AH_SYSTEM_NUMBER,
                                     sizeof STORAGE_KEY_AH_SYSTEM_NUMBER, &q, &v, &vlen);
        if (rr == TRIE_FOUND) {
            if (vlen != expect_len || memcmp(v, expect_val, vlen) != 0) wrong++;
        } else {
            broke++;
        }
        mutable_node[proof.nodes[i].len / 2] = saved;
    }
    Serial.printf("    ---- %u tampered nodes: %u broke the proof, %u off-path\n",
                  (unsigned)proof.count, (unsigned)broke,
                  (unsigned)(proof.count - broke));
    expect(wrong == 0, "no single-bit tamper produced a different value");
}

/* ---------- setup / loop ---------- */

static void banner(void)
{
    Serial.printf("\n\nPolkadot light client - M1 - " LC_NETWORK_NAME "\n");
    /* set_id is an identifier rather than a quantity, so it stays ungrouped -
     * it has to read the same as it does on a chain explorer. */
    Serial.printf("trust root: %s authorities, set_id %llu, threshold %s of %s\n",
                  fmt_num(CHECKPOINT_AUTHORITIES), (unsigned long long)CHECKPOINT_SET_ID,
                  fmt_num(CHECKPOINT_THRESHOLD), fmt_num(CHECKPOINT_TOTAL_WEIGHT));
    Serial.printf("checkpoint captured at relay #%s\n", fmt_num(CHECKPOINT_BLOCK));
    Serial.printf("heap: %s free, largest block %s\n",
                  fmt_num(ESP.getFreeHeap()), fmt_num(ESP.getMaxAllocHeap()));
}

/* This AP often refuses the first association with "comeback time too long"
 * and accepts the next one, so a single attempt is not a useful verdict.
 * Each attempt is a fresh begin(): after a refusal there is no association to
 * reconnect to. */
#define WIFI_ATTEMPTS 5

static bool wifi_connect(int attempts)
{
    for (int a = 1; a <= attempts; a++) {
        /* The name is not logged either: serial captures from this device end
         * up pasted into issues and READMEs, and there is only one network to
         * join, so printing which one adds nothing but the owner's SSID. */
        Serial.printf("wifi: joining the network (attempt %d/%d) ", a, attempts);
        ui_joining(a, attempts);
        WiFi.disconnect(true);
        delay(300);
        WiFi.mode(WIFI_STA);
        WiFi.begin(WIFI_SSID, WIFI_PASS);
        /* Polled at 100 ms rather than 400: the same 12-second window, but the
         * association is noticed up to 300 ms sooner. A dot every fourth pass
         * keeps the log reading the way it always has. */
        for (int i = 0; i < 120 && WiFi.status() != WL_CONNECTED; i++) {
            if (i % 4 == 0) Serial.print(".");
            delay(100);
        }
        if (WiFi.status() == WL_CONNECTED) {
            /* No modem sleep. The default parks the radio between DTIM beacons,
             * which costs nothing when a device wakes up to send one request -
             * and everything here, because it adds most of a beacon interval to
             * every inbound packet. Measured against the same endpoint: 20 ms
             * round trip from a wired host, ~300 ms from this board. lwip
             * advertises a 5,760-byte window, so that round trip is the divisor
             * on throughput, and a 106 KB justification was arriving at 17 KB/s.
             * The cost is a radio that stays powered - the right trade for a
             * mains-powered panel that wants to track a 6-second chain. */
#ifndef LC_WIFI_MODEM_SLEEP          /* -D restores the default, to re-measure */
            WiFi.setSleep(false);
#endif
            Serial.printf(" %s (%d dBm), heap %s\n", WiFi.localIP().toString().c_str(),
                          WiFi.RSSI(), fmt_num(ESP.getFreeHeap()));
            ui_net(true, WiFi.RSSI());
            return true;
        }
        Serial.println(" refused, retrying");
    }
    ui_net(false, 0);
    ui_failed("no wi-fi. cannot reach any node to verify against");
    return false;
}

void setup()
{
    Serial.begin(115200);
    delay(200);
    banner();

    ui_begin();
    door_begin();
    char l1[24], l2[24];
    snprintf(l1, sizeof l1, "%u authorities", (unsigned)CHECKPOINT_AUTHORITIES);
    snprintf(l2, sizeof l2, "set %llu  need %s", (unsigned long long)CHECKPOINT_SET_ID,
             fmt_num(CHECKPOINT_THRESHOLD));
    ui_boot(l1, l2);

    if (!wifi_connect(WIFI_ATTEMPTS))
        Serial.println("wifi: no association yet; the cycle loop will keep trying");
}

void loop()
{
    static uint32_t cycle = 0;

    if (WiFi.status() != WL_CONNECTED) {
        Serial.println("wifi down");
        door_fail();
        ui_net(false, 0);
        wifi_connect(WIFI_ATTEMPTS);
        return;
    }

    /* Both connections outlive the cycle. A handshake against these endpoints
     * costs about 2.2 s - more than verifying all 401 signatures - and nothing
     * about a refresh needs a fresh one, so they are opened once and kept.
     * Anything that goes wrong closes them, because a session left in the
     * middle of a response body is worse than no session at all; the next
     * cycle then pays for one handshake instead of inheriting garbage.
     *
     * The relay is a WebSocket and Asset Hub is plain HTTPS. Only the relay
     * needs a subscription, and keeping the other on the request/response path
     * means both transports stay exercised on every cycle rather than one of
     * them rotting. */
    static RpcSession relay, hub;

    if (!relay.isOpen()) {
        /* An empty slice: this is not part of a cycle, so there is no
         * fraction of one to claim. The bar stays empty until one starts. */
        ui_stage("connecting to relay", 0, 0);
        PHASE(0);
        if (relay.openWs(RELAY_ENDPOINT) != LC_T_OK) {
            Serial.println("  ! relay WebSocket connect failed");
            ui_failed("could not open the relay WebSocket");
            delay(2000);
            return;
        }
        if (relay.subscribeFinalizedHeads() != LC_T_OK) {
            Serial.println("  ! the node would not subscribe us to finalized heads");
            ui_failed("the node refused a finalized-head subscription");
            relay.close();
            delay(2000);
            return;
        }
        PHASE("relay WebSocket handshake and subscription");
        Serial.println("subscribed to finalized heads");
    }

    /* Everything the node pushed while the last cycle was busy, taken without
     * waiting. Then, if that was nothing, block until it pushes. */
    relay.pumpHeads(0);

    uint32_t head = 0, coalesced = 0, silent = 0;
    while (!relay.takeHead(&head, &coalesced)) {
        if (relay.pumpHeads(500) != LC_T_OK) {
            Serial.println("  ! the relay connection went away while waiting for a head");
            relay.close();
            return;
        }
        ui_tick();
        silent += 500;
        if (silent >= HEAD_SILENCE_MS) {
            Serial.printf("  ! no finalized head pushed in %s s; reconnecting\n",
                          fmt_num(HEAD_SILENCE_MS / 1000));
            relay.close();
            return;
        }
    }

    Serial.printf("\n--- cycle %u ---\n", ++cycle);
    /* A verify in flight is never interrupted. Heads that arrived while it ran
     * were folded into one number as they were absorbed, so what starts here is
     * the newest block the node has finalized - not the oldest of a backlog,
     * and not a queue that would take three cycles to work off. */
    if (coalesced > 1)
        Serial.printf("  %s heads arrived while the last cycle ran; taking the newest\n",
                      fmt_num(coalesced));

    uint32_t t0 = millis();
    ui_net(true, WiFi.RSSI());
    ui_sync_begin(cycle);

    Anchor anchor;
    PHASE(0);
    bool ok = false;
    if (establish_anchor(relay, &anchor, head))
        ok = read_asset_hub(hub, anchor, cycle == 1);
    if (!ok) { door_fail(); relay.close(); hub.close(); }
    PHASE("read the values, and the self-test");

#ifdef LC_NET_STATS
    Serial.printf("  net after the justification: %s ms to first byte, %s bytes, "
                  "%s ms blocked, %s ms polling empty\n",
                  fmt_num(lc_net.ttfb_ms), fmt_num(lc_net.bytes),
                  fmt_num(lc_net.wait_ms), fmt_num(lc_net.stalls));
#endif
    Serial.printf("  cycle took %s ms, heap %s free (largest block %s), "
                  "stack headroom %s\n",
                  fmt_num(millis() - t0), fmt_num(ESP.getFreeHeap()),
                  fmt_num(ESP.getMaxAllocHeap()),
                  fmt_num(uxTaskGetStackHighWaterMark(NULL)));

    /* No countdown to show any more: the next cycle starts when the chain says
     * so, not when a timer expires. The panel ages the proof instead, which is
     * the honest thing for it to display while following the head - a frozen
     * panel and a working one still have to look different. */
    ui_idle();

    /* The politeness gap and the result dwell, whichever asks for longer. Heads
     * pushed during it are not lost: they queue on the socket and the
     * pumpHeads(0) at the top of the next cycle folds them into one.
     *
     * ui_tick() keeps running, so the age in the header counts up while the
     * device holds here. A held panel and a hung one still have to look
     * different. */
    const uint32_t hold = MIN_CYCLE_GAP_MS > RESULT_DWELL_MS
                              ? MIN_CYCLE_GAP_MS : RESULT_DWELL_MS;
    uint32_t until = millis() + hold;
    while ((int32_t)(until - millis()) > 0) {
        ui_tick();
        delay(100);
    }
}
