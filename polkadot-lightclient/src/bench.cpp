#include "wifi.local.h"
/* Core-affinity benchmark: is it worth verifying signatures on a second core?
 *
 * Originally this file answered that question with its own forked copy of the
 * verification loop, because grandpa.c had no way to hand work to another core.
 * It does now, so every condition below drives the SHIPPED code - the same
 * grandpa.c, prefetch.cpp and sigpool.cpp that main.cpp uses. What is measured
 * and what runs on the device are the same thing again.
 *
 * Conditions, all against live mainnet, all on this board:
 *
 *   MICRO   ed25519 alone: core 0, core 1, and both at once (Wi-Fi idle).
 *           Isolates per-signature cost and cross-core contention.
 *   SEQ     the original path: one task reads a record, verifies it, reads the
 *           next. Network wait and ed25519 never overlap.       <- baseline
 *   OFF     prefetch only. A higher-priority task keeps the socket draining
 *           while the verifier works, so the two overlap - but the ed25519 is
 *           still all on one core. Isolates the transport half of the win.
 *   SPLIT   prefetch + sigpool: what ships. The verify loop is still single
 *           threaded and still does every cheap check itself; only the ed25519
 *           goes to the worker, and only when the worker will take it.
 *   DRAIN   stream the identical byte count with no verification at all.
 *           The floor: no arrangement of cores can beat this.
 *
 * Conditions are interleaved within each rep rather than run in blocks, because
 * RPC provider latency drifts over minutes and blocked trials would charge that
 * drift to whichever condition ran last. */

#include <Arduino.h>
#include <WiFi.h>
#include <esp_timer.h>

#include "checkpoint.h"
#include "grandpa.h"
#include "lc_crypto.h"
#include "prefetch.h"
#include "scale.h"
#include "sigpool.h"
#include "transport.h"



SET_LOOP_TASK_STACK_SIZE(16384);

static const int REPS = 4;              /* SEQ/OFF/DRAIN trials per condition */
static const uint32_t MICRO_SIGS = 200; /* signatures per crypto microbench */
static const uint32_t MICRO_BLOCK = 50; /* verifies between watchdog yields */

static uint8_t hdr_buf[32768];

/* No precomputed tables here on purpose: this benchmark measures the transport,
 * and its numbers are compared across firmware revisions. Handing it a faster
 * verifier than the one its history was recorded with would move the wrong
 * line. src/mcbench.cpp is where the verifier is timed. */
static const grandpa_authority_set AUTHORITIES = {
    CHECKPOINT_AUTHORITY_KEYS, CHECKPOINT_AUTHORITY_WEIGHTS,
    CHECKPOINT_AUTHORITIES, CHECKPOINT_TOTAL_WEIGHT,
    CHECKPOINT_THRESHOLD, CHECKPOINT_SET_ID, NULL,
};

/* A real precommit that verified, kept so the microbenchmarks time the same
 * path the firmware actually takes. An invalid signature can be rejected early
 * and would time faster than the work we care about. */
static uint8_t  micro_sig[64], micro_pk[32], micro_payload[GRANDPA_PAYLOAD_LEN];
static bool     have_micro = false;

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

/* ---------- counting reader: every condition reports bytes consumed ---------- */

typedef struct {
    lc_reader base;
    lc_reader *inner;
    uint32_t bytes;
} counting_reader;

static int counting_read(lc_reader *self, uint8_t *dst, size_t n)
{
    counting_reader *c = (counting_reader *)self->ctx;
    if (!lc_read(c->inner, dst, n)) return 0;
    c->bytes += (uint32_t)n;
    return 1;
}

static void counting_reader_init(counting_reader *c, lc_reader *inner)
{
    c->base.read = counting_read;
    c->base.ctx = c;
    c->inner = inner;
    c->bytes = 0;
}

/* ---------- crypto microbenchmark ---------- */

typedef struct {
    uint32_t n;
    volatile uint32_t done;
    int64_t busy_us;        /* excludes the watchdog yields */
    uint32_t ok;
} micro_arg;

static void micro_task(void *arg)
{
    micro_arg *a = (micro_arg *)arg;
    int64_t acc = 0;
    uint32_t ok = 0;
    for (uint32_t i = 0; i < a->n; i += MICRO_BLOCK) {
        uint32_t k = a->n - i < MICRO_BLOCK ? a->n - i : MICRO_BLOCK;
        int64_t t0 = esp_timer_get_time();
        for (uint32_t j = 0; j < k; j++)
            ok += lc_ed25519_verify(micro_sig, micro_payload, GRANDPA_PAYLOAD_LEN, micro_pk);
        acc += esp_timer_get_time() - t0;
        vTaskDelay(1);      /* let IDLE run; not counted in busy_us */
    }
    a->busy_us = acc;
    a->ok = ok;
    a->done = 1;
    vTaskDelete(NULL);
}

static void micro_run(const char *label, int core_a, int core_b)
{
    static micro_arg a, b;
    a.n = b.n = MICRO_SIGS;
    a.done = b.done = 0;
    a.busy_us = b.busy_us = 0;

    xTaskCreatePinnedToCore(micro_task, "microA", 8192, &a, 1, NULL, core_a);
    if (core_b >= 0)
        xTaskCreatePinnedToCore(micro_task, "microB", 8192, &b, 1, NULL, core_b);

    while (!a.done || (core_b >= 0 && !b.done)) delay(5);

    double ma = (double)a.busy_us / a.n / 1000.0;
    if (core_b < 0)
        Serial.printf("MICRO %-22s core%d  %6.3f ms/sig  (%u/%u verified)\n",
                      label, core_a, ma, a.ok, a.n);
    else {
        double mb = (double)b.busy_us / b.n / 1000.0;
        Serial.printf("MICRO %-22s core%d  %6.3f ms/sig | core%d  %6.3f ms/sig  "
                      "(%u+%u verified)\n",
                      label, core_a, ma, core_b, mb, a.ok, b.ok);
    }
}

/* ---------- one trial ---------- */

typedef enum { RUN_SEQ, RUN_OFF, RUN_DRAIN, RUN_SPLIT } run_mode;

typedef struct {
    bool ok;
    int64_t wall_us;        /* positioned-at-payload -> verification returned */
    uint32_t bytes;
    uint32_t n_valid, n_precommits;
    uint32_t on_worker;     /* SPLIT: checks the second core ran */
    uint32_t inline_sigs;   /* SPLIT: checks the verifier did while it was busy */
} trial;

static bool open_and_seek(RpcSession &s, uint32_t hint)
{
    char params[24];
    snprintf(params, sizeof params, "[%u]", hint);
    if (s.call("grandpa_proveFinality", params) != LC_T_OK) return false;
    return rpc_seek_result_hex(s) == LC_T_OK;
}

static trial run_trial(run_mode mode, uint32_t hint, uint32_t drain_bytes)
{
    trial t; memset(&t, 0, sizeof t);
    RpcSession s;
    if (s.open(RELAY_ENDPOINT) != LC_T_OK) return t;
    if (!open_and_seek(s, hint)) { s.close(); return t; }

    RpcHexReader hr;
    rpc_hex_reader_init(&hr, &s);

    if (mode == RUN_SEQ) {
        counting_reader cr; counting_reader_init(&cr, &hr.base);
        grandpa_result g;
        int64_t t0 = esp_timer_get_time();
        grandpa_status gs = grandpa_verify_finality_proof(&cr.base, &AUTHORITIES, &g, NULL, NULL);
        t.wall_us = esp_timer_get_time() - t0;
        t.bytes = cr.bytes;
        t.ok = (gs == GRANDPA_OK);
        t.n_valid = g.n_valid; t.n_precommits = g.n_precommits;
        if (t.ok && !have_micro) {
            memcpy(micro_sig, g.sample + 36, 64);
            memcpy(micro_pk,  g.sample + 100, 32);
            grandpa_localized_payload(micro_payload, g.target_hash, g.target_number,
                                      g.round, CHECKPOINT_SET_ID);
            have_micro = lc_ed25519_verify(micro_sig, micro_payload,
                                           GRANDPA_PAYLOAD_LEN, micro_pk) != 0;
        }
    } else if (mode == RUN_DRAIN) {
        /* Same bytes off the same wire, no ed25519 at all. */
        uint8_t chunk[132];
        int64_t t0 = esp_timer_get_time();
        uint32_t got = 0;
        while (got < drain_bytes) {
            size_t want = drain_bytes - got < sizeof chunk ? drain_bytes - got : sizeof chunk;
            if (!lc_read(&hr.base, chunk, want)) break;
            got += want;
        }
        t.wall_us = esp_timer_get_time() - t0;
        t.bytes = got;
        t.ok = (got == drain_bytes);
    } else {
        /* OFF and SPLIT differ by one line: whether a pool exists. Everything
         * else - the reader, the loop, the accounting - is what main.cpp runs. */
        RpcPrefetch *pf = prefetch_start(&s, xPortGetCoreID());
        sigpool *sp = (mode == RUN_SPLIT) ? sigpool_start(xPortGetCoreID() == 0 ? 1 : 0)
                                          : NULL;
        if (!pf || (mode == RUN_SPLIT && !sp)) {
            sigpool_stop(sp); prefetch_stop(pf); s.close(); return t;
        }

        counting_reader cr; counting_reader_init(&cr, prefetch_reader(pf));
        grandpa_result g;
        int64_t t0 = esp_timer_get_time();
        grandpa_status gs = grandpa_verify_finality_proof_ex(&cr.base, &AUTHORITIES, &g,
                                                             NULL, NULL, sigpool_iface(sp));
        t.wall_us = esp_timer_get_time() - t0;
        t.on_worker = sigpool_worker_sigs(sp);

        sigpool_stop(sp);
        prefetch_stop(pf);

        t.bytes = cr.bytes;
        t.ok = (gs == GRANDPA_OK);
        t.n_valid = g.n_valid; t.n_precommits = g.n_precommits;
        t.inline_sigs = g.n_valid - t.on_worker;
    }

    s.close();
    return t;
}

/* ---------- driver ---------- */

static bool wifi_connect()
{
    WiFi.mode(WIFI_STA);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    for (int i = 0; i < 60 && WiFi.status() != WL_CONNECTED; i++) delay(500);
    return WiFi.status() == WL_CONNECTED;
}

static bool finalized_number(uint32_t *out)
{
    RpcSession s;
    if (s.open(RELAY_ENDPOINT) != LC_T_OK) return false;
    if (s.call("chain_getFinalizedHead", "[]") != LC_T_OK) { s.close(); return false; }
    uint8_t h[32];
    if (rpc_seek_result_hex(s) != LC_T_OK || !s.readHex(h, 32)) { s.close(); return false; }
    s.skipBody();
    char hex[70]; to_hex0x(h, 32, hex);
    size_t len;
    if (transport_fetch_header(s, hex, hdr_buf, sizeof hdr_buf, &len) != LC_T_OK) {
        s.close(); return false;
    }
    lc_header hdr;
    bool ok = scale_decode_header(hdr_buf, len, &hdr);
    if (ok) *out = hdr.number;
    s.close();
    return ok;
}

static int64_t seq_us[REPS], off_us[REPS], split_us[REPS], drain_us[REPS];
static int n_seq, n_off, n_split, n_drain;

static void summarize(const char *name, const int64_t *v, int n)
{
    if (!n) { Serial.printf("%-6s  no successful trials\n", name); return; }
    int64_t sum = 0, lo = v[0], hi = v[0];
    for (int i = 0; i < n; i++) { sum += v[i]; if (v[i] < lo) lo = v[i]; if (v[i] > hi) hi = v[i]; }
    Serial.printf("%-6s  n=%d  mean %7.2f s   min %7.2f   max %7.2f\n",
                  name, n, sum / 1e6 / n, lo / 1e6, hi / 1e6);
}

void setup()
{
    Serial.begin(115200);
    delay(300);
    Serial.println("\n\n=== core-affinity benchmark: signature verification on core 1 ===");
    Serial.printf("cpu %u MHz, flash %u Hz, %s\n",
                  (unsigned)getCpuFrequencyMhz(), (unsigned)ESP.getFlashChipSpeed(),
                  ESP.getSdkVersion());
    Serial.printf("loop task on core %d; the sigpool worker goes on the other one\n",
                  xPortGetCoreID());
    Serial.printf("authorities %u  set_id %llu  threshold %llu\n",
                  (unsigned)CHECKPOINT_AUTHORITIES,
                  (unsigned long long)CHECKPOINT_SET_ID,
                  (unsigned long long)CHECKPOINT_THRESHOLD);

    if (!wifi_connect()) { Serial.println("wifi: failed, cannot benchmark"); return; }
    Serial.printf("wifi up, rssi %d, heap %u\n", WiFi.RSSI(), (unsigned)ESP.getFreeHeap());

    uint32_t hint = 0;
    if (!finalized_number(&hint)) { Serial.println("could not reach the relay chain"); return; }
    Serial.printf("finalized head #%u\n\n", hint);

    /* One SEQ trial first, to capture a verified precommit for the
     * microbenchmarks and the byte count DRAIN has to match. */
    trial warm = run_trial(RUN_SEQ, hint, 0);
    if (!warm.ok) { Serial.println("warm-up justification did not verify; aborting"); return; }
    uint32_t just_bytes = warm.bytes;
    Serial.printf("warm-up: SEQ %.2f s, %u bytes, %u/%u sigs, micro sample %s\n\n",
                  warm.wall_us / 1e6, just_bytes, warm.n_valid, warm.n_precommits,
                  have_micro ? "captured" : "MISSING");
    if (!have_micro) return;

    Serial.println("-- crypto alone, Wi-Fi associated but idle --");
    micro_run("ed25519 solo",        0, -1);
    micro_run("ed25519 solo",        1, -1);
    micro_run("ed25519 both cores",  0,  1);
    Serial.println();

    Serial.println("-- live trials, interleaved --");
    for (int r = 0; r < REPS; r++) {
        trial a = run_trial(RUN_SEQ, hint, 0);
        Serial.printf("rep %d SEQ    %7.2f s  %6u B  %u/%u sigs  %s\n", r + 1,
                      a.wall_us / 1e6, a.bytes, a.n_valid, a.n_precommits,
                      a.ok ? "ok" : "FAILED");
        if (a.ok) seq_us[n_seq++] = a.wall_us;

        trial b = run_trial(RUN_OFF, hint, 0);
        Serial.printf("rep %d OFF    %7.2f s  %6u B  %u/%u sigs  %s\n", r + 1,
                      b.wall_us / 1e6, b.bytes, b.n_valid, b.n_precommits,
                      b.ok ? "ok" : "FAILED");
        if (b.ok) off_us[n_off++] = b.wall_us;

        trial d = run_trial(RUN_SPLIT, hint, 0);
        Serial.printf("rep %d SPLIT  %7.2f s  %6u B  %u/%u sigs  "
                      "worker core %u, inline %u  %s\n", r + 1,
                      d.wall_us / 1e6, d.bytes, d.n_valid, d.n_precommits,
                      d.on_worker, d.inline_sigs, d.ok ? "ok" : "FAILED");
        if (d.ok) split_us[n_split++] = d.wall_us;

        trial c = run_trial(RUN_DRAIN, hint, just_bytes);
        Serial.printf("rep %d DRAIN  %7.2f s  %6u B  %s\n", r + 1,
                      c.wall_us / 1e6, c.bytes, c.ok ? "ok" : "SHORT");
        if (c.ok) { drain_us[n_drain++] = c.wall_us; }
    }

    Serial.println("\n=== summary ===");
    summarize("SEQ",   seq_us,   n_seq);
    summarize("OFF",   off_us,   n_off);
    summarize("SPLIT", split_us, n_split);
    summarize("DRAIN", drain_us, n_drain);
    Serial.printf("heap %u free, largest block %u\n",
                  (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxAllocHeap());
    Serial.println("=== done ===");
}

void loop() { delay(1000); }
