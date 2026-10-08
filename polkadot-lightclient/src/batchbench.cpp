/* Batch versus per-signature ed25519 verification, on the board.
 *
 * The host harness (test/run_ed.sh) settles correctness and gives a rough
 * algorithmic ratio in under a second. This answers the two questions it
 * cannot: what the ratio is on an Xtensa LX6 with a 32 KB instruction cache,
 * and how much RAM the batch state can actually have.
 *
 * The input is fixed - 403 real Polkadot precommits from
 * test/fixtures/ed_corpus.h, all over the same 53-byte payload - so no network,
 * no chain state, and no reason to restart the light client between runs.
 *
 *   pio run -e batchbench -t upload --upload-port 'rfc2217://host.internal:4000?ign_set_control'
 *
 * Correctness is checked first and against the framework's PREBUILT libsodium,
 * not the vendored copy, because the prebuilt one is what the firmware ships
 * and consensus is defined by what it accepts. The one known and deliberate
 * disagreement is the cofactor case documented in ed25519_batch.h; nothing in
 * this file's corpus or mutations reaches it. */

#include <Arduino.h>
#include <esp_timer.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "ed25519_batch.h"
#include "ed25519_fast.h"
#include "lc_crypto.h"

extern "C" {
#include "../test/fixtures/ed_corpus.h"
}

SET_LOOP_TASK_STACK_SIZE(16384);

/* The optimisation level the vendored verifier and the batch were built at.
 * Passed in by the environment because the compiler does not expose it, and
 * printing the wrong one would make the whole comparison worthless. */
#ifndef LC_OPT_NAME
#define LC_OPT_NAME "?"
#endif

#define MSG     ED_CORPUS_MSG
#define MSGLEN  (sizeof ED_CORPUS_MSG)
#define N       ED_CORPUS_N

static const int ROUNDS = 3;      /* interleaved A/B/batch rounds */

/* Chunk sizes to sweep, in points; two points per signature. The state is
 * sized once, for LC_BATCH_CHUNK, and lc_batch_set_chunk() moves the fold
 * point inside it, so one flash covers the whole trade-off. */
static const unsigned CHUNKS[] = { 64, 128, 256, 512, LC_BATCH_CHUNK };

static lc_ed25519_batch *B;
static uint8_t seed[32];

static void reseed()
{
    for (int i = 0; i < 32; i += 4) {
        uint32_t r = esp_random();
        seed[i] = r; seed[i+1] = r >> 8; seed[i+2] = r >> 16; seed[i+3] = r >> 24;
    }
}

/* One batch over `n` signatures from the corpus, with `sub` optionally
 * replacing entry `at`. Returns 1 if the batch verifies. */
static int run_batch(unsigned n, unsigned chunk,
                     int at = -1, const uint8_t *sub_sig = 0, const uint8_t *sub_pk = 0)
{
    reseed();
    if (!lc_batch_init(B, MSG, MSGLEN, seed)) { vTaskDelay(1); return 0; }
    lc_batch_set_chunk(B, chunk);
    for (unsigned i = 0; i < n; i++) {
        const uint8_t *s = (at >= 0 && (unsigned)at == i && sub_sig) ? sub_sig : ED_CORPUS_SIG[i];
        const uint8_t *p = (at >= 0 && (unsigned)at == i && sub_pk)  ? sub_pk  : ED_CORPUS_PK[i];
        if (!lc_batch_add(B, s, p)) { vTaskDelay(1); return 0; }
    }
    int r = lc_batch_final(B);
    vTaskDelay(1);      /* a 403-signature batch is seconds of uninterrupted
                         * CPU; without this the idle task starves and the task
                         * watchdog panics partway through the suite */
    return r;
}

/* ---------- does the batch accept exactly what libsodium accepts? ---------- */

static uint32_t checked, wrong;

static void expect(int got, int want, const char *what)
{
    checked++;
    if (got != want) {
        wrong++;
        if (wrong <= 8) Serial.printf("  WRONG [%s] got=%d want=%d\n", what, got, want);
    }
}

/* The board is a slow place to be exhaustive: one 403-signature batch is
 * several seconds, so sweeping 1,192 bit flips over full batches would be half
 * an hour. test/test_ed25519.c already does that sweep on the host in under a
 * second. What has to happen HERE is the part the host cannot vouch for: that
 * the batch agrees with the framework's PREBUILT libsodium, on this silicon,
 * with this compiler. So the flips run over short batches, and the full-length
 * batch is exercised where length is the variable being tested. */
/* Short, but not cheap: the bucket summation in a fold is 2*NBUCKETS additions
 * per window whether the batch holds eight points or eight hundred, so every
 * one of these costs on the order of a hundred milliseconds. That fixed cost is
 * why batching is for justifications and not for single signatures, and it sets
 * how many flips fit in a device run. */
#define SHORT_N 8

static int run_short(unsigned at, const uint8_t *sig, const uint8_t *pk)
{
    reseed();
    lc_batch_init(B, MSG, MSGLEN, seed);
    for (unsigned i = 0; i < SHORT_N; i++) {
        const uint8_t *s = (i == at && sig) ? sig : ED_CORPUS_SIG[i];
        const uint8_t *p = (i == at && pk)  ? pk  : ED_CORPUS_PK[i];
        if (!lc_batch_add(B, s, p)) { vTaskDelay(1); return 0; }
    }
    int r = lc_batch_final(B);
    vTaskDelay(1);
    return r;
}

/* Enough to know the build is not broken, in a couple of seconds, for runs that
 * are about tuning rather than correctness. */
static void quick_agreement()
{
    uint8_t sig[64];

    expect(run_batch(N, LC_BATCH_CHUNK), 1, "batch accepts all 403");
    memcpy(sig, ED_CORPUS_SIG[42], 64); sig[13] ^= 0x20;
    expect(run_batch(N, LC_BATCH_CHUNK, 42, sig, 0), 0, "one flipped bit is caught");
    expect(run_batch(N, LC_BATCH_CHUNK, 10, ED_CORPUS_SIG[11], 0), 0, "swapped signature");
    for (unsigned c = 0; c < sizeof CHUNKS / sizeof CHUNKS[0]; c++)
        expect(run_batch(N, CHUNKS[c]), 1, "every chunk size accepts");
}

static void agreement()
{
    uint8_t sig[64], pk[32], msg[MSGLEN];

    /* the whole corpus, per-signature through the shipped libsodium */
    uint32_t ok = 0;
    for (unsigned i = 0; i < N; i++)
        ok += lc_ed25519_verify(ED_CORPUS_SIG[i], MSG, MSGLEN, ED_CORPUS_PK[i]);
    expect(ok == N, 1, "prebuilt libsodium accepts all 403");
    expect(run_batch(N, LC_BATCH_CHUNK), 1, "batch accepts all 403");
    expect(run_short(SHORT_N, 0, 0), 1, "batch accepts a short prefix");
    Serial.printf("  ..corpus and short batch done (%u checks so far)\n", checked);

    /* Every single-bit flip of a signature and of a key, in a short batch, each
     * one also put through the prebuilt verifier on its own. Two rejections is
     * not the claim; agreeing on which inputs get rejected is. */
    for (unsigned bit = 0; bit < 64 * 8; bit++) {
        memcpy(sig, ED_CORPUS_SIG[3], 64);
        sig[bit / 8] ^= 1u << (bit % 8);
        expect(run_short(3, sig, 0), 0, "sig-bitflip batch");
        expect(lc_ed25519_verify(sig, MSG, MSGLEN, ED_CORPUS_PK[3]), 0, "sig-bitflip single");
        if ((bit & 63) == 63) Serial.printf("  ..sig flip %u/512\n", bit + 1);
    }
    for (unsigned bit = 0; bit < 32 * 8; bit++) {
        memcpy(pk, ED_CORPUS_PK[4], 32);
        pk[bit / 8] ^= 1u << (bit % 8);
        expect(run_short(4, 0, pk), 0, "pk-bitflip batch");
        expect(lc_ed25519_verify(ED_CORPUS_SIG[4], MSG, MSGLEN, pk), 0, "pk-bitflip single");
        if ((bit & 63) == 63) Serial.printf("  ..pk flip %u/256\n", bit + 1);
    }

    /* One bit per payload byte: a wrong set_id, round or target must fail. The
     * host sweeps all 424 bits; this is here to show the same thing happens on
     * the target, and each one costs a fold. */
    for (unsigned bit = 0; bit < MSGLEN * 8; bit += 8) {
        memcpy(msg, MSG, MSGLEN);
        msg[bit / 8] ^= 1u << (bit % 8);
        reseed();
        lc_batch_init(B, msg, MSGLEN, seed);
        for (unsigned i = 0; i < SHORT_N; i++)
            if (!lc_batch_add(B, ED_CORPUS_SIG[i], ED_CORPUS_PK[i])) break;
        expect(lc_batch_final(B), 0, "msg-bitflip batch");
        expect(lc_ed25519_verify(ED_CORPUS_SIG[0], msg, MSGLEN, ED_CORPUS_PK[0]), 0,
               "msg-bitflip single");
        vTaskDelay(1);
    }

    Serial.println("  ..flips done, sweeping positions and lengths");

    /* A flipped bit spread across the full batch: buckets, chunk folds and the
     * running accumulator all have to carry it to the end. */
    for (unsigned k = 0; k < 8; k++) {
        unsigned i = (k * N) / 8;
        unsigned b = (i * 37) % 512;
        memcpy(sig, ED_CORPUS_SIG[i], 64);
        sig[b / 8] ^= 1u << (b % 8);
        expect(run_batch(N, LC_BATCH_CHUNK, (int) i, sig, 0), 0, "position sweep");
    }

    /* Lengths either side of every chunk fold, where an off-by-one would live. */
    {
        static const unsigned LENS[] = { 1, 2, 3, 127, 128, 129, 255, 256, 257,
                                         383, 384, 385, 401, 402, 403 };
        for (unsigned k = 0; k < sizeof LENS / sizeof LENS[0]; k++)
            if (LENS[k] <= N) expect(run_batch(LENS[k], LC_BATCH_CHUNK), 1, "prefix accepted");
    }

    /* Every chunk size must give the same two answers. */
    for (unsigned c = 0; c < sizeof CHUNKS / sizeof CHUNKS[0]; c++) {
        expect(run_batch(N, CHUNKS[c]), 1, "chunk: good batch");
        memcpy(sig, ED_CORPUS_SIG[42], 64); sig[13] ^= 0x20;
        expect(run_batch(N, CHUNKS[c], 42, sig, 0), 0, "chunk: bad batch");
    }

    /* Individually valid signatures, wrongly paired. Nothing is malformed here,
     * so only the group equation can catch it. */
    expect(run_batch(N, LC_BATCH_CHUNK, 10, ED_CORPUS_SIG[11], 0), 0, "swapped signature");
    expect(run_batch(N, LC_BATCH_CHUNK, 200, ED_CORPUS_SIG[201], 0), 0, "replayed signature");

    /* The corpus against a neighbouring round: every signature valid, all of
     * them over the wrong payload. */
    memcpy(msg, MSG, MSGLEN);
    msg[37] ^= 1;
    reseed();
    lc_batch_init(B, msg, MSGLEN, seed);
    for (unsigned i = 0; i < N; i++)
        if (!lc_batch_add(B, ED_CORPUS_SIG[i], ED_CORPUS_PK[i])) break;
    expect(lc_batch_final(B), 0, "wrong round");
}

/* ---------- timing ---------- */

typedef int (*verify_fn)(const uint8_t *, const uint8_t *, size_t, const uint8_t *);

/* Busy microseconds for one pass over the corpus, watchdog yields excluded. */
static int64_t time_individual(verify_fn f, uint32_t *ok_out)
{
    int64_t acc = 0;
    uint32_t ok = 0;
    for (unsigned i = 0; i < N; i += 25) {
        unsigned k = (N - i < 25) ? N - i : 25;
        int64_t t0 = esp_timer_get_time();
        for (unsigned j = 0; j < k; j++)
            ok += f(ED_CORPUS_SIG[i + j], MSG, MSGLEN, ED_CORPUS_PK[i + j]);
        acc += esp_timer_get_time() - t0;
        vTaskDelay(1);
    }
    *ok_out = ok;
    return acc;
}

/* The batch cannot be split for the watchdog the way the loop above can, so it
 * runs in one go. 403 signatures at the expected rate is a few seconds, which
 * is inside the default 5 s task watchdog only because the loop task is not
 * subscribed to it by default; the yield after each pass keeps IDLE0 fed. */
static int64_t time_batch(unsigned chunk, int *ok_out)
{
    reseed();
    int64_t t0 = esp_timer_get_time();
    lc_batch_init(B, MSG, MSGLEN, seed);
    lc_batch_set_chunk(B, chunk);
    for (unsigned i = 0; i < N; i++)
        if (!lc_batch_add(B, ED_CORPUS_SIG[i], ED_CORPUS_PK[i])) break;
    *ok_out = lc_batch_final(B);
    int64_t d = esp_timer_get_time() - t0;
    vTaskDelay(1);
    return d;
}

/* ---------- both cores at once ---------- */

struct core_job {
    lc_ed25519_batch   *state;
    unsigned            first, count, chunk;
    volatile int64_t    us;
    volatile int        ok;
    volatile bool       done;
};

static void core_task(void *arg)
{
    core_job *j = (core_job *) arg;
    lc_ed25519_batch *b = j->state;
    uint8_t s[32];

    for (int i = 0; i < 32; i += 4) {
        uint32_t r = esp_random();
        s[i] = r; s[i+1] = r >> 8; s[i+2] = r >> 16; s[i+3] = r >> 24;
    }

    /* Yield between signatures. These tasks outrank IDLE, and a whole batch is
     * seconds of uninterrupted arithmetic, so without this the task watchdog
     * aborts the board partway through - which is exactly what it did the first
     * time both cores actually got a state allocated. A fold is the longest
     * uninterruptible stretch, about 1.6 s at chunk 512, comfortably inside the
     * 5 s watchdog. The delay is outside the measured region.  */
    int64_t acc = 0;
    lc_batch_init(b, MSG, MSGLEN, s);
    lc_batch_set_chunk(b, j->chunk);
    for (unsigned i = 0; i < j->count; i++) {
        int64_t t0 = esp_timer_get_time();
        int rc = lc_batch_add(b, ED_CORPUS_SIG[j->first + i], ED_CORPUS_PK[j->first + i]);
        acc += esp_timer_get_time() - t0;
        if ((i & 7) == 7) vTaskDelay(1);
        if (!rc) break;
    }
    int64_t t1 = esp_timer_get_time();
    j->ok = lc_batch_final(b);
    j->us = acc + (esp_timer_get_time() - t1);

    j->done = true;
    vTaskDelete(NULL);
}

/* Half the justification per core. Splitting a batch is sound for the same
 * reason deferring one signature is: the justification is rejected unless every
 * part verifies, so two batch bits AND together into the answer. */
static void two_core(lc_ed25519_batch *s0, lc_ed25519_batch *s1, unsigned chunk)
{
    static core_job a, b;
    a.state = s0; a.first = 0;     a.count = N / 2;     a.chunk = chunk; a.done = false;
    b.state = s1; b.first = N / 2; b.count = N - N / 2; b.chunk = chunk; b.done = false;

    int64_t t0 = esp_timer_get_time();
    xTaskCreatePinnedToCore(core_task, "bat0", 8192, &a, 2, NULL, 0);
    xTaskCreatePinnedToCore(core_task, "bat1", 8192, &b, 2, NULL, 1);
    while (!a.done || !b.done) vTaskDelay(pdMS_TO_TICKS(10));
    int64_t wall = esp_timer_get_time() - t0;

    Serial.printf("two cores, chunk %4u:  core0 %6.0f ms (%u sigs, ok=%d) | "
                  "core1 %6.0f ms (%u sigs, ok=%d) | wall %6.0f ms%s\n",
                  chunk, a.us / 1000.0, a.count, a.ok,
                  b.us / 1000.0, b.count, b.ok, wall / 1000.0,
                  (a.ok < 0 || b.ok < 0) ? "   !! a core could not allocate" : "");
}

/* ---------- ---------- */

void setup()
{
    Serial.begin(115200);
    /* The RFC2217 bridge takes several seconds to reconnect after esptool
     * closes its session. Keep it outside every measured region. */
    delay(10000);

    Serial.println("\n\n=== ed25519: batch vs per-signature ===");
    Serial.printf("cpu %u MHz, %s\n", (unsigned) getCpuFrequencyMhz(), ESP.getSdkVersion());
    Serial.printf("corpus: %u real precommits, %u-byte payload, round %llu, set %llu\n",
                  N, (unsigned) MSGLEN, (unsigned long long) ED_CORPUS_ROUND,
                  (unsigned long long) ED_CORPUS_SET_ID);
    int lib_w = 0, lib_chunk = 0;
    lc_batch_config(&lib_w, &lib_chunk);
    Serial.printf("build:  %s, w=%d, chunk=%d, state %u bytes  (header says w=%d chunk=%d)\n",
                  LC_OPT_NAME, lib_w, lib_chunk, (unsigned) lc_batch_sizeof(),
                  LC_BATCH_W, LC_BATCH_CHUNK);
    if (lib_w != LC_BATCH_W || lib_chunk != LC_BATCH_CHUNK)
        Serial.println("!! the library and this file were built with different tunings");
    Serial.printf("heap:   %u free before allocating\n", (unsigned) ESP.getFreeHeap());

    B = (lc_ed25519_batch *) malloc(lc_batch_sizeof());
    if (!B) { Serial.println("!! cannot allocate the batch state - stop"); return; }
    Serial.printf("        %u free after\n\n", (unsigned) ESP.getFreeHeap());

    Serial.println("-- does the batch accept exactly what libsodium accepts? --");
    uint32_t t0 = millis();
#ifdef BATCHBENCH_QUICK
    Serial.println("  (BATCHBENCH_QUICK: sanity only - run env:batchbench for the full suite)");
    quick_agreement();
#else
    agreement();
#endif
    Serial.printf("%u checks, %u wrong  (%u ms)\n\n", checked, wrong,
                  (unsigned) (millis() - t0));
    if (wrong) {
        Serial.println("!! disagreement - not timing, the result would be meaningless");
        return;
    }

    Serial.println("-- timing, interleaved --");
    int64_t os_tot = 0, o3_tot = 0;
    int64_t bat_tot[sizeof CHUNKS / sizeof CHUNKS[0]] = { 0 };

    for (int r = 0; r < ROUNDS; r++) {
        uint32_t ok;
        int64_t a = time_individual(lc_ed25519_verify, &ok);
        int64_t b = time_individual(lc_ed25519_verify_fast, &ok);
        os_tot += a; o3_tot += b;
        Serial.printf("round %d  per-sig prebuilt %7.0f ms | per-sig vendored %7.0f ms",
                      r + 1, a / 1000.0, b / 1000.0);
        for (unsigned c = 0; c < sizeof CHUNKS / sizeof CHUNKS[0]; c++) {
            int ok2;
            int64_t d = time_batch(CHUNKS[c], &ok2);
            bat_tot[c] += d;
            Serial.printf(" | batch/%u %6.0f ms%s", CHUNKS[c], d / 1000.0, ok2 ? "" : " BAD");
        }
        Serial.println();
    }

    double os_ms = (double) os_tot / ROUNDS / 1000.0;
    double o3_ms = (double) o3_tot / ROUNDS / 1000.0;

    Serial.println("\n=== summary: one core, 403 signatures ===");
    Serial.printf("per-signature, prebuilt -Os   %7.2f s   %6.3f ms/sig   1.00x\n",
                  os_ms / 1000.0, os_ms / N);
    Serial.printf("per-signature, vendored %-3s   %7.2f s   %6.3f ms/sig   %.2fx\n",
                  LC_OPT_NAME, o3_ms / 1000.0, o3_ms / N, os_ms / o3_ms);
    for (unsigned c = 0; c < sizeof CHUNKS / sizeof CHUNKS[0]; c++) {
        double ms = (double) bat_tot[c] / ROUNDS / 1000.0;
        /* State actually needed for this chunk size, not what was allocated. */
        Serial.printf("batch, chunk %4u points      %7.2f s   %6.3f ms/sig   %.2fx\n",
                      CHUNKS[c], ms / 1000.0, ms / N, os_ms / ms);
    }

    /* Two per-core states do not fit alongside this one, so release it first.
     * They are also allocated once and reused: the first version allocated
     * inside each task, and after a few rounds of that an 87 KB request could
     * no longer find a contiguous block even with 330 KB free. A core that
     * cannot allocate reports nothing and the wall clock silently becomes the
     * other core's time, which is how this measurement lied twice. */
    free(B);
    B = 0;
    Serial.printf("\n=== both cores ===  (%u free, each core needs %u)\n",
                  (unsigned) ESP.getFreeHeap(), (unsigned) lc_batch_sizeof());
    lc_ed25519_batch *s0 = (lc_ed25519_batch *) malloc(lc_batch_sizeof());
    lc_ed25519_batch *s1 = (lc_ed25519_batch *) malloc(lc_batch_sizeof());
    if (!s0 || !s1) {
        Serial.println("!! cannot allocate two states - skipping the two-core arm");
    } else {
        for (unsigned c = 0; c < sizeof CHUNKS / sizeof CHUNKS[0]; c++)
            two_core(s0, s1, CHUNKS[c]);
    }
    free(s0); free(s1);

    Serial.printf("\nheap %u free\n", (unsigned) ESP.getFreeHeap());
    Serial.println("=== done ===");
}

void loop() { delay(1000); }
