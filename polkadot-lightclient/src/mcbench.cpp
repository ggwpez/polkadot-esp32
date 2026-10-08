/* Per-signature ed25519 verification on one core and on both, no batching.
 *
 * EXPERIMENTS.md E5 measured the batch on two cores and left the per-signature
 * two-core figure as a projection: "half of single-core, near-linear, because
 * the batch scaled that way". This file replaces that projection with a
 * measurement, because a projection is exactly what the batch decision should
 * not rest on.
 *
 * Nothing here changes what is accepted. Both arms are ordinary ref10
 * verification of one signature at a time, so the accepted and rejected sets
 * are libsodium's, and splitting a justification across two cores is sound for
 * the trivial reason that AND is associative.
 *
 *   tools/devrun.sh mcbench
 *
 * Two flashes cannot be compared by absolute milliseconds - E5 measured a 4%
 * spread on byte-identical libsodium across images, from instruction-cache
 * layout alone. So every image times the framework's PREBUILT libsodium as an
 * in-image anchor and reports the vendored arm as a RATIO to it. Ratios are
 * comparable across flashes; the millisecond columns are not. */

#include <Arduino.h>
#include <esp_timer.h>
#include <esp_system.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "ed25519_fast.h"
#include "lc_crypto.h"

extern "C" {
#include "../test/fixtures/ed_corpus.h"
}

#ifdef LC_ED25519_PRECOMP
#include "checkpoint.h"
#include "checkpoint_precomp.h"
#endif

SET_LOOP_TASK_STACK_SIZE(16384);

#ifndef LC_OPT_NAME
#define LC_OPT_NAME "?"
#endif

/* Set by env:mcbench_asm. Names the vendored arm in the output so a capture
 * cannot be mistaken for the other build. */
#ifdef LC_FE25519_ASM
#define VENDORED_NAME "vendored+asm"
extern "C" uint32_t lc_fe25519_difftest(uint32_t iters, uint32_t seed);
extern "C" void lc_fe25519_mul_pair(int32_t out_c[10], int32_t out_asm[10],
                                    const int32_t f[10], const int32_t g[10]);
extern "C" uint32_t lc_fe25519_mulbench(uint32_t iters, int use_asm);

/* fe25519_mul alone, both implementations, in one image so the comparison does
 * not depend on the cross-flash anchor. Interleaved for the same reason the
 * signature rounds are. */
static void fe_kernel_bench()
{
    const uint32_t ITERS = 200000;
    int64_t ct = 0, at = 0;
    uint32_t sink = 0;
    for (int r = 0; r < 3; r++) {
        int64_t t0 = esp_timer_get_time();
        sink ^= lc_fe25519_mulbench(ITERS, 0);
        ct += esp_timer_get_time() - t0;
        vTaskDelay(1);
        t0 = esp_timer_get_time();
        sink ^= lc_fe25519_mulbench(ITERS, 1);
        at += esp_timer_get_time() - t0;
        vTaskDelay(1);
    }
    double cns = (double) ct / 3.0 * 1000.0 / ITERS;
    double ans = (double) at / 3.0 * 1000.0 / ITERS;
    Serial.printf("fe25519_mul alone, %u calls x3:  C %6.1f ns  |  asm %6.1f ns  |  %.3fx"
                  "   (checksum %08x)\n", ITERS, cns, ans, cns / ans, sink);
    /* 240 MHz, so nanoseconds divided by 4.1667 are cycles. */
    Serial.printf("                                 %6.0f cyc %10s %6.0f cyc\n",
                  cns * 0.24, "", ans * 0.24);
}

/* Three inputs with hand-checkable answers, run one at a time with the serial
 * port flushed in between, so that "the board stopped" names an instruction
 * rather than a sweep. */
static void fe_smoke()
{
    static const int32_t ONE[10]  = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    static const int32_t ZERO[10] = { 0 };
    /* Every limb at the top of ref10's documented precondition, alternating
     * sign: the worst case for the accumulator and for every carry. */
    static int32_t BIG[10];
    for (int i = 0; i < 10; i++)
        BIG[i] = (i & 1) ? -55351705 : 110703411;

    struct { const char *name; const int32_t *f, *g; } cases[] = {
        { "0 * 0",     ZERO, ZERO },
        { "1 * 1",     ONE,  ONE  },
        { "1 * big",   ONE,  BIG  },
        { "big * big", BIG,  BIG  },
    };
    for (unsigned i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int32_t c[10], x[10];
        Serial.printf("  %-10s ", cases[i].name);
        Serial.flush();
        lc_fe25519_mul_pair(c, x, cases[i].f, cases[i].g);
        int ok = 1;
        for (int k = 0; k < 10; k++) if (c[k] != x[k]) ok = 0;
        Serial.printf("%s\n", ok ? "match" : "MISMATCH");
        if (!ok) {
            Serial.print("    C  :"); for (int k = 0; k < 10; k++) Serial.printf(" %d", c[k]);
            Serial.print("\n    asm:"); for (int k = 0; k < 10; k++) Serial.printf(" %d", x[k]);
            Serial.println();
        }
        Serial.flush();
    }
}
#else
#define VENDORED_NAME "vendored"
#endif

extern "C" uint32_t lc_prof_phase(int phase, const uint8_t pk[32], const uint8_t sig[64],
                                 const uint8_t *msg, size_t msg_len, uint32_t iters);

#define MSG     ED_CORPUS_MSG
#define MSGLEN  (sizeof ED_CORPUS_MSG)
#define N       ED_CORPUS_N

static const int ROUNDS = 3;

/* Every arm takes a table pointer, and the ones that have no use for it ignore
 * it, so all three are timed by the same loop over the same records. */
typedef int (*verify_fn)(const uint8_t *sig, const uint8_t *msg, size_t msg_len,
                         const uint8_t *pk, const void *tab);

static int v_prebuilt(const uint8_t *sig, const uint8_t *msg, size_t len,
                      const uint8_t *pk, const void *tab)
{ (void) tab; return lc_ed25519_verify(sig, msg, len, pk); }

static int v_vendored(const uint8_t *sig, const uint8_t *msg, size_t len,
                      const uint8_t *pk, const void *tab)
{ (void) tab; return lc_ed25519_verify_fast(sig, msg, len, pk); }

#ifdef LC_ED25519_PRECOMP
static int v_table(const uint8_t *sig, const uint8_t *msg, size_t len,
                   const uint8_t *pk, const void *tab)
{ return lc_ed25519_verify_pre(sig, msg, len, pk, (const lc_ed25519_pretab *) tab); }
#endif

/* ---------- the records every arm runs over ----------

   The corpus is a real justification from set 3585 and the tables in flash are
   for set 3587, so a handful of its signers have since left the authority set
   and have no table. Rather than let the table arm run over a different set of
   records than the other two - which would make the ratio meaningless - every
   arm runs over the intersection. That is also the honest shape of the
   production path: a signer with no table is verified the old way.

   Using the SHIPPED tables rather than building fixtures for the corpus is
   deliberate. It measures src/checkpoint_precomp.c, read from memory-mapped
   flash exactly as the firmware reads it, and not a benchmark's private copy. */

static uint16_t     SEL[N];         /* corpus indices, in corpus order */
static const void  *SEL_TAB[N];     /* the signer's table, or NULL */
static unsigned     NSEL;

static void select_records()
{
#ifdef LC_ED25519_PRECOMP
    for (unsigned i = 0; i < N; i++) {
        size_t lo = 0, hi = CHECKPOINT_AUTHORITIES;
        const void *tab = NULL;
        while (lo < hi) {
            size_t mid = lo + (hi - lo) / 2;
            int c = memcmp(CHECKPOINT_AUTHORITY_KEYS + mid * 32, ED_CORPUS_PK[i], 32);
            if (c == 0) { tab = &CHECKPOINT_AUTHORITY_PRECOMP[mid]; break; }
            if (c < 0) lo = mid + 1; else hi = mid;
        }
        if (!tab) continue;
        SEL_TAB[NSEL] = tab;
        SEL[NSEL++] = (uint16_t) i;
    }
#else
    for (unsigned i = 0; i < N; i++) { SEL_TAB[i] = NULL; SEL[i] = (uint16_t) i; }
    NSEL = N;
#endif
}

/* ---------- does the vendored verifier accept exactly what libsodium does? --

   Cheap here in a way the batch never was: one per-signature check is ~19 ms,
   so a few thousand of them is a minute, and the flip sweeps that had to be
   cut down to SHORT_N=8 for the batch can run at full length. */

static uint32_t checked, wrong;

static void agree(const uint8_t *sig, const uint8_t *pk, const char *what)
{
    checked++;
    int a = lc_ed25519_verify(sig, MSG, MSGLEN, pk);
    int b = lc_ed25519_verify_fast(sig, MSG, MSGLEN, pk);
    if (a != b) {
        wrong++;
        if (wrong <= 8) Serial.printf("  WRONG [%s] prebuilt=%d vendored=%d\n", what, a, b);
    }
}

static void agreement()
{
    uint8_t sig[64], pk[32];

    /* Every real precommit, both paths, both must accept. */
    for (unsigned i = 0; i < N; i++) {
        agree(ED_CORPUS_SIG[i], ED_CORPUS_PK[i], "corpus");
        if (!lc_ed25519_verify(ED_CORPUS_SIG[i], MSG, MSGLEN, ED_CORPUS_PK[i])) {
            wrong++;
            Serial.printf("  WRONG [corpus %u] prebuilt rejects a real precommit\n", i);
        }
        if ((i & 15) == 15) vTaskDelay(1);
    }

    /* Every single-bit flip of one signature and one key. 512 + 256 checks,
     * all of which both paths must reject. */
    for (unsigned b = 0; b < 512; b++) {
        memcpy(sig, ED_CORPUS_SIG[0], 64);
        sig[b >> 3] ^= (uint8_t) (1u << (b & 7));
        agree(sig, ED_CORPUS_PK[0], "sig bitflip");
        if ((b & 15) == 15) vTaskDelay(1);
    }
    for (unsigned b = 0; b < 256; b++) {
        memcpy(pk, ED_CORPUS_PK[0], 32);
        pk[b >> 3] ^= (uint8_t) (1u << (b & 7));
        agree(ED_CORPUS_SIG[0], pk, "pk bitflip");
        if ((b & 15) == 15) vTaskDelay(1);
    }

    /* Signature under the wrong key, and a key with the wrong signature: the
     * forgery shape a rogue authority would actually try. */
    for (unsigned i = 0; i + 1 < 64; i++) {
        agree(ED_CORPUS_SIG[i], ED_CORPUS_PK[i + 1], "swapped key");
        agree(ED_CORPUS_SIG[i + 1], ED_CORPUS_PK[i], "swapped sig");
        if ((i & 15) == 15) vTaskDelay(1);
    }

    /* The edge cases the wrapper's own checks exist for: small-order points,
     * non-canonical encodings, an all-ones scalar above L. */
    static const uint8_t small_order[8][32] = {
        {0},
        {1},
        {0xe0,0xeb,0x7a,0x7c,0x3b,0x41,0xb8,0xae,0x16,0x56,0xe3,0xfa,0xf1,0x9f,0xc4,0x6a,
         0xda,0x09,0x8d,0xeb,0x9c,0x32,0xb1,0xfd,0x86,0x62,0x05,0x16,0x5f,0x49,0xb8,0x00},
        {0x5f,0x9c,0x95,0xbc,0xa3,0x50,0x8c,0x24,0xb1,0xd0,0xb1,0x55,0x9c,0x83,0xef,0x5b,
         0x04,0x44,0x5c,0xc4,0x58,0x1c,0x8e,0x86,0xd8,0x22,0x4e,0xdd,0xd0,0x9f,0x11,0x57},
        {0xec,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
        {0xed,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
        {0xee,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x7f},
        {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
         0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff},
    };
    for (unsigned i = 0; i < 8; i++) {
        memcpy(sig, ED_CORPUS_SIG[0], 64);
        memcpy(sig, small_order[i], 32);            /* R small-order or non-canonical */
        agree(sig, ED_CORPUS_PK[0], "small-order R");
        agree(ED_CORPUS_SIG[0], small_order[i], "small-order A");
        memcpy(sig, ED_CORPUS_SIG[0], 64);
        memset(sig + 32, 0xff, 32);                 /* S far above L */
        agree(sig, ED_CORPUS_PK[0], "S >= L");
        vTaskDelay(1);
    }

    /* Deterministic garbage: neither path should accept any of it, and more to
     * the point they should disagree on none of it. */
    uint32_t x = 0x9e3779b9u;
    for (unsigned i = 0; i < 256; i++) {
        for (unsigned k = 0; k < 64; k++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; sig[k] = (uint8_t) x; }
        for (unsigned k = 0; k < 32; k++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; pk[k] = (uint8_t) x; }
        agree(sig, pk, "garbage");
        if ((i & 15) == 15) vTaskDelay(1);
    }
}

/* ---------- one core ---------- */

/* Busy microseconds for one pass over the corpus. The watchdog yields sit
 * between the timed blocks, not inside them. */
static int64_t time_one_core(verify_fn f, uint32_t *ok_out)
{
    int64_t acc = 0;
    uint32_t ok = 0;
    for (unsigned i = 0; i < NSEL; i += 25) {
        unsigned k = (NSEL - i < 25) ? NSEL - i : 25;
        int64_t t0 = esp_timer_get_time();
        for (unsigned j = 0; j < k; j++) {
            unsigned r = SEL[i + j];
            ok += f(ED_CORPUS_SIG[r], MSG, MSGLEN, ED_CORPUS_PK[r], SEL_TAB[i + j]);
        }
        acc += esp_timer_get_time() - t0;
        vTaskDelay(1);
    }
    *ok_out = ok;
    return acc;
}

/* ---------- both cores ---------- */

struct core_job {
    verify_fn        f;
    unsigned         first, count;
    volatile int64_t us;        /* busy time on this core */
    volatile uint32_t ok;
    volatile bool    done;
};

static void core_task(void *arg)
{
    core_job *j = (core_job *) arg;
    int64_t acc = 0;
    uint32_t ok = 0;

    for (unsigned i = 0; i < j->count; i += 25) {
        unsigned k = (j->count - i < 25) ? j->count - i : 25;
        int64_t t0 = esp_timer_get_time();
        for (unsigned m = 0; m < k; m++) {
            unsigned s = j->first + i + m, r = SEL[s];
            ok += j->f(ED_CORPUS_SIG[r], MSG, MSGLEN, ED_CORPUS_PK[r], SEL_TAB[s]);
        }
        acc += esp_timer_get_time() - t0;
        vTaskDelay(1);          /* these tasks outrank IDLE; without this the
                                 * task watchdog aborts the board partway */
    }
    j->us = acc;
    j->ok = ok;
    j->done = true;
    vTaskDelete(NULL);
}

/* Wall microseconds for the whole 403-signature corpus split across the two
 * cores. Half each: the work is uniform, so there is nothing to schedule. */
static int64_t time_two_cores(verify_fn f, uint32_t *ok_out,
                              int64_t *us0, int64_t *us1)
{
    static core_job a, b;
    a.f = f; a.first = 0;        a.count = NSEL / 2;        a.done = false;
    b.f = f; b.first = NSEL / 2; b.count = NSEL - NSEL / 2; b.done = false;

    int64_t t0 = esp_timer_get_time();
    xTaskCreatePinnedToCore(core_task, "ver0", 8192, &a, 2, NULL, 0);
    xTaskCreatePinnedToCore(core_task, "ver1", 8192, &b, 2, NULL, 1);
    while (!a.done || !b.done) vTaskDelay(pdMS_TO_TICKS(5));
    int64_t wall = esp_timer_get_time() - t0;

    *ok_out = a.ok + b.ok;
    *us0 = a.us; *us1 = b.us;
    return wall;
}

/* ---------- ---------- */

void setup()
{
    Serial.begin(115200);
    delay(10000);               /* the RFC2217 bridge needs to reconnect */

    Serial.println("\n\n=== ed25519: per-signature, one core vs two ===");
    Serial.printf("cpu %u MHz, %s\n", (unsigned) getCpuFrequencyMhz(), ESP.getSdkVersion());
    Serial.printf("corpus: %u real precommits, %u-byte payload, round %llu, set %llu\n",
                  N, (unsigned) MSGLEN, (unsigned long long) ED_CORPUS_ROUND,
                  (unsigned long long) ED_CORPUS_SET_ID);
    Serial.printf("build:  %s, vendored arm = %s\n", LC_OPT_NAME, VENDORED_NAME);
    Serial.printf("heap:   %u free\n", (unsigned) ESP.getFreeHeap());

    select_records();
#ifdef LC_ED25519_PRECOMP
    Serial.printf("tables: %u authorities in checkpoint set %llu, %u of %u "
                  "corpus signers have one\n",
                  (unsigned) CHECKPOINT_AUTHORITIES,
                  (unsigned long long) CHECKPOINT_SET_ID, NSEL, N);
#else
    Serial.println("tables: none in this build");
#endif
    Serial.printf("timed:  %u records, the same ones for every arm\n\n", NSEL);
    if (NSEL == 0) {
        Serial.println("!! no records to time - the corpus and the checkpoint set "
                       "share no signers at all, which means one of them is wrong");
        Serial.println("=== done ===");
        return;
    }

#ifdef LC_FE25519_ASM
    /* Chunked, and loud about it. Two things can go wrong here and they look
     * identical from a serial log that just stops: the assembly can fault, or
     * the run can starve the idle task and take a watchdog reset. Printing per
     * chunk and yielding between them separates the two - a fault dies in the
     * first chunk, a watchdog cannot happen at all. */
    Serial.println("-- fe25519 assembly against the C reference --");
    fe_smoke();
    uint32_t t_dt = millis(), bad = 0, done = 0;
    const uint32_t CHUNK = 500, TOTAL = 20000;
    Serial.print("  ");
    for (uint32_t i = 0; i < TOTAL; i += CHUNK) {
        bad += lc_fe25519_difftest(CHUNK, 0x5eed1234u + i);
        done += CHUNK;
        Serial.print('.'); Serial.flush();
        vTaskDelay(1);
    }
    Serial.printf("\n%u cases (x3 for the two aliasings), %u mismatches  (%u ms)\n\n",
                  done, bad, (unsigned) (millis() - t_dt));
    if (bad) {
        Serial.println("!! the assembly does not match the C - not timing anything");
        Serial.println("=== done ===");
        return;
    }
#endif

#ifdef LC_FE25519_ASM
    Serial.println("-- the field kernel on its own --");
    fe_kernel_bench();
    Serial.println();
#endif

    Serial.println("-- where a verification's time goes --");
    {
        static const char *NAME[] = {
            "input screening", "SHA-512 (117 B)", "sc25519_reduce",
            "decompress A", "build Ai[8] table", "double scalarmult (incl. table)",
            "tobytes + compare", "WHOLE VERIFICATION",
        };
        /* Iteration counts differ per phase so each timed region is long enough
         * to swamp the timer, and short enough not to starve the idle task. */
        static const uint32_t IT[] = { 2000, 2000, 20000, 500, 2000, 100, 5000, 100 };
        double us[8];
        for (int p = 0; p < 8; p++) {
            int64_t t0 = esp_timer_get_time();
            uint32_t sink = lc_prof_phase(p, ED_CORPUS_PK[0], ED_CORPUS_SIG[0],
                                          MSG, MSGLEN, IT[p]);
            us[p] = (double) (esp_timer_get_time() - t0) / IT[p];
            (void) sink;
            vTaskDelay(1);
        }
        for (int p = 0; p < 8; p++)
            Serial.printf("  %-32s %8.1f us   %5.1f%%\n", NAME[p], us[p],
                          100.0 * us[p] / us[7]);
        /* The two phases that depend only on the public key. 600 authorities,
         * fixed for an era, recomputed on every one of 403 signatures. */
        Serial.printf("  %-32s %8.1f us   %5.1f%%  <- cacheable per authority\n",
                      "decompress + table, together", us[3] + us[4],
                      100.0 * (us[3] + us[4]) / us[7]);
    }
    Serial.println();

    Serial.println("-- does the vendored verifier accept exactly what libsodium accepts? --");
    uint32_t t0 = millis();
    agreement();
    Serial.printf("%u checks, %u disagreements  (%u ms)\n\n", checked, wrong,
                  (unsigned) (millis() - t0));
    if (wrong) {
        Serial.println("!! disagreement - not timing, the result would be meaningless");
        Serial.println("=== done ===");
        return;
    }

#ifdef LC_ED25519_PRECOMP
    /* The tables in flash, against the same prebuilt libsodium.
     *
     * test/run_pre.sh already checks the generated tables against ref10's own
     * arithmetic on the host, over all 600 authorities and 1,860 verification
     * inputs. What only the board can answer is whether the bytes that ended up
     * in the linked image are those tables - a truncated array, a stale
     * regeneration or a linker script surprise all look like correct source. So
     * this is deliberately not a second copy of the host suite: it reads the
     * real records through the real pointers, and it checks that the table is
     * load-bearing by handing one verification the wrong authority's. */
    Serial.println("-- the tables in flash --");
    {
        uint32_t n = 0, bad = 0;
        for (unsigned i = 0; i < NSEL; i++) {
            unsigned r = SEL[i];
            int a = lc_ed25519_verify(ED_CORPUS_SIG[r], MSG, MSGLEN, ED_CORPUS_PK[r]);
            int b = v_table(ED_CORPUS_SIG[r], MSG, MSGLEN, ED_CORPUS_PK[r], SEL_TAB[i]);
            n++;
            if (a != b || !a) {
                bad++;
                if (bad <= 8) Serial.printf("  WRONG [corpus %u] prebuilt=%d table=%d\n", r, a, b);
            }
            if ((i & 15) == 15) vTaskDelay(1);
        }
        uint8_t sig[64];
        for (unsigned b2 = 0; b2 < 512; b2++) {
            memcpy(sig, ED_CORPUS_SIG[SEL[0]], 64);
            sig[b2 >> 3] ^= (uint8_t) (1u << (b2 & 7));
            int a = lc_ed25519_verify(sig, MSG, MSGLEN, ED_CORPUS_PK[SEL[0]]);
            int c = v_table(sig, MSG, MSGLEN, ED_CORPUS_PK[SEL[0]], SEL_TAB[0]);
            n++;
            if (a != c) { bad++; if (bad <= 8) Serial.printf("  WRONG [flip %u]\n", b2); }
            if ((b2 & 15) == 15) vTaskDelay(1);
        }
        /* Another authority's table must reject a signature this one signed. */
        unsigned other = (NSEL > 1) ? 1 : 0;
        int wrongtab = v_table(ED_CORPUS_SIG[SEL[0]], MSG, MSGLEN,
                               ED_CORPUS_PK[SEL[0]], SEL_TAB[other]);
        n++;
        if (wrongtab) { bad++; Serial.println("  WRONG: another authority's table ACCEPTED"); }

        Serial.printf("%u checks, %u disagreements  (the corpus, 512 signature "
                      "bit flips, one wrong table)\n\n", n, bad);
        if (bad) {
            Serial.println("!! the tables in this image are not the tables the host "
                           "tests checked - not timing");
            Serial.println("=== done ===");
            return;
        }
    }
#endif

    Serial.println("-- timing, interleaved --");
    int64_t p1 = 0, v1 = 0, t1 = 0, pw = 0, vw = 0, tw = 0;
    int64_t p0us = 0, p1us = 0, v0us = 0, v1us = 0, t0us = 0, t1us = 0;

    for (int r = 0; r < ROUNDS; r++) {
        uint32_t ok;
        int64_t a0, a1;

        int64_t a = time_one_core(v_prebuilt, &ok);
        if (ok != NSEL) Serial.printf("  !! prebuilt one core: %u of %u ok\n", ok, NSEL);
        int64_t b = time_one_core(v_vendored, &ok);
        if (ok != NSEL) Serial.printf("  !! vendored one core: %u of %u ok\n", ok, NSEL);

        int64_t c = time_two_cores(v_prebuilt, &ok, &a0, &a1);
        if (ok != NSEL) Serial.printf("  !! prebuilt two cores: %u of %u ok\n", ok, NSEL);
        p0us += a0; p1us += a1;
        int64_t d = time_two_cores(v_vendored, &ok, &a0, &a1);
        if (ok != NSEL) Serial.printf("  !! vendored two cores: %u of %u ok\n", ok, NSEL);
        v0us += a0; v1us += a1;

        int64_t e = 0, g = 0;
#ifdef LC_ED25519_PRECOMP
        e = time_one_core(v_table, &ok);
        if (ok != NSEL) Serial.printf("  !! table one core: %u of %u ok\n", ok, NSEL);
        g = time_two_cores(v_table, &ok, &a0, &a1);
        if (ok != NSEL) Serial.printf("  !! table two cores: %u of %u ok\n", ok, NSEL);
        t0us += a0; t1us += a1;
#endif

        p1 += a; v1 += b; t1 += e; pw += c; vw += d; tw += g;
        Serial.printf("round %d  1-core: prebuilt %6.0f  %s %6.0f  +tables %6.0f | "
                      "2-core: prebuilt %6.0f  %s %6.0f  +tables %6.0f   (ms)\n",
                      r + 1, a / 1000.0, VENDORED_NAME, b / 1000.0, e / 1000.0,
                      c / 1000.0, VENDORED_NAME, d / 1000.0, g / 1000.0);
    }

    double p1ms = (double) p1 / ROUNDS / 1000.0;
    double v1ms = (double) v1 / ROUNDS / 1000.0;
    double t1ms = (double) t1 / ROUNDS / 1000.0;
    double pwms = (double) pw / ROUNDS / 1000.0;
    double vwms = (double) vw / ROUNDS / 1000.0;
    double twms = (double) tw / ROUNDS / 1000.0;

    Serial.printf("\n=== summary: %u signatures, per-signature verification ===\n", NSEL);
    Serial.printf("                            wall      ms/sig   vs 1-core prebuilt\n");
    Serial.printf("one core,  prebuilt -Os   %7.2f s   %6.3f     1.00x\n",
                  p1ms / 1000.0, p1ms / NSEL);
    Serial.printf("one core,  %-14s %7.2f s   %6.3f     %.2fx\n",
                  VENDORED_NAME, v1ms / 1000.0, v1ms / NSEL, p1ms / v1ms);
    Serial.printf("two cores, prebuilt -Os   %7.2f s   %6.3f     %.2fx\n",
                  pwms / 1000.0, pwms / NSEL, p1ms / pwms);
    Serial.printf("two cores, %-14s %7.2f s   %6.3f     %.2fx\n",
                  VENDORED_NAME, vwms / 1000.0, vwms / NSEL, p1ms / vwms);
#ifdef LC_ED25519_PRECOMP
    Serial.printf("one core,  +tables       %7.2f s   %6.3f     %.2fx\n",
                  t1ms / 1000.0, t1ms / NSEL, p1ms / t1ms);
    Serial.printf("two cores, +tables       %7.2f s   %6.3f     %.2fx\n",
                  twms / 1000.0, twms / NSEL, p1ms / twms);

    /* The number this whole change is about, and the one to compare against
     * E10's predicted 9.4%: the tables against the same verifier without them,
     * in the same image, so instruction-cache layout cancels. */
    Serial.printf("\ntables vs the same verifier without them: %.3fx one core, "
                  "%.3fx two cores  (%.1f%% and %.1f%% off)\n",
                  v1ms / t1ms, vwms / twms,
                  100.0 * (1.0 - t1ms / v1ms), 100.0 * (1.0 - twms / vwms));
#endif

    /* The number that says whether the two cores actually got two cores' worth
     * of machine. Busy time per core against the single-core pass over the same
     * count: anything above 1.00 is contention, most plausibly the shared
     * instruction cache, and it is the reason two cores is not exactly 2x. */
    Serial.println("\n=== scaling ===");
    Serial.printf("prebuilt: core0 busy %6.0f ms, core1 busy %6.0f ms, wall %6.0f ms"
                  "  -> parallel efficiency %.3f, per-core slowdown %.3f\n",
                  p0us / (double) ROUNDS / 1000.0, p1us / (double) ROUNDS / 1000.0, pwms,
                  p1ms / pwms / 2.0,
                  ((p0us + p1us) / (double) ROUNDS / 1000.0) / p1ms);
    Serial.printf("%-9s core0 busy %6.0f ms, core1 busy %6.0f ms, wall %6.0f ms"
                  "  -> parallel efficiency %.3f, per-core slowdown %.3f\n",
                  VENDORED_NAME, v0us / (double) ROUNDS / 1000.0, v1us / (double) ROUNDS / 1000.0, vwms,
                  v1ms / vwms / 2.0,
                  ((v0us + v1us) / (double) ROUNDS / 1000.0) / v1ms);
#ifdef LC_ED25519_PRECOMP
    Serial.printf("+tables:  core0 busy %6.0f ms, core1 busy %6.0f ms, wall %6.0f ms"
                  "  -> parallel efficiency %.3f, per-core slowdown %.3f\n",
                  t0us / (double) ROUNDS / 1000.0, t1us / (double) ROUNDS / 1000.0, twms,
                  t1ms / twms / 2.0,
                  ((t0us + t1us) / (double) ROUNDS / 1000.0) / t1ms);
#endif

    Serial.printf("\nheap %u free\n", (unsigned) ESP.getFreeHeap());
    Serial.println("=== done ===");
}

void loop() { delay(1000); }
