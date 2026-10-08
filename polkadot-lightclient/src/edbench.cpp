/* Is the prebuilt libsodium leaving ed25519 speed on the table?
 *
 * The verification of a GRANDPA justification is 401 signatures and, since the
 * transport work was overlapped, essentially the whole cycle. All of it runs
 * inside liblibsodium.a, which Espressif ships prebuilt at -Os with the field
 * arithmetic out of line - fe25519_mul is a 3 KB call in the innermost loop.
 * lib/ed25519_fast is the same upstream ref10 code compiled as a single
 * translation unit at -O3 -fwhole-program, which is free to inline it.
 *
 * This measures both on the same board against the same vectors, with no
 * network in the picture, and checks they agree on every input first: a faster
 * verifier that accepts a different set of signatures is not a faster verifier,
 * it is a consensus bug. Correctness is also covered on the host against the
 * system libsodium - see test/run.sh. */

#include <Arduino.h>
#include <esp_timer.h>

#include "ed25519_fast.h"
#include "lc_crypto.h"

SET_LOOP_TASK_STACK_SIZE(16384);

static const uint32_t N_SIGS = 300;     /* timed verifications per arm */
static const uint32_t BLOCK  = 25;      /* verifies between watchdog yields */
static const int      ROUNDS = 4;       /* interleaved A/B rounds */

#include "../test/edbench_vectors.inc"

/* ---------- do the two implementations agree? ---------- */

static uint32_t checked, disagreed;

static void agree(const char *what, const uint8_t *sig, const uint8_t *m, size_t mlen,
                  const uint8_t *pk)
{
    int ref  = lc_ed25519_verify(sig, m, mlen, pk);
    int fast = lc_ed25519_verify_fast(sig, m, mlen, pk);
    checked++;
    if (ref != fast) {
        disagreed++;
        if (disagreed <= 8)
            Serial.printf("  DISAGREE [%s] mlen=%u  prebuilt=%d  fast=%d\n",
                          what, (unsigned)mlen, ref, fast);
    }
}

static void agreement_suite()
{
    uint8_t sig[64], pk[32], m[64];

    agree("valid", VEC_SIG, VEC_MSG, sizeof VEC_MSG, VEC_PK);

    /* every single-bit flip of the signature, the key and the message */
    for (unsigned i = 0; i < 64 * 8; i++) {
        memcpy(sig, VEC_SIG, 64);
        sig[i / 8] ^= 1u << (i % 8);
        agree("sig-bitflip", sig, VEC_MSG, sizeof VEC_MSG, VEC_PK);
    }
    for (unsigned i = 0; i < 32 * 8; i++) {
        memcpy(pk, VEC_PK, 32);
        pk[i / 8] ^= 1u << (i % 8);
        agree("pk-bitflip", VEC_SIG, VEC_MSG, sizeof VEC_MSG, pk);
    }
    for (unsigned i = 0; i < sizeof VEC_MSG * 8; i++) {
        memcpy(m, VEC_MSG, sizeof VEC_MSG);
        m[i / 8] ^= 1u << (i % 8);
        agree("msg-bitflip", VEC_SIG, m, sizeof VEC_MSG, VEC_PK);
    }

    /* the structurally hostile inputs: small-order points and non-canonical
     * encodings, where a verifier drifts from consensus rather than failing */
    for (unsigned i = 0; i < N_EDGE; i++) {
        agree("edge-pk", VEC_SIG, VEC_MSG, sizeof VEC_MSG, EDGE[i]);
        memcpy(sig, VEC_SIG, 64); memcpy(sig, EDGE[i], 32);
        agree("edge-R", sig, VEC_MSG, sizeof VEC_MSG, VEC_PK);
        memcpy(sig, VEC_SIG, 64); memcpy(sig + 32, EDGE[i], 32);
        agree("edge-S", sig, VEC_MSG, sizeof VEC_MSG, VEC_PK);
    }

    /* pseudo-random garbage, deterministic so a failure is reproducible */
    uint32_t x = 0x9e3779b9u;
    for (unsigned i = 0; i < 400; i++) {
        for (unsigned j = 0; j < 64; j++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; sig[j] = (uint8_t)x; }
        for (unsigned j = 0; j < 32; j++) { x ^= x << 13; x ^= x >> 17; x ^= x << 5; pk[j]  = (uint8_t)x; }
        agree("garbage", sig, VEC_MSG, sizeof VEC_MSG, pk);
    }
}

/* ---------- timing ---------- */

typedef int (*verify_fn)(const uint8_t *, const uint8_t *, size_t, const uint8_t *);

static int call_ref(const uint8_t *s, const uint8_t *m, size_t l, const uint8_t *p)
{ return lc_ed25519_verify(s, m, l, p); }
static int call_fast(const uint8_t *s, const uint8_t *m, size_t l, const uint8_t *p)
{ return lc_ed25519_verify_fast(s, m, l, p); }

/* Returns busy microseconds for n verifications, excluding watchdog yields. */
static int64_t time_arm(verify_fn f, uint32_t n, uint32_t *ok_out)
{
    int64_t acc = 0;
    uint32_t ok = 0;
    for (uint32_t i = 0; i < n; i += BLOCK) {
        uint32_t k = (n - i < BLOCK) ? n - i : BLOCK;
        int64_t t0 = esp_timer_get_time();
        for (uint32_t j = 0; j < k; j++)
            ok += f(VEC_SIG, VEC_MSG, sizeof VEC_MSG, VEC_PK);
        acc += esp_timer_get_time() - t0;
        vTaskDelay(1);
    }
    *ok_out = ok;
    return acc;
}

void setup()
{
    Serial.begin(115200);
    /* RFC2217 bridges take several seconds to reconnect after esptool closes
     * its session. Keep this outside every measured region. */
    delay(10000);
    Serial.println("\n\n=== ed25519: prebuilt -Os vs vendored -O3 ===");
    Serial.printf("cpu %u MHz, %s\n", (unsigned)getCpuFrequencyMhz(), ESP.getSdkVersion());
    Serial.printf("payload %u bytes (GRANDPA localized precommit)\n\n", (unsigned)sizeof VEC_MSG);

    Serial.println("-- do they agree? --");
    uint32_t t0 = millis();
    agreement_suite();
    Serial.printf("%u inputs, %u disagreements  (%u ms)\n\n",
                  checked, disagreed, (unsigned)(millis() - t0));
    if (disagreed) {
        Serial.println("!! implementations differ - not measuring, the result would be meaningless");
        return;
    }

    Serial.println("-- timing, interleaved --");
    int64_t ref_tot = 0, fast_tot = 0;
    uint32_t ref_n = 0, fast_n = 0;
    for (int r = 0; r < ROUNDS; r++) {
        uint32_t ok_a = 0, ok_b = 0;
        int64_t a = time_arm(call_ref,  N_SIGS, &ok_a);
        int64_t b = time_arm(call_fast, N_SIGS, &ok_b);
        Serial.printf("round %d  prebuilt -Os %6.3f ms/sig (%u ok) | vendored -O3 %6.3f ms/sig (%u ok)"
                      "  -> %.2fx\n",
                      r + 1, (double)a / N_SIGS / 1000.0, ok_a,
                      (double)b / N_SIGS / 1000.0, ok_b, (double)a / (double)b);
        ref_tot += a; fast_tot += b; ref_n += N_SIGS; fast_n += N_SIGS;
    }

    double ref_ms  = (double)ref_tot  / ref_n  / 1000.0;
    double fast_ms = (double)fast_tot / fast_n / 1000.0;
    Serial.println("\n=== summary ===");
    Serial.printf("prebuilt -Os   %6.3f ms/sig\n", ref_ms);
    Serial.printf("vendored -O3   %6.3f ms/sig   (%.2fx, %+.3f ms/sig)\n",
                  fast_ms, ref_ms / fast_ms, fast_ms - ref_ms);
    Serial.printf("401 signatures: %6.2f s -> %6.2f s single core, saving %.2f s\n",
                  401 * ref_ms / 1000.0, 401 * fast_ms / 1000.0,
                  401 * (ref_ms - fast_ms) / 1000.0);
    Serial.printf("                %6.2f s -> %6.2f s across two cores\n",
                  401 * ref_ms / 2000.0, 401 * fast_ms / 2000.0);
    Serial.printf("heap %u free\n", (unsigned)ESP.getFreeHeap());
    Serial.println("=== done ===");
}

void loop() { delay(1000); }
