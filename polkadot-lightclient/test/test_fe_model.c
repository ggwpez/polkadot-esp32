/* Does tools/gen_fe25519_mul.py's term table reproduce ref10's fe25519_mul?
 *
 * The generator emits Xtensa assembly from a product table and carry chain
 * pasted out of ref10's header. A transposed index in that table would be a
 * consensus bug visible on roughly one input in 2^30 - which is to say, never
 * in a corpus test and eventually in production. This runs the SAME table as
 * portable C against ref10 itself, on the host, in a couple of seconds.
 *
 * It tests the table, not the assembly: instruction encoding is checked on the
 * device by lc_fe25519_difftest, which env:mcbench_asm runs before it will
 * report a timing. See EXPERIMENTS.md E8.
 *
 *   sh test/run_fe.sh
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "vendor/private/ed25519_ref10.h"
void fe25519_mul_model(int32_t h[10], const int32_t f[10], const int32_t g[10]);

static uint64_t st = 0x243f6a8885a308d3ull;
static uint32_t r32(void){ st ^= st<<13; st ^= st>>7; st ^= st<<17; return (uint32_t)(st>>32); }

/* ref10's documented precondition: |f_i| <= 1.65*2^26 on even limbs,
 * 1.65*2^25 on odd. Sample the whole range including both extremes. */
static void rnd(int32_t v[10], int extreme)
{
    for (int i = 0; i < 10; i++) {
        int32_t lim = (int32_t)(1.65 * (i % 2 == 0 ? (1<<26) : (1<<25)));
        if (extreme) v[i] = (r32() & 1) ? lim : -lim;
        else         v[i] = (int32_t)(r32() % (uint32_t)(2*lim)) - lim;
    }
}

int main(void)
{
    int32_t f[10], g[10], a[10], b[10];
    long n = 0, bad = 0;
    for (long i = 0; i < 2000000; i++) {
        int ex = (i % 8 == 0);
        rnd(f, ex); rnd(g, ex);
        if (i < 4) { memset(f,0,sizeof f); memset(g,0,sizeof g); if(i&1) f[0]=1; if(i&2) g[0]=1; }
        fe25519_mul(a, f, g);
        fe25519_mul_model(b, f, g);
        n++;
        if (memcmp(a, b, sizeof a)) {
            if (++bad <= 3) {
                printf("MISMATCH at %ld\n  ref  ", i);
                for (int k=0;k<10;k++) printf("%d ", a[k]);
                printf("\n  model");
                for (int k=0;k<10;k++) printf(" %d", b[k]);
                printf("\n");
            }
        }
    }
    /* Aliasing: the C API allows h == f and h == g. */
    for (long i = 0; i < 100000; i++) {
        rnd(f, 0); memcpy(g, f, sizeof f); memcpy(a, f, sizeof f); memcpy(b, f, sizeof f);
        fe25519_mul(a, a, g); fe25519_mul_model(b, b, g); n++;
        if (memcmp(a, b, sizeof a)) bad++;
        rnd(g, 0); memcpy(a, g, sizeof g); memcpy(b, g, sizeof g);
        fe25519_mul(a, f, a); fe25519_mul_model(b, f, b); n++;
        if (memcmp(a, b, sizeof a)) bad++;
    }
    printf("%ld cases, %ld mismatches\n", n, bad);
    return bad != 0;
}
