#include "fmt.h"
#include <stdio.h>

static size_t int_digits(const char *s)
{
    size_t n = 0;
    while (s[n] >= '0' && s[n] <= '9') n++;
    return n;
}

void fmt_group(const char *digits, char *out, size_t cap)
{
    if (!cap) return;

    size_t n = int_digits(digits), o = 0;
    for (size_t i = 0; i < n && o + 1 < cap; i++) {
        if (i && (n - i) % 3 == 0) out[o++] = ',';
        if (o + 1 < cap) out[o++] = digits[i];
    }

    /* Fractional part and any trailing unit, verbatim. */
    for (const char *p = digits + n; *p && o + 1 < cap; p++) out[o++] = *p;
    out[o] = 0;
}

const char *fmt_num(uint64_t v)
{
    static char slot[8][FMT_NUM_MAX];
    static unsigned next;

    char plain[24];
    snprintf(plain, sizeof plain, "%llu", (unsigned long long)v);

    char *dst = slot[next++ % 8];
    fmt_group(plain, dst, FMT_NUM_MAX);
    return dst;
}

void fmt_compact(const char *digits, char *out, size_t cap)
{
    static const struct { size_t min_digits; char suffix; } SCALE[] = {
        { 13, 'T' }, { 10, 'B' }, { 7, 'M' }, { 4, 'K' },
    };
    size_t n = int_digits(digits);

    for (size_t i = 0; i < sizeof SCALE / sizeof *SCALE; i++) {
        if (n < SCALE[i].min_digits) continue;
        size_t whole = n - (SCALE[i].min_digits - 1);   /* digits before the point */
        snprintf(out, cap, "%.*s.%.2s%c", (int)whole, digits, digits + whole,
                 SCALE[i].suffix);
        return;
    }

    /* Below a thousand there is nothing to shorten; keep two decimals if the
     * value has them, so a small balance still reads as a balance. */
    const char *frac = digits[n] == '.' ? digits + n + 1 : "";
    if (*frac) snprintf(out, cap, "%.*s.%.2s", (int)n, digits, frac);
    else       snprintf(out, cap, "%.*s", (int)n, digits);
}
