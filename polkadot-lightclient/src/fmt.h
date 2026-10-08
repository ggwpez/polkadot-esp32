/* Number formatting for the two things that display them: the serial log and
 * the 21-column panel.
 *
 * Block numbers, byte counts and balances are all large enough that ungrouped
 * digits have to be counted rather than read, and the one number a passer-by
 * actually wants - the total issuance - is 21 significant digits wide in
 * planck. Neither is a correctness problem, which is exactly why it is worth
 * fixing here rather than in the code that proves them. */
#ifndef FMT_H
#define FMT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Longest result: 20 digits, 6 separators, NUL. */
#define FMT_NUM_MAX 32

/* Copies `digits` into `out` with thousands separators in the integer part. A
 * fractional part, if there is one, is passed through untouched: grouping after
 * the point is a different convention and Polkadot balances are not printed
 * that way anywhere else. Anything that is not a digit or the first '.' ends
 * the number and is copied verbatim, so "1234 DOT" groups correctly. */
void fmt_group(const char *digits, char *out, size_t cap);

/* As fmt_group, for an integer, into one of a few rotating internal buffers so
 * that several can appear in a single printf:
 *
 *     Serial.printf("%s of %s\n", fmt_num(a), fmt_num(b));
 *
 * Not reentrant, and deliberately so - it exists to keep call sites readable.
 * Only the loop task formats numbers; the prefetch and signature tasks never
 * print. Eight live results at once; the widest call site uses six. */
const char *fmt_num(uint64_t v);

/* A magnitude the eye can take in at a glance, two decimals and a suffix:
 * "1712345678.1234567890" -> "1.71B". Truncates rather than rounds, so the
 * short form never reads higher than the proven value.
 *
 * Used only where the full figure does not fit and is also printed in full
 * somewhere else. */
void fmt_compact(const char *digits, char *out, size_t cap);

#ifdef __cplusplus
}
#endif
#endif
