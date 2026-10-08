/* SCALE codec - only the parts the light client needs.
 *
 * Every read is bounds-checked and sets a sticky error flag, so a hostile RPC
 * cannot walk us off the end of a buffer. Callers may run a whole decode and
 * check scale_ok() once at the end. */
#ifndef SCALE_H
#define SCALE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
    int err;            /* sticky: once set, every subsequent read is a no-op */
} scale_rd;

void scale_init(scale_rd *r, const uint8_t *buf, size_t len);
static inline int scale_ok(const scale_rd *r) { return !r->err; }
static inline size_t scale_remaining(const scale_rd *r)
{
    return r->err ? 0 : r->len - r->pos;
}

/* Returns a pointer into the buffer, or NULL (and sets err) if short. */
const uint8_t *scale_take(scale_rd *r, size_t n);
uint8_t  scale_u8(scale_rd *r);
uint32_t scale_u32(scale_rd *r);
uint64_t scale_u64(scale_rd *r);
uint64_t scale_compact(scale_rd *r);

/* Length-prefixed byte vector. Returns a pointer into the buffer and writes the
 * length to *out_len. NULL on error. */
const uint8_t *scale_vec_bytes(scale_rd *r, size_t *out_len);

/* Little-endian unsigned integer of `len` bytes, as stored by most storage
 * items. Values longer than 16 bytes, or that do not fit in 128 bits, set err. */
typedef struct { uint64_t lo, hi; } scale_u128;
scale_u128 scale_le_u128(const uint8_t *b, size_t len, int *err);

/* Compact-encodes `v` into `out` (max 5 bytes for a u32). Returns bytes written. */
size_t scale_encode_compact(uint8_t *out, uint32_t v);

/* ---- block header ---- */

typedef struct {
    uint8_t parent[32];
    uint32_t number;
    uint8_t state_root[32];
    uint8_t extrinsics_root[32];
    size_t encoded_len;     /* bytes consumed - a header is variable length */
} lc_header;

/* Decodes a SCALE block header, including walking the digest so encoded_len is
 * exact. Returns 1 on success. */
int scale_decode_header(const uint8_t *buf, size_t len, lc_header *out);

#ifdef __cplusplus
}
#endif
#endif
