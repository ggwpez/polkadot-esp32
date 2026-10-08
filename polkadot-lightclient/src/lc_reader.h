/* A pull-based byte source.
 *
 * The GRANDPA verifier consumes ~53 KB of justification but never holds more
 * than one 132-byte precommit at a time, so it reads through this interface
 * instead of taking a buffer. On the device the source is hex-decoded bytes
 * arriving over TLS; in tests it is memory. The verification code cannot tell
 * the difference, which is the point. */
#ifndef LC_READER_H
#define LC_READER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lc_reader {
    /* Fills dst with exactly n bytes. Returns 1 on success, 0 on error or EOF.
     * A short read is an error: the caller always knows how much it needs. */
    int (*read)(struct lc_reader *self, uint8_t *dst, size_t n);
    void *ctx;
} lc_reader;

static inline int lc_read(lc_reader *r, uint8_t *dst, size_t n)
{
    return r->read(r, dst, n);
}

/* Discards n bytes. */
int lc_skip(lc_reader *r, size_t n);

/* SCALE primitives over a stream. Return 0 and leave *out untouched on error. */
int lc_read_u32(lc_reader *r, uint32_t *out);
int lc_read_u64(lc_reader *r, uint64_t *out);
int lc_read_compact(lc_reader *r, uint64_t *out);

/* Memory-backed source, for tests and for data already buffered. */
typedef struct {
    lc_reader base;
    const uint8_t *buf;
    size_t len, pos;
} lc_mem_reader;

void lc_mem_reader_init(lc_mem_reader *m, const uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif
#endif
