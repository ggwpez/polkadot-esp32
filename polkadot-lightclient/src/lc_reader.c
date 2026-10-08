#include "lc_reader.h"
#include <string.h>

int lc_skip(lc_reader *r, size_t n)
{
    uint8_t scratch[64];
    while (n) {
        size_t chunk = n < sizeof scratch ? n : sizeof scratch;
        if (!lc_read(r, scratch, chunk)) return 0;
        n -= chunk;
    }
    return 1;
}

int lc_read_u32(lc_reader *r, uint32_t *out)
{
    uint8_t b[4];
    if (!lc_read(r, b, 4)) return 0;
    *out = (uint32_t)b[0] | (uint32_t)b[1] << 8 | (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
    return 1;
}

int lc_read_u64(lc_reader *r, uint64_t *out)
{
    uint8_t b[8];
    if (!lc_read(r, b, 8)) return 0;
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | b[i];
    *out = v;
    return 1;
}

int lc_read_compact(lc_reader *r, uint64_t *out)
{
    uint8_t b0;
    if (!lc_read(r, &b0, 1)) return 0;
    switch (b0 & 3) {
    case 0:
        *out = b0 >> 2;
        return 1;
    case 1: {
        uint8_t b1;
        if (!lc_read(r, &b1, 1)) return 0;
        *out = ((uint32_t)b0 | (uint32_t)b1 << 8) >> 2;
        return 1;
    }
    case 2: {
        uint8_t rest[3];
        if (!lc_read(r, rest, 3)) return 0;
        *out = ((uint32_t)b0 | (uint32_t)rest[0] << 8 |
                (uint32_t)rest[1] << 16 | (uint32_t)rest[2] << 24) >> 2;
        return 1;
    }
    default: {
        size_t n = (size_t)(b0 >> 2) + 4;
        if (n > 8) return 0;
        uint8_t rest[8];
        if (!lc_read(r, rest, n)) return 0;
        uint64_t v = 0;
        for (size_t i = n; i-- > 0;) v = v << 8 | rest[i];
        *out = v;
        return 1;
    }
    }
}

static int mem_read(lc_reader *self, uint8_t *dst, size_t n)
{
    lc_mem_reader *m = (lc_mem_reader *)self->ctx;
    if (n > m->len - m->pos) return 0;
    memcpy(dst, m->buf + m->pos, n);
    m->pos += n;
    return 1;
}

void lc_mem_reader_init(lc_mem_reader *m, const uint8_t *buf, size_t len)
{
    m->base.read = mem_read;
    m->base.ctx = m;
    m->buf = buf;
    m->len = len;
    m->pos = 0;
}
