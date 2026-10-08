#include "scale.h"
#include <string.h>

void scale_init(scale_rd *r, const uint8_t *buf, size_t len)
{
    r->buf = buf; r->len = len; r->pos = 0; r->err = 0;
}

const uint8_t *scale_take(scale_rd *r, size_t n)
{
    if (r->err) return 0;
    if (n > r->len - r->pos) { r->err = 1; return 0; }   /* no overflow: pos <= len */
    const uint8_t *p = r->buf + r->pos;
    r->pos += n;
    return p;
}

uint8_t scale_u8(scale_rd *r)
{
    const uint8_t *p = scale_take(r, 1);
    return p ? p[0] : 0;
}

uint32_t scale_u32(scale_rd *r)
{
    const uint8_t *p = scale_take(r, 4);
    if (!p) return 0;
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

uint64_t scale_u64(scale_rd *r)
{
    const uint8_t *p = scale_take(r, 8);
    if (!p) return 0;
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = v << 8 | p[i];
    return v;
}

uint64_t scale_compact(scale_rd *r)
{
    if (r->err) return 0;
    if (r->pos >= r->len) { r->err = 1; return 0; }
    uint8_t b0 = r->buf[r->pos];
    switch (b0 & 3) {
    case 0:
        r->pos += 1;
        return b0 >> 2;
    case 1: {
        const uint8_t *p = scale_take(r, 2);
        if (!p) return 0;
        return ((uint32_t)p[0] | (uint32_t)p[1] << 8) >> 2;
    }
    case 2: {
        const uint8_t *p = scale_take(r, 4);
        if (!p) return 0;
        return ((uint32_t)p[0] | (uint32_t)p[1] << 8 |
                (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24) >> 2;
    }
    default: {
        size_t n = (size_t)(b0 >> 2) + 4;
        r->pos += 1;
        const uint8_t *p = scale_take(r, n);
        if (!p) return 0;
        if (n > 8) { r->err = 1; return 0; }   /* we never legitimately see these */
        uint64_t v = 0;
        for (size_t i = n; i-- > 0;) v = v << 8 | p[i];
        return v;
    }
    }
}

const uint8_t *scale_vec_bytes(scale_rd *r, size_t *out_len)
{
    uint64_t n = scale_compact(r);
    if (r->err) return 0;
    if (n > r->len - r->pos) { r->err = 1; return 0; }
    if (out_len) *out_len = (size_t)n;
    return scale_take(r, (size_t)n);
}

scale_u128 scale_le_u128(const uint8_t *b, size_t len, int *err)
{
    scale_u128 v = { 0, 0 };
    if (len > 16) { if (err) *err = 1; return v; }
    for (size_t i = 0; i < len; i++) {
        if (i < 8) v.lo |= (uint64_t)b[i] << (8 * i);
        else       v.hi |= (uint64_t)b[i] << (8 * (i - 8));
    }
    return v;
}

size_t scale_encode_compact(uint8_t *out, uint32_t v)
{
    if (v < 64) { out[0] = (uint8_t)(v << 2); return 1; }
    if (v < (1u << 14)) {
        uint32_t x = v << 2 | 1;
        out[0] = (uint8_t)x; out[1] = (uint8_t)(x >> 8);
        return 2;
    }
    if (v < (1u << 30)) {
        uint32_t x = v << 2 | 2;
        for (int i = 0; i < 4; i++) out[i] = (uint8_t)(x >> (8 * i));
        return 4;
    }
    out[0] = (4 - 4) << 2 | 3;                 /* big-integer mode, 4 bytes follow */
    for (int i = 0; i < 4; i++) out[1 + i] = (uint8_t)(v >> (8 * i));
    return 5;
}

int scale_decode_header(const uint8_t *buf, size_t len, lc_header *out)
{
    scale_rd r;
    scale_init(&r, buf, len);

    const uint8_t *p = scale_take(&r, 32);
    if (p) memcpy(out->parent, p, 32);

    uint64_t num = scale_compact(&r);
    if (num > 0xffffffffull) return 0;
    out->number = (uint32_t)num;

    p = scale_take(&r, 32);
    if (p) memcpy(out->state_root, p, 32);
    p = scale_take(&r, 32);
    if (p) memcpy(out->extrinsics_root, p, 32);

    uint64_t ndigest = scale_compact(&r);
    for (uint64_t i = 0; i < ndigest && scale_ok(&r); i++) {
        uint8_t t = scale_u8(&r);
        switch (t) {
        case 0:                                 /* Other(Vec<u8>) */
            scale_vec_bytes(&r, 0);
            break;
        case 4: case 5: case 6:                 /* Consensus / Seal / PreRuntime */
            scale_take(&r, 4);                  /* ConsensusEngineId */
            scale_vec_bytes(&r, 0);
            break;
        case 8:                                 /* RuntimeEnvironmentUpdated */
            break;
        default:
            r.err = 1;                          /* unknown digest -> refuse to guess */
            break;
        }
    }
    if (!scale_ok(&r)) return 0;
    out->encoded_len = r.pos;
    return 1;
}
