#include "ws_frame.h"

#include <string.h>

/* A message that never ends is a peer wedging the device, not a large payload.
 * The largest thing this client is ever sent is a ~110 KB justification, so a
 * megabyte is generous by an order of magnitude and still bounded. */
#define WS_DRAIN_MAX (1024u * 1024u)

#define OP_CONT  0x0
#define OP_TEXT  0x1
#define OP_BIN   0x2
#define OP_CLOSE 0x8
#define OP_PING  0x9
#define OP_PONG  0xA

void ws_init(ws_conn *c, ws_src_fn src, ws_sink_fn sink, void *ctx, uint32_t seed)
{
    memset(c, 0, sizeof *c);
    c->src  = src;
    c->sink = sink;
    c->ctx  = ctx;
    c->rng  = seed ? seed : 0x9e3779b9u;
}

static uint32_t next_rand(ws_conn *c)
{
    uint32_t x = c->rng;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return c->rng = x;
}

/* A source that has stopped producing is a dead connection, not a short read:
 * there is no framing above this to resynchronise on. */
static int rd(ws_conn *c)
{
    int v = c->src(c->ctx);
    if (v < 0) c->closed = 1;
    return v;
}

static int send_frame(ws_conn *c, uint8_t opcode, uint8_t *buf, size_t n)
{
    uint8_t h[14];
    size_t hl = 0;
    uint32_t k;
    uint8_t key[4];
    size_t i;

    h[hl++] = (uint8_t)(0x80 | opcode);           /* FIN, no RSV */
    if (n < 126) {
        h[hl++] = (uint8_t)(0x80 | n);
    } else if (n < 65536) {
        h[hl++] = 0x80 | 126;
        h[hl++] = (uint8_t)(n >> 8);
        h[hl++] = (uint8_t)n;
    } else {
        h[hl++] = 0x80 | 127;
        for (i = 0; i < 8; i++) h[hl++] = (uint8_t)((uint64_t)n >> (8 * (7 - i)));
    }

    k = next_rand(c);
    key[0] = (uint8_t)(k >> 24); key[1] = (uint8_t)(k >> 16);
    key[2] = (uint8_t)(k >> 8);  key[3] = (uint8_t)k;
    memcpy(h + hl, key, 4);
    hl += 4;

    for (i = 0; i < n; i++) buf[i] ^= key[i & 3];

    if (!c->sink(c->ctx, h, hl)) return 0;
    return n == 0 || c->sink(c->ctx, buf, n);
}

/* Control frames must be complete in one frame and at most 125 bytes, so the
 * whole payload can be held on the stack - the only place in this file that
 * buffers anything. A ping is answered from here, which means a pong can be
 * written in the middle of reading somebody else's message. That is legal and
 * required, and it is safe on the device because exactly one task owns the
 * socket at a time: loop() does not touch it while the prefetcher is streaming
 * a justification, and vice versa. */
static int handle_control(ws_conn *c, uint8_t opcode, uint8_t fin, uint64_t len)
{
    uint8_t pay[125];
    uint64_t i;

    if (!fin || len > 125) { c->failed = 1; return 0; }
    for (i = 0; i < len; i++) {
        int v = rd(c);
        if (v < 0) return 0;
        pay[i] = (uint8_t)v;
    }

    switch (opcode) {
    case OP_PING:
        return send_frame(c, OP_PONG, pay, (size_t)len);
    case OP_PONG:
        return 1;                       /* unsolicited pongs are allowed */
    case OP_CLOSE:
        c->closed = 1;
        return 0;
    default:
        c->failed = 1;
        return 0;
    }
}

/* Reads frame headers until a data frame turns up, disposing of control frames
 * on the way. `continuation` says which opcode is expected: mid-message only a
 * continuation is legal, and between messages only a first fragment is - two
 * data messages may not interleave on one connection (RFC 6455 5.4), which is
 * what lets everything above this stay a linear byte stream. */
static int advance(ws_conn *c, int continuation)
{
    for (;;) {
        int b0, b1;
        uint8_t opcode, fin;
        uint64_t len;
        int i;

        if (c->closed || c->failed) return 0;

        b0 = rd(c); if (b0 < 0) return 0;
        b1 = rd(c); if (b1 < 0) return 0;

        /* No extensions were negotiated, so a reserved bit means the peer is
         * speaking a protocol we did not agree to. */
        if (b0 & 0x70) { c->failed = 1; return 0; }
        /* A server must not mask (RFC 6455 5.1). Accepting it anyway would mean
         * guessing at which side of the connection we are on. */
        if (b1 & 0x80) { c->failed = 1; return 0; }

        fin    = (uint8_t)((b0 & 0x80) != 0);
        opcode = (uint8_t)(b0 & 0x0f);
        len    = (uint64_t)(b1 & 0x7f);

        if (len == 126) {
            len = 0;
            for (i = 0; i < 2; i++) { int v = rd(c); if (v < 0) return 0; len = len << 8 | (uint64_t)v; }
        } else if (len == 127) {
            len = 0;
            for (i = 0; i < 8; i++) { int v = rd(c); if (v < 0) return 0; len = len << 8 | (uint64_t)v; }
            if (len >> 63) { c->failed = 1; return 0; }
        }

        if (opcode & 0x8) {
            if (!handle_control(c, opcode, fin, len)) return 0;
            continue;
        }

        if (continuation) {
            if (opcode != OP_CONT) { c->failed = 1; return 0; }
        } else {
            if (opcode != OP_TEXT && opcode != OP_BIN) { c->failed = 1; return 0; }
        }

        c->remaining = len;
        c->fin = fin;
        return 1;
    }
}

int ws_next_message(ws_conn *c)
{
    if (c->in_msg && !ws_drain_message(c)) return 0;
    if (!advance(c, 0)) return 0;
    c->in_msg = 1;
    return 1;
}

int ws_read_byte(ws_conn *c)
{
    int v;

    if (!c->in_msg) return -1;

    /* A zero-length fragment is legal, so this chases continuations rather than
     * assuming one frame carries at least one byte. */
    while (c->remaining == 0) {
        if (c->fin) { c->in_msg = 0; return -1; }
        if (!advance(c, 1)) { c->in_msg = 0; return -1; }
    }

    v = rd(c);
    if (v < 0) { c->in_msg = 0; return -1; }
    c->remaining--;
    return v;
}

int ws_drain_message(ws_conn *c)
{
    uint32_t n = 0;
    while (ws_read_byte(c) >= 0) {
        if (++n > WS_DRAIN_MAX) { c->failed = 1; return 0; }
    }
    return !c->failed && !c->closed;
}

int ws_send_text(ws_conn *c, uint8_t *buf, size_t n)
{
    if (c->closed || c->failed) return 0;
    return send_frame(c, OP_TEXT, buf, n);
}
