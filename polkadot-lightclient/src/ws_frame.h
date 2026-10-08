/* RFC 6455 framing, and nothing else.
 *
 * This file knows about frames. It does not know about sockets, TLS, HTTP or
 * JSON: bytes arrive through a callback and leave through another one. That is
 * deliberate. The framing layer is the part of a WebSocket that is easy to get
 * subtly wrong - fragmentation, the two extended length forms, a ping arriving
 * in the middle of somebody else's message - and it is the part the device
 * cannot exercise, because the endpoint sends no pings and never fragments.
 * Keeping it free of Arduino lets test/run_ws.sh drive every one of those cases
 * from a byte array on the host. transport.cpp supplies the socket.
 *
 * The interface is a byte at a time on purpose. A justification is 106 KB
 * against 94 KB of free heap, so no message may ever be assembled in memory -
 * which is also why no off-the-shelf WebSocket library can be used here. It
 * happens to be the shape RpcSession already wanted: ws_read_byte() drops in
 * where the HTTP chunked-encoding reader used to be, and everything above
 * getByte() is unchanged. */
#ifndef WS_FRAME_H
#define WS_FRAME_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One byte from the transport: 0..255, or -1 if the stream ended or stalled. */
typedef int (*ws_src_fn)(void *ctx);
/* Writes n bytes. All or nothing: 1 on success, 0 on failure. */
typedef int (*ws_sink_fn)(void *ctx, const uint8_t *buf, size_t n);

typedef struct {
    ws_src_fn  src;
    ws_sink_fn sink;
    void      *ctx;

    uint64_t remaining;   /* payload bytes left in the frame being consumed */
    uint8_t  in_msg;      /* a data message is open and not yet fully read */
    uint8_t  fin;         /* the frame being consumed carried FIN */
    uint8_t  closed;      /* the peer sent close, or went away */
    uint8_t  failed;      /* protocol error - the caller must drop the socket */
    uint32_t rng;         /* xorshift state, for mask keys */
} ws_conn;

/* `seed` only has to be non-zero. Masking is mandatory for a client, but its
 * unpredictability defends against cache-poisoning intermediaries, which cannot
 * exist inside the TLS tunnel this runs in. A counter would do; a weak PRNG
 * costs nothing and keeps the host test deterministic. */
void ws_init(ws_conn *c, ws_src_fn src, ws_sink_fn sink, void *ctx, uint32_t seed);

/* Advances to the first payload byte of the next data message, handling any
 * control frames on the way. Returns 1, or 0 on close or protocol error.
 * Any unread part of a previous message is discarded first. */
int ws_next_message(ws_conn *c);

/* One payload byte of the message in progress, or -1 at its end. Control frames
 * that arrive between fragments are handled here and stay invisible. */
int ws_read_byte(ws_conn *c);

/* Discards the rest of the message in progress. 1 if it ended cleanly. */
int ws_drain_message(ws_conn *c);

/* Sends `buf` as a single masked text frame. MASKS buf IN PLACE - it must be
 * scratch the caller does not need afterwards. Client frames must be masked
 * (RFC 6455 5.3), and masking a copy would mean owning a second 768-byte
 * buffer for no reason. */
int ws_send_text(ws_conn *c, uint8_t *buf, size_t n);

#ifdef __cplusplus
}
#endif
#endif
