/* RFC 6455 framing, driven from byte arrays on the host.
 *
 * The device cannot test most of this. luckyfriday sends no pings, never
 * fragments a message and has never closed one mid-stream, so on real traffic
 * the interesting half of ws_frame.c is code that ships unexecuted. That is
 * exactly the half worth testing: a ping arriving between two fragments of a
 * 106 KB justification is the one event that would corrupt a proof rather than
 * fail it, because the pong is written from the prefetch task while the
 * verifier is mid-record.
 *
 * So the source and sink are plain arrays here, and every case the endpoint
 * does not produce is produced by hand: both extended length forms,
 * fragmentation, interleaved control frames, and the protocol violations that
 * must drop the socket instead of being tolerated.
 *
 *   sh test/run_ws.sh
 */
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>

#include "../src/ws_frame.h"

static int tests = 0, failures = 0;

static void check(int cond, const char *fmt, ...)
{
    va_list ap;
    tests++;
    if (!cond) failures++;
    printf("  %s ", cond ? "\033[32mpass\033[0m" : "\033[31mFAIL\033[0m");
    va_start(ap, fmt);
    vprintf(fmt, ap);
    va_end(ap);
    putchar('\n');
}

static void section(const char *s) { printf("\n\033[1m%s\033[0m\n", s); }

/* ---- a socket made of two arrays ---- */

typedef struct {
    const uint8_t *in;
    size_t in_len, in_pos;
    uint8_t out[4096];
    size_t out_len;
    int     out_full;
} wire;

static int wire_src(void *ctx)
{
    wire *w = (wire *) ctx;
    if (w->in_pos >= w->in_len) return -1;
    return w->in[w->in_pos++];
}

static int wire_sink(void *ctx, const uint8_t *b, size_t n)
{
    wire *w = (wire *) ctx;
    if (w->out_len + n > sizeof w->out) { w->out_full = 1; return 0; }
    memcpy(w->out + w->out_len, b, n);
    w->out_len += n;
    return 1;
}

static void wire_init(wire *w, const uint8_t *in, size_t n)
{
    memset(w, 0, sizeof *w);
    w->in = in; w->in_len = n;
}

/* ---- building server->client frames (never masked) ---- */

typedef struct { uint8_t b[262144]; size_t n; } buf;

static void put(buf *f, uint8_t v) { f->b[f->n++] = v; }

static void frame(buf *f, int fin, uint8_t opcode, const uint8_t *pay, size_t n)
{
    size_t i;
    put(f, (uint8_t) ((fin ? 0x80 : 0) | opcode));
    if (n < 126) {
        put(f, (uint8_t) n);
    } else if (n < 65536) {
        put(f, 126);
        put(f, (uint8_t) (n >> 8)); put(f, (uint8_t) n);
    } else {
        put(f, 127);
        for (i = 0; i < 8; i++) put(f, (uint8_t) ((uint64_t) n >> (8 * (7 - i))));
    }
    for (i = 0; i < n; i++) put(f, pay[i]);
}

/* Reads a whole message into dst; returns its length, or -1 if none started. */
static long take_message(ws_conn *c, uint8_t *dst, size_t cap)
{
    long n = 0;
    int v;
    if (!ws_next_message(c)) return -1;
    while ((v = ws_read_byte(c)) >= 0) {
        if ((size_t) n < cap) dst[n] = (uint8_t) v;
        n++;
    }
    return n;
}

static uint8_t big[70000];
static uint8_t got[70000];

int main(void)
{
    static buf f;
    wire w;
    ws_conn c;
    size_t i;

    for (i = 0; i < sizeof big; i++) big[i] = (uint8_t) (i * 7 + (i >> 8));

    section("one frame at a time");
    {
        f.n = 0;
        frame(&f, 1, 0x1, (const uint8_t *) "hello", 5);
        frame(&f, 1, 0x1, (const uint8_t *) "second", 6);
        wire_init(&w, f.b, f.n);
        ws_init(&c, wire_src, wire_sink, &w, 1);

        long n = take_message(&c, got, sizeof got);
        check(n == 5 && memcmp(got, "hello", 5) == 0, "a short text frame reads back whole");
        n = take_message(&c, got, sizeof got);
        check(n == 6 && memcmp(got, "second", 6) == 0, "and the next message follows it");
        check(!ws_next_message(&c) && c.closed, "a spent stream reports closed, not a third message");
    }

    section("the two extended length forms");
    {
        f.n = 0;
        frame(&f, 1, 0x1, big, 300);            /* 126: 16-bit length */
        frame(&f, 1, 0x2, big, 70000);          /* 127: 64-bit length */
        wire_init(&w, f.b, f.n);
        ws_init(&c, wire_src, wire_sink, &w, 1);

        long n = take_message(&c, got, sizeof got);
        check(n == 300 && memcmp(got, big, 300) == 0, "300 bytes via the 16-bit length");
        n = take_message(&c, got, sizeof got);
        check(n == 70000 && memcmp(got, big, 70000) == 0,
              "70,000 bytes via the 64-bit length, byte for byte");
    }

    section("fragmentation is invisible above the framing");
    {
        f.n = 0;
        frame(&f, 0, 0x1, big,          1000);   /* first fragment */
        frame(&f, 0, 0x0, big + 1000,      0);   /* a legal empty fragment */
        frame(&f, 0, 0x0, big + 1000,   2000);
        frame(&f, 1, 0x0, big + 3000,   1500);   /* final */
        wire_init(&w, f.b, f.n);
        ws_init(&c, wire_src, wire_sink, &w, 1);

        long n = take_message(&c, got, sizeof got);
        check(n == 4500 && memcmp(got, big, 4500) == 0,
              "four fragments, one of them empty, arrive as one 4,500-byte message");
    }

    section("control frames in the middle of somebody else's message");
    {
        f.n = 0;
        frame(&f, 0, 0x1, big, 100);
        frame(&f, 1, 0x9, (const uint8_t *) "are you there", 13);   /* ping */
        frame(&f, 0, 0x0, big + 100, 100);
        frame(&f, 1, 0xA, (const uint8_t *) "unsolicited", 11);     /* pong */
        frame(&f, 1, 0x0, big + 200, 100);
        wire_init(&w, f.b, f.n);
        ws_init(&c, wire_src, wire_sink, &w, 1);

        long n = take_message(&c, got, sizeof got);
        check(n == 300 && memcmp(got, big, 300) == 0,
              "the payload is unaffected by a ping and a pong between fragments");

        /* The pong we owed: FIN|0xA, masked, 13 bytes. */
        check(w.out_len == 2 + 4 + 13, "one pong was written, %u bytes", (unsigned) w.out_len);
        check(w.out[0] == 0x8A, "it is a final pong frame (0x%02x)", w.out[0]);
        check(w.out[1] == (0x80 | 13), "it is masked and 13 bytes long (0x%02x)", w.out[1]);
        {
            uint8_t un[13];
            for (i = 0; i < 13; i++) un[i] = w.out[6 + i] ^ w.out[2 + (i & 3)];
            check(memcmp(un, "are you there", 13) == 0,
                  "and unmasking it gives back the ping's payload");
        }
    }

    section("a message that is not read to the end");
    {
        f.n = 0;
        frame(&f, 1, 0x1, big, 5000);
        frame(&f, 1, 0x1, (const uint8_t *) "next", 4);
        wire_init(&w, f.b, f.n);
        ws_init(&c, wire_src, wire_sink, &w, 1);

        check(ws_next_message(&c), "a 5,000-byte message opens");
        for (i = 0; i < 10; i++) ws_read_byte(&c);
        long n = take_message(&c, got, sizeof got);
        check(n == 4 && memcmp(got, "next", 4) == 0,
              "abandoning it after 10 bytes still lands on the next message");
    }

    section("what must drop the socket");
    {
        struct { const char *what; uint8_t hdr[4]; size_t hlen; } bad[] = {
            { "a reserved bit set",            { 0xC1, 0x02, 'h', 'i' }, 4 },
            { "a server frame that is masked", { 0x81, 0x82, 0, 0 },     4 },
            { "a continuation with no message open", { 0x80, 0x00 },     2 },
            { "an unknown control opcode",     { 0x8B, 0x00 },           2 },
        };
        for (i = 0; i < sizeof bad / sizeof *bad; i++) {
            wire_init(&w, bad[i].hdr, bad[i].hlen);
            ws_init(&c, wire_src, wire_sink, &w, 1);
            check(!ws_next_message(&c) && c.failed, "%s is a protocol error", bad[i].what);
        }

        /* A control frame may not be fragmented, and may not exceed 125 bytes. */
        f.n = 0;
        put(&f, 0x09); put(&f, 0x02); put(&f, 'h'); put(&f, 'i');   /* ping, no FIN */
        wire_init(&w, f.b, f.n);
        ws_init(&c, wire_src, wire_sink, &w, 1);
        check(!ws_next_message(&c) && c.failed, "a fragmented ping is a protocol error");

        f.n = 0;
        put(&f, 0x89); put(&f, 126); put(&f, 0x00); put(&f, 0xC8);  /* ping, 200 bytes */
        wire_init(&w, f.b, f.n);
        ws_init(&c, wire_src, wire_sink, &w, 1);
        check(!ws_next_message(&c) && c.failed, "a 200-byte ping is a protocol error");

        /* Two data messages may not interleave on one connection. */
        f.n = 0;
        frame(&f, 0, 0x1, big, 10);
        frame(&f, 1, 0x1, big, 10);
        wire_init(&w, f.b, f.n);
        ws_init(&c, wire_src, wire_sink, &w, 1);
        check(ws_next_message(&c), "a fragmented message opens");
        for (i = 0; i < 10; i++) ws_read_byte(&c);
        check(ws_read_byte(&c) < 0 && c.failed,
              "a second data message before it finished is a protocol error");
    }

    section("ends that are not protocol errors");
    {
        f.n = 0;
        frame(&f, 0, 0x1, big, 100);
        frame(&f, 1, 0x8, (const uint8_t *) "\x03\xe8", 2);         /* close, 1000 */
        wire_init(&w, f.b, f.n);
        ws_init(&c, wire_src, wire_sink, &w, 1);
        check(ws_next_message(&c), "a message opens");
        for (i = 0; i < 100; i++) ws_read_byte(&c);
        check(ws_read_byte(&c) < 0 && c.closed && !c.failed,
              "a close between fragments ends the read as closed, not failed");

        f.n = 0;
        frame(&f, 1, 0x1, big, 500);
        wire_init(&w, f.b, f.n - 200);                              /* cut short */
        ws_init(&c, wire_src, wire_sink, &w, 1);
        long n = take_message(&c, got, sizeof got);
        check(n == 300 && c.closed && !c.failed,
              "a stream that stops mid-payload ends the message as closed");
    }

    section("what this client writes");
    {
        static uint8_t msg[400];
        for (i = 0; i < sizeof msg; i++) msg[i] = (uint8_t) ('a' + i % 26);
        uint8_t copy[400];
        memcpy(copy, msg, sizeof msg);

        wire_init(&w, f.b, 0);
        ws_init(&c, wire_src, wire_sink, &w, 12345);
        check(ws_send_text(&c, msg, 40), "a 40-byte request is sent");
        check(w.out_len == 2 + 4 + 40, "as 2 header + 4 mask + 40 payload bytes");
        check(w.out[0] == 0x81 && w.out[1] == (0x80 | 40),
              "a final, masked text frame (0x%02x 0x%02x)", w.out[0], w.out[1]);
        {
            int same = 1;
            for (i = 0; i < 40; i++)
                if ((w.out[6 + i] ^ w.out[2 + (i & 3)]) != copy[i]) same = 0;
            check(same, "and unmasking the frame gives back the request");
        }

        memcpy(msg, copy, sizeof msg);
        wire_init(&w, f.b, 0);
        ws_init(&c, wire_src, wire_sink, &w, 999);
        check(ws_send_text(&c, msg, 400), "a 400-byte request is sent");
        check(w.out_len == 4 + 4 + 400 && w.out[1] == (0x80 | 126) &&
              w.out[2] == 1 && w.out[3] == 0x90,
              "with the 16-bit length form, big-endian 400");

        /* Two sends must not reuse a mask key. */
        {
            uint8_t k1[4];
            memcpy(k1, w.out + 4, 4);
            memcpy(msg, copy, sizeof msg);
            w.out_len = 0;
            ws_send_text(&c, msg, 400);
            check(memcmp(k1, w.out + 4, 4) != 0, "a second frame uses a different mask key");
        }
    }

    printf("\n%d tests, %d failures\n", tests, failures);
    return failures != 0;
}
