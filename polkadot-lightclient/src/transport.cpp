#include "transport.h"

#include <Arduino.h>
#include <WiFiClientSecure.h>
#include <esp_system.h>
#include <string.h>

#include "scale.h"
#include "network.h"

/* Which provider, and why it is not a soundness question.
 *
 * Nothing here is trusted, so the choice is only about latency and liveness.
 * Measured against the same block from a wired host, asking each for the
 * finality proof that dominates a refresh:
 *
 *   rpc.polkadot.io        0.10 s to first byte   TLS 1.3 ONLY - unusable
 *   luckyfriday            0.19 s                 gzip on request  <- shipped
 *   publicnode             0.12 s                 gzip, but serves no Asset Hub
 *   onFinality /public     1.36 s                 ignores Accept-Encoding
 *
 * Parity's own endpoint is the fastest and cannot be used: it rejects TLS 1.2
 * with `protocol_version`, and the mbedTLS 2.28 in this framework has no
 * TLS 1.3. That is worth recording, because it is the kind of thing that looks
 * like a bug in the firmware for an hour. The ESP32 also has no ChaCha20, which
 * is what these hosts prefer, so the suite that actually gets negotiated is
 * ECDHE-ECDSA-AES-GCM - present on both sides, and checked before switching.
 *
 * A second of onFinality's lead time was the node building the proof, and it
 * was an eighth of a refresh. These hosts also honour `Accept-Encoding: gzip`
 * - 46 KB on the wire instead of 106 KB - which is worth more than the latency
 * and needs a streaming inflate the firmware does not have. See PLAN 13.
 *
 * Parity really is faster from a wired host, and it does not help here.
 * Ten rounds against the head of the chain, the only block this ever asks for:
 * Parity 0.359 s median to luckyfriday's 0.591 s, winning 9 of 10 - ~70 ms of
 * that first-byte, ~165 ms streaming (437 vs 259 KB/s). Reaching it would mean
 * TLS 1.3, which is not a flag: mbedTLS 2.28.7 has none to enable (its
 * MBEDTLS_SSL_PROTO_TLS1_3_EXPERIMENTAL is a development placeholder whose own
 * header says the protocol "aren't yet supported") and the framework ships
 * libmbedtls.a prebuilt with no source, so it means arduino-esp32 3.x built as
 * an IDF component.
 *
 * That was tested without paying for it. publicnode is as fast as Parity on the
 * wire, speaks TLS 1.2, and offers AES-GCM, so it was put on the relay and
 * flashed. On the board it streamed the justification at 172,729 B/s - the same
 * 167-203 KB/s luckyfriday gives, from a host measured at 437 KB/s wired. The
 * ESP32 is the ceiling, not the provider, so the streaming two thirds of that
 * gap does not exist up here and only the ~70 ms of latency was ever available.
 * Wired benchmarks pick the provider; only the board decides if it mattered.
 *
 * publicnode also broke the second request on a kept-alive connection after a
 * large response - `bad HTTP response`, 7 ms in - which would have cost a fresh
 * handshake per call and swamped the 70 ms anyway. It was reverted. */
/* Above: historical mainnet measurements. Active endpoints are selected in
 * network.h after the Products Devnet preflight in docs/DEVNET.md. */
const RpcEndpoint RELAY_ENDPOINT     = { LC_RELAY_HOST, LC_RELAY_PATH, 443 };
const RpcEndpoint ASSET_HUB_ENDPOINT = { LC_HUB_HOST, LC_HUB_PATH, 443 };

static const uint32_t IO_TIMEOUT_MS = 20000;

#ifdef LC_NET_STATS
lc_net_stats lc_net;
void lc_net_reset(void) { memset(&lc_net, 0, sizeof lc_net); }
#endif

const char *lc_transport_strerror(lc_transport_status s)
{
    switch (s) {
    case LC_T_OK:        return "ok";
    case LC_T_CONNECT:   return "connection failed";
    case LC_T_HTTP:      return "bad HTTP response";
    case LC_T_RPC_ERROR: return "node returned a JSON-RPC error";
    case LC_T_PARSE:     return "unexpected response shape";
    case LC_T_TOO_BIG:   return "response too large for buffer";
    case LC_T_TRUNCATED: return "connection ended mid-response";
    }
    return "unknown";
}

/* Socket read buffer.
 *
 * WiFiClientSecure keeps none of its own: read() with no argument is
 * read(&b, 1), which calls available() and then get_ssl_receive, so a single
 * byte costs two trips into the TLS record layer. A justification is ~106 KB
 * of hex, which made that ~420,000 mbedtls_ssl_read calls and left the
 * transport, not the 401 signatures, as the cost of a refresh. Pulling a
 * buffer at a time turns it into roughly one call per two kilobytes.
 *
 * It sits below HTTP framing, so on a keep-alive connection it may hold bytes
 * that belong to the next response. That is correct - the stream is drained in
 * order, and the buffer is reset only when the socket underneath it is. */
#ifndef RX_BUF
#define RX_BUF 2048
#endif

struct RpcSession::Impl {
    WiFiClientSecure client;
    bool chunked = false;
    bool eof = true;
    size_t remaining = 0;       /* bytes left in the body, or in the chunk */
    bool first_chunk = true;

    /* WebSocket mode. `wsc` does the framing and knows nothing about this
     * socket beyond the two callbacks below. */
    bool     ws = false;
    ws_conn  wsc;
    uint32_t next_id = 1;
    char     sub_id[40] = { 0 };  /* the subscription handle the node returned */

    /* The coalescing slot. Not a queue on purpose - see takeHead(). */
    uint32_t head_number = 0;
    uint32_t head_count = 0;
    /* Request scratch lives here rather than on the stack: the same task runs
     * the TLS handshake, which needs every byte of stack it can get. */
    char body[768];
    char head[384];
    char line[256];

    uint8_t rx[RX_BUF];
    size_t  rx_pos = 0, rx_len = 0;

    void rxReset() { rx_pos = rx_len = 0; }

    /* Whether a read can proceed without waiting on the network. What makes
     * pumpHeads() able to say "nothing has arrived" instead of blocking. */
    bool bytesReady() { return rx_pos < rx_len || client.available() > 0; }

    void noteHead(uint32_t n)
    {
        if (n > head_number) head_number = n;
        head_count++;
    }

    /* Blocks for more bytes with a timeout, so a stalled peer cannot wedge the
     * device forever. */
    bool fill()
    {
        uint32_t t0 = millis(), deadline = t0 + IO_TIMEOUT_MS;
        for (;;) {
            int n = client.read(rx, sizeof rx);
            if (n > 0) {
                rx_pos = 0; rx_len = (size_t)n;
#ifdef LC_NET_STATS
                lc_net.fills++;
                lc_net.bytes += (uint32_t)n;
                if ((uint32_t)n > lc_net.max_read) lc_net.max_read = (uint32_t)n;
                lc_net.wait_ms += millis() - t0;
#endif
                return true;
            }
            if (!client.connected() && client.available() == 0) return false;
            if ((int32_t)(millis() - deadline) >= 0) return false;
#ifdef LC_NET_STATS
            lc_net.stalls++;
#endif
            delay(1);
        }
    }

    int rawByte()
    {
        if (rx_pos == rx_len && !fill()) return -1;
        return rx[rx_pos++];
    }

    bool readLine(char *out, size_t cap)
    {
        size_t n = 0;
        for (;;) {
            int v = rawByte();
            if (v < 0) return false;
            if (v == '\n') { out[n < cap ? n : cap - 1] = 0; return true; }
            if (v == '\r') continue;
            if (n < cap - 1) out[n++] = (char)v;
        }
    }
};

/* ws_frame.c pulls and pushes through these two and sees nothing else of the
 * socket, which is what lets test/run_ws.sh drive the whole framing layer from
 * byte arrays with no Arduino in the build. */
int RpcSession::wsSrc(void *ctx)
{
    return ((Impl *) ctx)->rawByte();
}

int RpcSession::wsSink(void *ctx, const uint8_t *b, size_t n)
{
    Impl *p = (Impl *) ctx;
    return p->client.write(b, n) == n;
}

/* 16 random bytes as base64, for Sec-WebSocket-Key. */
static void b64_16(const uint8_t *in, char *out)
{
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, o = 0;
    for (i = 0; i < 15; i += 3) {
        uint32_t v = (uint32_t) in[i] << 16 | (uint32_t) in[i + 1] << 8 | in[i + 2];
        out[o++] = T[v >> 18 & 63]; out[o++] = T[v >> 12 & 63];
        out[o++] = T[v >> 6 & 63];  out[o++] = T[v & 63];
    }
    out[o++] = T[in[15] >> 2];
    out[o++] = T[(in[15] & 3) << 4];
    out[o++] = '='; out[o++] = '=';
    out[o] = 0;
}

RpcSession::RpcSession() : p_(new Impl), ep_(0) {}
RpcSession::~RpcSession() { close(); delete p_; }
bool RpcSession::isOpen() const { return p_->client.connected(); }

bool RpcSession::isWs() const { return p_->ws; }

void RpcSession::close()
{
    p_->client.stop();
    p_->rxReset();
    p_->eof = true;
    p_->ws = false;
    p_->sub_id[0] = 0;
    /* A pending head is dropped with the socket it came through. Keeping it
     * would mean acting on a number whose subscription no longer exists, and
     * the reopen re-subscribes and is told the current head again anyway. */
    p_->head_number = 0;
    p_->head_count = 0;
    ep_ = 0;
}

lc_transport_status RpcSession::open(const RpcEndpoint &ep)
{
    close();
    /* Not certificate-checked, on purpose - see transport.h. */
    p_->client.setInsecure();
    if (!p_->client.connect(ep.host, ep.port)) return LC_T_CONNECT;
    /* After connect, not before: setting a socket option needs a socket, and
     * doing it early logs a spurious "Bad file number" on every connection. */
    p_->client.setTimeout(IO_TIMEOUT_MS / 1000);
    ep_ = &ep;
    return LC_T_OK;
}

lc_transport_status RpcSession::openWs(const RpcEndpoint &ep)
{
    lc_transport_status st = open(ep);
    if (st != LC_T_OK) return st;

    uint8_t raw[16];
    char key[25];
    for (int i = 0; i < 16; i++) raw[i] = (uint8_t) esp_random();
    b64_16(raw, key);

    char *head = p_->head;
    int hlen = snprintf(head, sizeof p_->head,
                        "GET %s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "User-Agent: esp32-lightclient/1\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Key: %s\r\n"
                        "Sec-WebSocket-Version: 13\r\n\r\n",
                        ep.path, ep.host, key);
    if (hlen <= 0 || (size_t) hlen >= sizeof p_->head) { close(); return LC_T_PARSE; }
    if (p_->client.write((const uint8_t *) head, hlen) != (size_t) hlen) {
        close();
        return LC_T_TRUNCATED;
    }

    char *line = p_->line;
    if (!p_->readLine(line, sizeof p_->line)) { close(); return LC_T_TRUNCATED; }
    if (strncmp(line, "HTTP/1.", 7) != 0 || strncmp(line + 9, "101", 3) != 0) {
        close();
        return LC_T_HTTP;
    }
    /* Headers to the blank line. Sec-WebSocket-Accept is deliberately not
     * checked. It is sha1(key + a fixed GUID), and what it defends against is a
     * caching intermediary being tricked into treating the upgrade as an
     * ordinary response - which cannot happen inside a TLS tunnel with no
     * proxy in it. transport.h already argues that tunnel is uncertified on
     * purpose; this is the same argument, and a 101 that is not a WebSocket
     * fails on the very first frame header anyway. */
    for (;;) {
        if (!p_->readLine(line, sizeof p_->line)) { close(); return LC_T_TRUNCATED; }
        if (line[0] == 0) break;
    }

    /* The seed only has to differ between boots; masking is unpredictability
     * this connection does not need. See ws_frame.h. */
    ws_init(&p_->wsc, wsSrc, wsSink, p_, esp_random() | 1u);
    p_->ws = true;
    p_->eof = false;
    return LC_T_OK;
}

lc_transport_status RpcSession::call(const char *method, const char *params)
{
    return p_->ws ? callWs(method, params) : callHttp(method, params);
}

lc_transport_status RpcSession::callHttp(const char *method, const char *params)
{
    if (!ep_) return LC_T_CONNECT;
    if (!p_->client.connected()) {
        const RpcEndpoint *ep = ep_;
        lc_transport_status s = open(*ep);
        if (s != LC_T_OK) return s;
    }

    char *body = p_->body;
    int blen = snprintf(body, sizeof p_->body,
                        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"%s\",\"params\":%s}",
                        method, params);
    if (blen <= 0 || (size_t)blen >= sizeof p_->body) return LC_T_PARSE;

    char *head = p_->head;
    int hlen = snprintf(head, sizeof p_->head,
                        "POST %s HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "User-Agent: esp32-lightclient/1\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: %d\r\n"
                        "Connection: keep-alive\r\n\r\n",
                        ep_->path, ep_->host, blen);
    if (hlen <= 0 || (size_t)hlen >= sizeof p_->head) return LC_T_PARSE;

    if (p_->client.write((const uint8_t *)head, hlen) != (size_t)hlen) return LC_T_TRUNCATED;
    if (p_->client.write((const uint8_t *)body, blen) != (size_t)blen) return LC_T_TRUNCATED;

    char *line = p_->line;
#ifdef LC_NET_STATS
    uint32_t sent_ms = millis();
#endif
    if (!p_->readLine(line, sizeof p_->line)) return LC_T_TRUNCATED;
#ifdef LC_NET_STATS
    lc_net.ttfb_ms += millis() - sent_ms;
#endif
    if (strncmp(line, "HTTP/1.", 7) != 0 || strncmp(line + 9, "200", 3) != 0) return LC_T_HTTP;

    p_->chunked = false;
    p_->remaining = 0;
    p_->first_chunk = true;
    bool have_length = false;

    for (;;) {
        if (!p_->readLine(line, sizeof p_->line)) return LC_T_TRUNCATED;
        if (line[0] == 0) break;
        if (strncasecmp(line, "Content-Length:", 15) == 0) {
            p_->remaining = (size_t)strtoul(line + 15, 0, 10);
            have_length = true;
        } else if (strncasecmp(line, "Transfer-Encoding:", 18) == 0 &&
                   strstr(line, "chunked")) {
            p_->chunked = true;
        }
    }
    if (!p_->chunked && !have_length) return LC_T_HTTP;
    p_->eof = false;
    return LC_T_OK;
}

int RpcSession::getByte()
{
    /* On a WebSocket the message boundary IS the body boundary, and the frame
     * layer keeps it. Everything above here - scanTo, readHex, the prefetcher,
     * the GRANDPA verifier - cannot tell the two transports apart, which is the
     * whole reason the chunked reader was written this shape. */
    if (p_->ws) return ws_read_byte(&p_->wsc);

    if (p_->eof) return -1;

    if (p_->chunked) {
        if (p_->remaining == 0) {
            char line[32];
            if (!p_->first_chunk && !p_->readLine(line, sizeof line))
                return -1;                          /* CRLF after the previous chunk */
            p_->first_chunk = false;
            if (!p_->readLine(line, sizeof line)) return -1;
            p_->remaining = (size_t)strtoul(line, 0, 16);
            if (p_->remaining == 0) { p_->eof = true; return -1; }
        }
    } else if (p_->remaining == 0) {
        p_->eof = true;
        return -1;
    }

    int v = p_->rawByte();
    if (v < 0) { p_->eof = true; return -1; }
    p_->remaining--;
    return v;
}

bool RpcSession::skipBody()
{
    if (p_->ws) return ws_drain_message(&p_->wsc) != 0;

    /* Bounded: a peer that keeps talking should cost us a reconnect, not an
     * unbounded read. */
    for (size_t i = 0; i < 256 * 1024; i++)
        if (getByte() < 0) return p_->eof;
    close();
    return false;
}

bool RpcSession::scanTo(const char *literal)
{
    size_t n = strlen(literal), m = 0;
    for (;;) {
        int c = getByte();
        if (c < 0) return false;
        if ((char)c == literal[m]) {
            if (++m == n) return true;
        } else {
            /* Restart, but the mismatching byte may itself begin a new match. */
            m = ((char)c == literal[0]) ? 1 : 0;
        }
    }
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

size_t RpcSession::readHexUpTo(uint8_t *dst, size_t n)
{
    size_t i = 0;
    for (; i < n; i++) {
        int hi = hexval(getByte());
        int lo = hexval(getByte());
        if (hi < 0 || lo < 0) break;
        dst[i] = (uint8_t)(hi << 4 | lo);
    }
    return i;
}

bool RpcSession::readHex(uint8_t *dst, size_t n)
{
    return readHexUpTo(dst, n) == n;
}

int RpcSession::scanEither(const char *a, const char *b)
{
    size_t na = strlen(a), nb = strlen(b), ma = 0, mb = 0;
    for (;;) {
        int c = getByte();
        if (c < 0) return 0;
        /* Same restart rule as scanTo: a mismatching byte may itself begin a
         * new match. */
        ma = ((char) c == a[ma]) ? ma + 1 : ((char) c == a[0] ? 1 : 0);
        if (ma == na) return 1;
        mb = ((char) c == b[mb]) ? mb + 1 : ((char) c == b[0] ? 1 : 0);
        if (mb == nb) return 2;
    }
}

int RpcSession::classifyMessage(uint32_t *id)
{
    int which = scanEither("\"id\":", "\"method\":\"");
    if (which != 1) return which;

    uint32_t v = 0;
    int digits = 0;
    for (;;) {
        int c = getByte();
        if (c < 0) return 0;
        if (c < '0' || c > '9') break;
        v = v * 10 + (uint32_t) (c - '0');
        if (++digits > 9) return 0;
    }
    if (id) *id = v;
    return digits ? 1 : 0;
}

void RpcSession::absorbHead()
{
    /* Positioned just after "method":" - read the name, then the block number
     * out of the header the node pushed. Nothing here is trusted: it is a hint
     * about which block to ask grandpa_proveFinality for, and the justification
     * is what decides whether that block is final. */
    char name[40];
    size_t n = 0;
    for (;;) {
        int c = getByte();
        if (c < 0) return;
        if (c == '"') break;
        if (n < sizeof name - 1) name[n++] = (char) c;
    }
    name[n] = 0;
    if (strcmp(name, "chain_finalizedHead") != 0) return;

    if (!scanTo("\"number\":\"0x")) return;
    uint32_t number = 0;
    int digits = 0;
    for (;;) {
        int c = getByte();
        if (c < 0) return;
        if (c == '"') break;
        int h = hexval(c);
        if (h < 0 || ++digits > 8) return;
        number = number << 4 | (uint32_t) h;
    }
    if (digits) p_->noteHead(number);
}

lc_transport_status RpcSession::callWs(const char *method, const char *params)
{
    if (!p_->ws) return LC_T_CONNECT;
    /* No silent reopen, unlike the HTTP path. A fresh socket has no
     * subscription on it, and a device quietly waiting forever for heads that
     * will never be pushed is exactly the failure that looks like a hung
     * network. The caller reopens and re-subscribes together. */
    if (!p_->client.connected() && !p_->bytesReady()) return LC_T_CONNECT;

    uint32_t id = ++p_->next_id;
    int blen = snprintf(p_->body, sizeof p_->body,
                        "{\"jsonrpc\":\"2.0\",\"id\":%u,\"method\":\"%s\",\"params\":%s}",
                        (unsigned) id, method, params);
    if (blen <= 0 || (size_t) blen >= sizeof p_->body) return LC_T_PARSE;
    /* ws_send_text masks in place; p_->body is scratch and nothing reads it
     * after this. */
    if (!ws_send_text(&p_->wsc, (uint8_t *) p_->body, (size_t) blen)) return LC_T_TRUNCATED;

#ifdef LC_NET_STATS
    uint32_t sent_ms = millis();
#endif

    /* The node may push heads before it answers. Absorbing them here is what
     * keeps them out of the middle of somebody's response parse - and what
     * makes them still count towards the next cycle's coalesced head. The
     * bound is on messages, not time: a peer that pushes without ever
     * answering should cost a reconnect. */
    for (int guard = 0; guard < 64; guard++) {
        if (!ws_next_message(&p_->wsc)) return LC_T_TRUNCATED;

        uint32_t got = 0;
        int kind = classifyMessage(&got);
        if (kind == 2) { absorbHead(); skipBody(); continue; }
        if (kind != 1) { skipBody(); continue; }

        if (got != id) {
            /* A response to a request nobody is waiting for means the stream
             * and this session disagree about where they are. Draining on is
             * how a wrong answer gets parsed as a right one. */
            return LC_T_PARSE;
        }
#ifdef LC_NET_STATS
        lc_net.ttfb_ms += millis() - sent_ms;
#endif
        return LC_T_OK;
    }
    return LC_T_PARSE;
}

lc_transport_status RpcSession::subscribeFinalizedHeads()
{
    if (!p_->ws) return LC_T_CONNECT;
    lc_transport_status st = callWs("chain_subscribeFinalizedHeads", "[]");
    if (st != LC_T_OK) return st;

    /* The handle is kept for the record rather than to filter on: this session
     * has exactly one subscription, so a notification carrying any other id
     * would mean the node invented one. */
    if (!scanTo("\"result\":\"")) { skipBody(); return LC_T_RPC_ERROR; }
    size_t n = 0;
    for (;;) {
        int c = getByte();
        if (c < 0) break;
        if (c == '"') break;
        if (n < sizeof p_->sub_id - 1) p_->sub_id[n++] = (char) c;
    }
    p_->sub_id[n] = 0;
    skipBody();
    return n ? LC_T_OK : LC_T_PARSE;
}

lc_transport_status RpcSession::pumpHeads(uint32_t timeout_ms)
{
    if (!p_->ws) return LC_T_CONNECT;

    uint32_t deadline = millis() + timeout_ms;
    while (!p_->bytesReady()) {
        if (!p_->client.connected()) return LC_T_CONNECT;
        if ((int32_t) (millis() - deadline) >= 0) return LC_T_OK;   /* nothing arrived */
        delay(5);
    }

    /* Then take everything already here, without waiting for more. A head
     * notification is 861 bytes and lands in one or two TLS records, so
     * finishing one that has started is a sub-millisecond block rather than a
     * wait on the network. */
    do {
        if (!ws_next_message(&p_->wsc)) return LC_T_TRUNCATED;
        uint32_t id = 0;
        int kind = classifyMessage(&id);
        if (kind == 2) absorbHead();
        skipBody();
    } while (p_->bytesReady());

    return LC_T_OK;
}

bool RpcSession::takeHead(uint32_t *number, uint32_t *coalesced)
{
    if (!p_->head_count) return false;
    if (number) *number = p_->head_number;
    if (coalesced) *coalesced = p_->head_count;
    p_->head_number = 0;
    p_->head_count = 0;
    return true;
}

static int hex_reader_read(lc_reader *self, uint8_t *dst, size_t n)
{
    RpcHexReader *r = (RpcHexReader *)self->ctx;
    return r->session->readHex(dst, n) ? 1 : 0;
}

void rpc_hex_reader_init(RpcHexReader *r, RpcSession *s)
{
    r->base.read = hex_reader_read;
    r->base.ctx = r;
    r->session = s;
}

lc_transport_status rpc_seek_result_hex(RpcSession &s)
{
    /* A JSON-RPC error response has no "result" at all, so failing to find one
     * is reported as an error from the node rather than a parse failure. */
    if (!s.scanTo("\"result\":\"0x")) return LC_T_RPC_ERROR;
    return LC_T_OK;
}

/* Reads hex digit pairs into dst until the closing quote. Returns the byte
 * count, or -1 on a malformed run or overflow. */
static long read_hex_until_quote(RpcSession &s, uint8_t *dst, size_t cap)
{
    size_t n = 0;
    for (;;) {
        int c1 = s.getByte();
        if (c1 < 0) return -1;
        if (c1 == '"') return (long)n;
        int c2 = s.getByte();
        int hi = hexval(c1), lo = hexval(c2);
        if (hi < 0 || lo < 0) return -1;
        if (n >= cap) return -1;
        dst[n++] = (uint8_t)(hi << 4 | lo);
    }
}

/* Space reserved at the front of the caller's buffer for the fixed part of the
 * header, which can only be written once the digest has been counted. */
#define HEADER_PREFIX_RESERVE 128

lc_transport_status transport_fetch_header(RpcSession &s, const char *block_hash_hex,
                                           uint8_t *buf, size_t cap, size_t *out_len)
{
    char params[96];
    if ((size_t)snprintf(params, sizeof params, "[\"%s\"]", block_hash_hex) >= sizeof params)
        return LC_T_PARSE;

    lc_transport_status st = s.call("chain_getHeader", params);
    if (st != LC_T_OK) return st;
    if (cap < HEADER_PREFIX_RESERVE + 64) return LC_T_TOO_BIG;

    uint8_t parent[32], state_root[32], extrinsics_root[32];
    uint32_t number = 0;

    /* Substrate serialises the header in declaration order, so one forward scan
     * finds every field. If a node ever reorders them this fails to parse - it
     * cannot silently produce a header that hashes to something wrong, because
     * the caller checks the hash. */
    if (!s.scanTo("\"parentHash\":\"0x") || !s.readHex(parent, 32))     return LC_T_PARSE;

    if (!s.scanTo("\"number\":\"0x")) return LC_T_PARSE;
    int ndigits = 0;
    for (;;) {
        int c = s.getByte();
        if (c < 0) return LC_T_TRUNCATED;
        if (c == '"') break;
        int v = hexval(c);
        if (v < 0 || ++ndigits > 8) return LC_T_PARSE;
        number = number << 4 | (uint32_t)v;
    }
    if (ndigits == 0) return LC_T_PARSE;

    if (!s.scanTo("\"stateRoot\":\"0x") || !s.readHex(state_root, 32))            return LC_T_PARSE;
    if (!s.scanTo("\"extrinsicsRoot\":\"0x") || !s.readHex(extrinsics_root, 32))  return LC_T_PARSE;
    if (!s.scanTo("\"logs\":["))                                                  return LC_T_PARSE;

    size_t logs_len = 0;
    uint32_t n_logs = 0;
    for (;;) {
        int c = s.getByte();
        if (c < 0) return LC_T_TRUNCATED;
        if (c == ']') break;
        if (c != '"') continue;                    /* commas and whitespace */
        int p0 = s.getByte(), p1 = s.getByte();
        if (p0 != '0' || p1 != 'x') return LC_T_PARSE;
        long got = read_hex_until_quote(s, buf + HEADER_PREFIX_RESERVE + logs_len,
                                        cap - HEADER_PREFIX_RESERVE - logs_len);
        if (got < 0) return LC_T_TOO_BIG;
        logs_len += (size_t)got;
        n_logs++;
    }
    s.skipBody();

    /* Rebuild the SCALE encoding backwards from the digest, so the whole header
     * ends up contiguous in one buffer with no second allocation. */
    uint8_t count_enc[5], num_enc[5];
    size_t count_len = scale_encode_compact(count_enc, n_logs);
    size_t num_len = scale_encode_compact(num_enc, number);
    size_t fixed = 32 + num_len + 32 + 32 + count_len;
    if (fixed > HEADER_PREFIX_RESERVE) return LC_T_TOO_BIG;

    uint8_t *start = buf + HEADER_PREFIX_RESERVE - fixed;
    uint8_t *w = start;
    memcpy(w, parent, 32);            w += 32;
    memcpy(w, num_enc, num_len);      w += num_len;
    memcpy(w, state_root, 32);        w += 32;
    memcpy(w, extrinsics_root, 32);   w += 32;
    memcpy(w, count_enc, count_len);

    *out_len = fixed + logs_len;
    memmove(buf, start, *out_len);
    return LC_T_OK;
}

lc_transport_status transport_fetch_read_proof(RpcSession &s,
                                               const char *const *keys_hex, size_t n_keys,
                                               const char *at_hash_hex,
                                               uint8_t *buf, size_t cap,
                                               trie_proof *proof, const char *child_key_hex)
{
    char params[512];
    size_t o = 0;
    int prefix = child_key_hex ? snprintf(params, sizeof params, "[\"%s\",[", child_key_hex)
                               : snprintf(params, sizeof params, "[[");
    if (prefix < 0 || (size_t)prefix >= sizeof params) return LC_T_PARSE;
    o = (size_t)prefix;
    for (size_t i = 0; i < n_keys; i++) {
        int n = snprintf(params + o, sizeof params - o, "%s\"%s\"", i ? "," : "", keys_hex[i]);
        if (n < 0 || (size_t)n >= sizeof params - o) return LC_T_PARSE;
        o += (size_t)n;
    }
    if ((size_t)snprintf(params + o, sizeof params - o, "],\"%s\"]", at_hash_hex)
        >= sizeof params - o) return LC_T_PARSE;

    lc_transport_status st = s.call(child_key_hex ? "state_getChildReadProof" : "state_getReadProof", params);
    if (st != LC_T_OK) return st;

    if (!s.scanTo("\"proof\":[")) return LC_T_RPC_ERROR;

    size_t used = 0;
    for (;;) {
        int c = s.getByte();
        if (c < 0) return LC_T_TRUNCATED;
        if (c == ']') break;
        if (c != '"') continue;
        int p0 = s.getByte(), p1 = s.getByte();
        if (p0 != '0' || p1 != 'x') return LC_T_PARSE;
        long got = read_hex_until_quote(s, buf + used, cap - used);
        if (got < 0) return LC_T_TOO_BIG;
        if (trie_proof_add(proof, buf + used, (size_t)got) != TRIE_FOUND) return LC_T_TOO_BIG;
        used += (size_t)got;
    }
    s.skipBody();
    return LC_T_OK;
}
