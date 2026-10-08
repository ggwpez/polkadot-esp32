/* JSON-RPC over TLS.
 *
 * This is the only part of the firmware that talks to anyone, and it is the
 * only part that is allowed to be wrong without consequence: everything it
 * returns is checked against the trust root before it is believed.
 *
 * Because of that, the TLS connection is deliberately NOT certificate-checked.
 * A man in the middle can do exactly what a hostile RPC provider can do - refuse
 * to answer, or serve stale-but-valid data - and neither can forge a value that
 * the verifier will accept. Carrying a CA bundle would add bytes, add an expiry
 * date to a device with no OTA, and buy no soundness. It is worth being explicit
 * that this is a design decision and not an oversight.
 *
 * The obvious next question is why there is any TLS here at all, since an
 * uncertified tunnel stops a passive observer and nothing else, and every byte
 * that comes out of it is checked anyway. The answer is not principle, it is
 * the providers: measured against all six candidate endpoints, plain HTTP on
 * port 80 either redirects to https or is refused outright, and Substrate's
 * unencrypted 9944 accepts a TCP connection from a load balancer and then
 * speaks nothing. So the cost is paid for access, not for security - about
 * 45 KB of heap per open session and ~155 KB of linked mbedTLS. The way out is
 * not a flag, it is M2b: libp2p over raw TCP, whose mandatory Noise handshake
 * uses X25519, ChaCha20-Poly1305 and BLAKE2 - all of them already in the
 * libsodium this firmware links - with no X.509 and no 16 KB record buffers.
 * PLAN section 13 carries the numbers.
 *
 * The interface is deliberately narrow so M2 can put libp2p behind it. */
#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include "lc_reader.h"
#include "trie.h"
#include "ws_frame.h"

typedef enum {
    LC_T_OK = 0,
    LC_T_CONNECT,       /* TCP or TLS failed */
    LC_T_HTTP,          /* not a 200, or a malformed response */
    LC_T_RPC_ERROR,     /* the node returned a JSON-RPC error */
    LC_T_PARSE,         /* the response did not contain what we asked for */
    LC_T_TOO_BIG,       /* response did not fit the caller's buffer */
    LC_T_TRUNCATED      /* connection ended mid-response */
} lc_transport_status;

const char *lc_transport_strerror(lc_transport_status s);

struct RpcEndpoint {
    const char *host;
    const char *path;
    uint16_t port;
};

extern const RpcEndpoint RELAY_ENDPOINT;
extern const RpcEndpoint ASSET_HUB_ENDPOINT;

/* Where a refresh actually spends its time on the wire. Off by default; build
 * with -DLC_NET_STATS to have main.cpp print it. Separates the two things that
 * look identical from outside - a node that is slow to answer, and a link that
 * is slow to deliver. */
#ifdef LC_NET_STATS
struct lc_net_stats {
    uint32_t ttfb_ms;   /* request written -> first byte of the status line */
    uint32_t fills;     /* socket reads that returned data */
    uint32_t bytes;     /* bytes they returned */
    uint32_t stalls;    /* 1 ms polls with nothing to read */
    uint32_t wait_ms;   /* total time blocked waiting for bytes */
    uint32_t max_read;  /* largest single socket read */
};
extern lc_net_stats lc_net;
void lc_net_reset(void);
#endif

class RpcSession {
public:
    RpcSession();
    ~RpcSession();

    /* Opens a TLS connection. Kept open across calls: the handshake costs about
     * two seconds and ~46 KB, which is worth paying once per refresh. */
    lc_transport_status open(const RpcEndpoint &ep);

    /* Opens the same endpoint, on the same port, with the same TLS 1.2 and the
     * same cipher suite - and then upgrades it to a WebSocket. The only reason
     * to want one is that Substrate serves subscriptions nowhere else: over
     * HTTP, chain_subscribeFinalizedHeads and every other subscribe method
     * answer {"code":-32603,"message":"Internal error"}, which is jsonrpsee
     * declining to run a subscription on a request/response transport.
     *
     * It REPLACES the HTTP session rather than joining it. Ordinary calls work
     * unchanged over a WebSocket - measured at the same 146-219 ms - so one
     * socket carries both, and the device holds no more TLS state than before.
     * That matters: a session costs ~45 KB against 94,820 free, and PLAN 12
     * records an 8 KB read buffer being enough to make sigpool_start fail. */
    lc_transport_status openWs(const RpcEndpoint &ep);
    bool isWs() const;

    void close();
    bool isOpen() const;

    /* Sends a request and positions the reader at the start of the body.
     * `params` is a JSON array written by the caller, e.g. "[123]".
     *
     * Identical to use in either mode. On a WebSocket the node may push a head
     * notification before it answers, so this absorbs any that arrive while
     * waiting - they update the pending head rather than being lost or being
     * mistaken for the response. */
    lc_transport_status call(const char *method, const char *params);

    /* Subscribes to chain_subscribeFinalizedHeads. WebSocket sessions only.
     * Only the heads are subscribed, deliberately: the notification is 861
     * bytes, so one landing while call() is waiting costs microseconds to
     * absorb. Subscribing to justifications would push 106 KB unbidden, and
     * draining one that arrived at the wrong moment costs ~0.6 s of wire at
     * the 167-203 KB/s this board manages. The proof is still pulled with
     * grandpa_proveFinality, when we want it. */
    lc_transport_status subscribeFinalizedHeads();

    /* Reads every message that has already arrived, waiting up to `timeout_ms`
     * for the first one. Head notifications update the pending head; anything
     * else is discarded. */
    lc_transport_status pumpHeads(uint32_t timeout_ms);

    /* The highest finalized block number pushed since the last take, and how
     * many notifications were folded into it. False if none arrived.
     *
     * This is the coalescing, and it is one line of state rather than a queue:
     * heads absorbed inside call() land here too, so a verify that ran long
     * enough to span three notifications comes back to the newest block, not to
     * a backlog of three. Nothing is ever interrupted to make that happen - a
     * running verification finishes, and only the NEXT one is redirected. */
    bool takeHead(uint32_t *number, uint32_t *coalesced);

    /* Scans the body for a literal. Used to reach "result" without buffering
     * the response - the finality proof alone is 53 KB. */
    bool scanTo(const char *literal);

    int  getByte();                       /* -1 on EOF/error */
    bool skipBody();                      /* drain what is left, for keep-alive */

    /* Reads `n` bytes of hex from the body, decoding into dst. */
    bool readHex(uint8_t *dst, size_t n);

    /* As readHex, but returns how many bytes it managed to decode instead of
     * throwing away a partial result. A reader that does not know where the hex
     * string ends - the prefetcher - needs the tail, not just the news that the
     * end was reached. */
    size_t readHexUpTo(uint8_t *dst, size_t n);

    const RpcEndpoint *endpoint() const { return ep_; }

private:
    struct Impl;
    Impl *p_;
    const RpcEndpoint *ep_;

    lc_transport_status callHttp(const char *method, const char *params);
    lc_transport_status callWs(const char *method, const char *params);

    /* Scans for whichever of two literals comes first: 1, 2, or 0 if the
     * message ended without either. */
    int scanEither(const char *a, const char *b);

    /* Tells a response from a notification, one forward pass and no
     * backtracking. jsonrpsee puts the discriminator second in both shapes -
     * {"jsonrpc":"2.0","id":8,"result":...} against
     * {"jsonrpc":"2.0","method":"chain_finalizedHead","params":{...}} - so
     * whichever of "id": and "method":" turns up first settles it. Returns 1
     * for a response (with its id), 2 for a notification, 0 for neither. */
    int classifyMessage(uint32_t *id);

    /* Reads a notification's block number and records it as pending. */
    void absorbHead();

    /* ws_frame.c's view of this socket, and the only part of it that file
     * sees. Members rather than free functions because Impl is private. */
    static int wsSrc(void *ctx);
    static int wsSink(void *ctx, const uint8_t *buf, size_t n);
};

/* An lc_reader that pulls hex digits out of an open session's body, so the
 * GRANDPA verifier can stream a 53 KB justification it never has to store. */
struct RpcHexReader {
    lc_reader base;
    RpcSession *session;
};
void rpc_hex_reader_init(RpcHexReader *r, RpcSession *s);

/* Positions the session at the hex payload of a "result" string. */
lc_transport_status rpc_seek_result_hex(RpcSession &s);

/* Fetches a header and re-encodes it to SCALE, so the caller can hash it and
 * check the hash against something it already trusts. The node's JSON is not
 * trusted - it is raw material for a hash that either matches or does not. */
lc_transport_status transport_fetch_header(RpcSession &s, const char *block_hash_hex,
                                           uint8_t *buf, size_t cap, size_t *out_len);

/* Fetches state_getReadProof and loads the nodes into `proof`. Node bytes are
 * decoded into `buf`, which must outlive any lookup against the proof. */
lc_transport_status transport_fetch_read_proof(RpcSession &s,
                                               const char *const *keys_hex, size_t n_keys,
                                               const char *at_hash_hex,
                                               uint8_t *buf, size_t cap,
                                               trie_proof *proof, const char *child_key_hex = nullptr);

#endif
