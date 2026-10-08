/* Keeps the socket draining while the verifier is busy.
 *
 * Without this the same thread does both jobs, so every ~20 ms signature check
 * is 20 ms in which nobody is reading the TCP window. The fix is one task above
 * the verifier in priority whose only job is to pull hex out of the session and
 * push bytes into a ring: it runs when there is data, blocks when there is not,
 * and the verifier reads from the ring instead of from the wire.
 *
 * It presents itself as an lc_reader, which is why the verification core needs
 * no idea any of this is happening. */
#ifndef PREFETCH_H
#define PREFETCH_H

#include "lc_reader.h"
#include "transport.h"

struct RpcPrefetch;

/* Starts feeding from `s`, which must already be positioned at the hex payload.
 * Returns NULL if the buffer or task would not fit; the caller then reads the
 * session directly. */
RpcPrefetch *prefetch_start(RpcSession *s, int core);

/* The reader to hand to the verifier. */
lc_reader *prefetch_reader(RpcPrefetch *p);

/* Stops the feeder and frees it. The session is left wherever the feeder got
 * to, so the caller should close it rather than reuse it. Safe on NULL. */
void prefetch_stop(RpcPrefetch *p);

#endif
