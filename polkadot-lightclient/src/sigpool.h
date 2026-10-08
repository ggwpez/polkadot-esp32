/* The second core, wired up as a grandpa_sig_pool.
 *
 * The verification loop stays exactly where it was - one thread, stream order,
 * every cheap check in place. All this adds is somewhere to put the ed25519,
 * which is where ~19.5 ms of every 20 ms record goes.
 *
 * The loop task runs on core 1 and the Wi-Fi driver on core 0, so the worker is
 * pinned to core 0: that core is otherwise only servicing the radio, and a
 * measured cross-core contention of under 2% says the shared instruction cache
 * does not care. When the queue is full submit() refuses rather than blocking,
 * and the verifier does that check itself - so core 1 spends its socket-wait
 * cycles on signatures instead of idling, and the split rebalances itself
 * without anyone tuning it. */
#ifndef SIGPOOL_H
#define SIGPOOL_H

#include "grandpa.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sigpool sigpool;

/* Starts the worker. Returns NULL if the task or its queue would not fit, and
 * the caller then verifies single-core - a slower anchor is not a failure. */
sigpool *sigpool_start(int worker_core);

/* Waits for the worker to exit and frees everything. Safe on NULL. */
void sigpool_stop(sigpool *p);

/* The interface to hand to grandpa_verify_finality_proof_ex. */
const grandpa_sig_pool *sigpool_iface(sigpool *p);

/* How many checks the worker actually ran, for the "n on core 0, m on core 1"
 * line. Only meaningful after join. */
uint32_t sigpool_worker_sigs(const sigpool *p);

#ifdef __cplusplus
}
#endif
#endif
