#include "prefetch.h"

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/stream_buffer.h>
#include <freertos/task.h>
#include <stdlib.h>

/* 8 KB is ~62 precommit records: enough that a burst of arriving segments is
 * never dropped on the floor while the verifier is inside a signature check,
 * and small next to the ~200 KB free at this point. */
#define PREFETCH_BUF   8192
#define PREFETCH_STACK 4096
#define PREFETCH_CHUNK 256

/* How long the reader waits with nothing arriving before it calls the stream
 * dead. Generous: a loaded public RPC node can stall for seconds mid-response,
 * and the cost of being wrong is a spurious "justification truncated". */
#define PREFETCH_STALL_MS 20000

struct RpcPrefetch {
    lc_reader          base;
    RpcSession        *session;
    StreamBufferHandle_t sb;
    TaskHandle_t       task;
    volatile bool      stop;
    volatile bool      exited;      /* feeder will produce nothing more */
};

static void prefetch_task(void *arg)
{
    RpcPrefetch *p = (RpcPrefetch *)arg;
    uint8_t chunk[PREFETCH_CHUNK];

    while (!p->stop) {
        /* A short read means the closing quote of the result string, which is
         * the normal way this loop ends - but the bytes decoded before it still
         * have to be delivered, and the tail of the justification is in them. */
        size_t got = p->session->readHexUpTo(chunk, sizeof chunk);

        size_t off = 0;
        while (off < got && !p->stop)
            off += xStreamBufferSend(p->sb, chunk + off, got - off,
                                     pdMS_TO_TICKS(100));
        if (got < sizeof chunk || off < got) break;
    }
    p->exited = true;
    vTaskDelete(NULL);
}

static int prefetch_read(lc_reader *self, uint8_t *dst, size_t n)
{
    RpcPrefetch *p = (RpcPrefetch *)self->ctx;
    size_t got = 0;
    uint32_t waited = 0;

    while (got < n) {
        size_t r = xStreamBufferReceive(p->sb, dst + got, n - got, pdMS_TO_TICKS(50));
        if (r) { got += r; waited = 0; continue; }
        /* Nothing came. The feeder having exited is only conclusive once the
         * ring is also empty, which the receive above just established. */
        if (p->exited) return 0;
        waited += 50;
        if (waited >= PREFETCH_STALL_MS) return 0;
    }
    return 1;
}

RpcPrefetch *prefetch_start(RpcSession *s, int core)
{
    RpcPrefetch *p = (RpcPrefetch *)calloc(1, sizeof *p);
    if (!p) return NULL;

    p->session = s;
    p->base.read = prefetch_read;
    p->base.ctx  = p;

    p->sb = xStreamBufferCreate(PREFETCH_BUF, 1);
    if (!p->sb) { free(p); return NULL; }

    /* Above the verifier, so an arriving segment always wins over a signature
     * check. It spends nearly all of its life blocked on the socket. */
    if (xTaskCreatePinnedToCore(prefetch_task, "prefetch", PREFETCH_STACK, p,
                                2, &p->task, core) != pdPASS) {
        vStreamBufferDelete(p->sb);
        free(p);
        return NULL;
    }
    return p;
}

lc_reader *prefetch_reader(RpcPrefetch *p) { return p ? &p->base : NULL; }

void prefetch_stop(RpcPrefetch *p)
{
    if (!p) return;
    p->stop = true;
    while (!p->exited) delay(5);
    delay(10);                  /* let the idle task reap the stack */
    vStreamBufferDelete(p->sb);
    free(p);
}
