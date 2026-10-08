#include "sigpool.h"

#include <Arduino.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <freertos/semphr.h>
#include <freertos/task.h>
#include <stdlib.h>
#include <string.h>

/* Four is enough to keep the worker fed: one being verified, three queued, and
 * a ~20 ms check is long compared to the time the verifier needs to read and
 * screen the next 132-byte record. Deeper only lets the reader run ahead. */
#define SIGPOOL_DEPTH 4
#define SIGPOOL_STACK 8192

/* The signature and key are copied because they point into the verifier's
 * record buffer, which is reused on the very next iteration. The message is
 * not: it is the 53-byte localized payload, identical for every precommit and
 * guaranteed valid until join() returns. */
typedef struct {
    uint8_t sig[64];
    uint8_t pk[32];
    const uint8_t *msg;
    size_t msg_len;
    /* The signer's precomputed table, or NULL. Points into the authority set,
     * which is const flash for the life of the firmware, so unlike sig and pk
     * it is safe to keep as a pointer. */
    const void *tab;
} sigpool_job;

struct sigpool {
    grandpa_sig_pool iface;
    QueueHandle_t     jobs;
    SemaphoreHandle_t done;     /* counting: one give per completed check */
    TaskHandle_t      task;
    volatile bool     running;
    volatile bool     exited;
    uint32_t          taken;    /* submits accepted - written by the verifier */
    uint32_t          joined;   /* completions collected - written by the verifier */
    volatile uint32_t failed;   /* written by the worker, read after `done` */
    volatile uint32_t ran;      /* checks the worker performed */
};

/* Checks to run before letting the idle task have a tick. A ~20 ms check makes
 * this a yield roughly twice a second, which the watchdog is comfortable with
 * and which costs about 15 ms across a whole justification.
 *
 * It is not optional. This worker outranks IDLE0 and, once the queue is never
 * empty, xQueueReceive stops blocking - so the idle task never runs and the
 * task watchdog panics the board. That only started happening when the
 * transport got fast enough to keep the queue full, which is a good way to
 * discover that the network had been the thing scheduling this all along. */
#define SIGPOOL_YIELD_EVERY 32

static void sigpool_task(void *arg)
{
    sigpool *p = (sigpool *)arg;
    sigpool_job j;
    uint32_t since_yield = 0;

    while (p->running) {
        if (xQueueReceive(p->jobs, &j, pdMS_TO_TICKS(50)) != pdTRUE) {
            since_yield = 0;    /* blocking on the queue is itself a yield */
            continue;
        }
        if (!lc_ed25519_verify_tab(j.sig, j.msg, j.msg_len, j.pk, j.tab)) p->failed++;
        p->ran++;
        xSemaphoreGive(p->done);
        if (++since_yield >= SIGPOOL_YIELD_EVERY) {
            since_yield = 0;
            vTaskDelay(1);
        }
    }
    p->exited = true;
    vTaskDelete(NULL);
}

static int sigpool_submit(void *ctx, const uint8_t sig[64], const uint8_t *msg,
                          size_t msg_len, const uint8_t pk[32], const void *tab)
{
    sigpool *p = (sigpool *)ctx;
    sigpool_job j;
    memcpy(j.sig, sig, 64);
    memcpy(j.pk, pk, 32);
    j.msg = msg;
    j.msg_len = msg_len;
    j.tab = tab;

    /* Zero wait, always. A full queue means the worker is already saturated,
     * and the right answer is for the caller to do this one itself. */
    if (xQueueSend(p->jobs, &j, 0) != pdTRUE) return 0;
    p->taken++;
    return 1;
}

static uint32_t sigpool_join(void *ctx)
{
    sigpool *p = (sigpool *)ctx;
    while (p->joined < p->taken) {
        if (xSemaphoreTake(p->done, pdMS_TO_TICKS(10000)) != pdTRUE) break;
        p->joined++;
    }
    /* Every completion has been observed through the semaphore, so the worker's
     * writes to `failed` are visible here. A timeout above can only happen if
     * the worker died; counting the abandoned checks as failures keeps this
     * failing closed. */
    return p->failed + (p->taken - p->joined);
}

sigpool *sigpool_start(int worker_core)
{
    sigpool *p = (sigpool *)calloc(1, sizeof *p);
    if (!p) return NULL;

    p->jobs = xQueueCreate(SIGPOOL_DEPTH, sizeof(sigpool_job));
    p->done = xSemaphoreCreateCounting(GRANDPA_MAX_AUTHORITIES, 0);
    if (!p->jobs || !p->done) { sigpool_stop(p); return NULL; }

    p->running = true;
    p->iface.submit = sigpool_submit;
    p->iface.join   = sigpool_join;
    p->iface.ctx    = p;

    /* Same priority as the loop task: neither core should be able to starve the
     * other, and the reader that outranks both is what keeps the socket drained. */
    if (xTaskCreatePinnedToCore(sigpool_task, "sigpool", SIGPOOL_STACK, p,
                                1, &p->task, worker_core) != pdPASS) {
        p->running = false;
        p->task = NULL;
        sigpool_stop(p);
        return NULL;
    }
    return p;
}

void sigpool_stop(sigpool *p)
{
    if (!p) return;
    if (p->task) {
        p->running = false;
        /* The worker polls the queue with a 50 ms timeout, so it notices. */
        while (!p->exited) delay(5);
        delay(10);              /* let the idle task reap the stack */
    }
    if (p->jobs) vQueueDelete(p->jobs);
    if (p->done) vSemaphoreDelete(p->done);
    free(p);
}

const grandpa_sig_pool *sigpool_iface(sigpool *p) { return p ? &p->iface : NULL; }

uint32_t sigpool_worker_sigs(const sigpool *p) { return p ? p->ran : 0; }
