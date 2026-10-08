#ifndef DOOR_POLICY_H
#define DOOR_POLICY_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define DOOR_POLICY_LEN 392
#define DOOR_MAX_AGE_MS 120000
#define DOOR_UNLOCK_MS 3000
typedef struct {
    uint8_t policy[DOOR_POLICY_LEN];
    uint32_t block, revision, received_ms, opened_ms;
    uint64_t timestamp_ms;
    bool ready, opened;
} door_policy_state;
void door_policy_invalidate(door_policy_state *s);
bool door_policy_accept(door_policy_state *s, const uint8_t *value, size_t len,
                        uint32_t block, uint64_t timestamp_ms, uint64_t now_epoch_ms,
                        uint32_t now_ms);
bool door_policy_fresh(const door_policy_state *s, uint32_t now_ms);
bool door_policy_scan(door_policy_state *s, const uint8_t digest[32], uint32_t now_ms);
bool door_policy_unlocked(door_policy_state *s, uint32_t now_ms);
#ifdef __cplusplus
}
#endif
#endif
