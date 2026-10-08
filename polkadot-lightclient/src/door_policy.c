#include "door_policy.h"
#include <string.h>

void door_policy_invalidate(door_policy_state *s) { s->ready = s->opened = false; }
bool door_policy_fresh(const door_policy_state *s, uint32_t now) {
    return s->ready && (uint32_t)(now - s->received_ms) < DOOR_MAX_AGE_MS;
}
bool door_policy_accept(door_policy_state *s, const uint8_t *v, size_t len,
                        uint32_t block, uint64_t stamp, uint64_t epoch, uint32_t now) {
    uint32_t revision = len >= 8 ? (uint32_t)v[4] | (uint32_t)v[5]<<8 |
        (uint32_t)v[6]<<16 | (uint32_t)v[7]<<24 : 0;
    bool toggle = len == 9 && !memcmp(v, "DOR2", 4) && v[8] <= 1;
    if ((!toggle && (len != DOOR_POLICY_LEN || memcmp(v, "DOR1", 4))) ||
        epoch < 1700000000000ULL || stamp > epoch + 5000 ||
        (epoch > stamp && epoch - stamp >= DOOR_MAX_AGE_MS) ||
        block < s->block || (block > s->block && stamp < s->timestamp_ms) || revision < s->revision) {
        door_policy_invalidate(s);
        return false;
    }
    // Repeated relay anchors can contain the same parachain block. Keep the
    // original monotonic deadline; duplicate proofs never renew freshness.
    if (block == s->block) {
        bool same = stamp == s->timestamp_ms && !memcmp(s->policy, v, len);
        if (!same || !door_policy_fresh(s, now)) {
            door_policy_invalidate(s);
            return false;
        }
        return true;
    }
    bool same_timestamp = stamp == s->timestamp_ms;
    if (same_timestamp && (uint32_t)(now-s->received_ms) >= DOOR_MAX_AGE_MS) {
        door_policy_invalidate(s);
        return false;
    }
    // Every accepted update closes an existing unlock if its policy changed.
    if (memcmp(s->policy, v, len)) s->opened = false;
    memset(s->policy, 0, sizeof s->policy);
    memcpy(s->policy, v, len);
    s->block = block; s->revision = revision; s->timestamp_ms = stamp;
    // Carry the chain's existing age into the monotonic deadline.
    if (!same_timestamp)
        s->received_ms = now - (uint32_t)(epoch > stamp ? epoch - stamp : 0);
    s->ready = true;
    return true;
}
bool door_policy_scan(door_policy_state *s, const uint8_t digest[32], uint32_t now) {
    s->opened = false;
    if (!door_policy_fresh(s, now) || !memcmp(s->policy, "DOR2", 4)) return false;
    uint8_t nonzero = 0;
    for (size_t i=0; i<32; i++) nonzero |= digest[i];
    if (!nonzero) return false;
    for (size_t slot=0; slot<11; slot++) {
        uint8_t difference = 0;
        for (size_t i=0; i<32; i++) difference |= digest[i] ^ s->policy[40+32*slot+i];
        if (!difference) { s->opened = true; s->opened_ms = now; return true; }
    }
    return false;
}
bool door_policy_unlocked(door_policy_state *s, uint32_t now) {
    if (!memcmp(s->policy, "DOR2", 4))
        return door_policy_fresh(s, now) && s->policy[8] == 1;
    if (!door_policy_fresh(s, now) || (uint32_t)(now-s->opened_ms) >= DOOR_UNLOCK_MS)
        s->opened = false;
    return s->opened;
}
