#pragma once
#include <stdint.h>
#include "transport.h"
void door_begin();
void door_fail();
bool door_read(RpcSession &session, const uint8_t root[32], const uint8_t block_hash[32],
               uint32_t block, uint64_t timestamp_ms, uint32_t relay_block);
bool door_enabled();
