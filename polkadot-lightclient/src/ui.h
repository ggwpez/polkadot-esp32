/* Optional 128x64 SSD1306 status display (I2C, SDA GPIO25 / SCL GPIO26).
 *
 * The screen is a window onto what the serial log already says, and nothing
 * more: it is never a source of truth and never gates verification. If no panel
 * answers on the bus every call here is a no-op, so an unplugged display cannot
 * change what the device does or how fast it does it.
 *
 * Two rules the layout exists to enforce:
 *
 *   - only proven values are shown. A number reaches this module after the
 *     signatures and the Merkle proofs have already checked out, never before.
 *   - a stale screen has to look stale. A frozen panel showing last hour's block
 *     number is worse than a blank one, so every data view carries the age of
 *     the anchor and the header flips from PROVEN to STALE once a refresh fails.
 *
 * Building with -DUI_DUMP_FRAMES=N prints the first N distinct frames to serial
 * as ASCII art. Layout bugs here are silent - a line one character too long is
 * clipped, not flagged - so checking the panel without being in the room is
 * worth the twenty lines it costs.
 */
#ifndef UI_H
#define UI_H

#include <stdint.h>

void ui_begin(void);
bool ui_present(void);

/* Repaints if anything time-dependent moved. Cheap to call in a spin loop. */
void ui_tick(void);

void ui_boot(const char *line1, const char *line2);
void ui_net(bool up, int rssi);
/* Deliberately takes no SSID. The panel is the one part of this device that
 * shows itself to whoever is in the room, and the network's name is the one
 * thing on it that says something about the owner rather than about the chain.
 * There is exactly one configured network, so naming it told nobody anything
 * they needed. */
void ui_joining(int attempt, int attempts);

/* One refresh cycle, drawn as one bar that fills once from empty to full.
 *
 * stage() names the step and claims its slice of that bar, [from_pct, to_pct].
 * The slices are the measured share of a cycle each step costs, not equal
 * steps: signature verification is four fifths of the work, so it gets four
 * fifths of the bar. Equal slices would park the bar at 20% for four seconds
 * and then cross the remaining 80% in one, which is a worse lie than no bar.
 * The boundaries live next to the call sites in main.cpp; PLAN.md 12 has the
 * measurements they came from.
 *
 * Entering a stage puts the bar at the start of its slice and leaves it there,
 * so the bar always reads as "at least this much is done". progress() moves it
 * inside the current slice and is fed straight from the GRANDPA verifier's own
 * counter - it is the only step that can count itself.
 *
 * progress() does not touch the stage or the slice, so a caller that starts
 * counting has to say what it is counting first. Signature verification once
 * inherited "getting justification" from the call before it and wore that
 * label for four fifths of the cycle. */
void ui_sync_begin(uint32_t cycle);
void ui_stage(const char *stage, uint8_t from_pct, uint8_t to_pct);
void ui_progress(uint32_t done, uint32_t total, const char *detail);

/* `value` is pre-formatted for a 21-column line by the caller. */
void ui_proven(uint32_t relay_number, uint32_t ah_number, const char *value,
               uint32_t valid_sigs, uint32_t authorities, uint64_t set_id);
void ui_failed(const char *why);

/* Held between cycles. There is no countdown to show - the next cycle starts
 * when the chain finalizes a block, not when a timer expires - so the header
 * carries the age of the proof instead. */
void ui_idle(void);

// key_label is a 21-column summary of the currently proven authorized keys.
void ui_door(bool unlocked, bool hide_label, bool fresh, bool synced,
             uint32_t age_s, uint32_t relay_block, const char *key_label,
             float icon_openness, int8_t shake_x);

#endif
