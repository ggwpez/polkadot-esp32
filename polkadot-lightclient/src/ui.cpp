#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <Arduino.h>
#include <Wire.h>
#include <math.h>

#include "fmt.h"
#include "ui.h"
#include "door_screen.h"
#include "door.h"

static const int SDA_PIN = 25;
static const int SCL_PIN = 26;
static const int W = 128;
static const int H = 64;

/* 400 kHz: a full frame is 1024 bytes, which at the 100 kHz default blocks for
 * ~90 ms. The verifier is already the slow part of a cycle; the screen should
 * not add to it. */
static const uint32_t I2C_HZ = 400000;

/* Text is 6x8 at size 1, so the panel is exactly 21 columns by 8 rows. Every
 * string below is written to fit 21 characters rather than relying on the
 * library to clip, because clipping silently turns a wrong value into a
 * plausible one. */
static const int COLS = 21;

static Adafruit_SSD1306 oled(W, H, &Wire, -1);
static uint8_t addr;

enum View { V_BOOT, V_JOIN, V_SYNC, V_DATA, V_FAIL };

static struct {
    View     view;

    char     boot1[COLS + 1], boot2[COLS + 1];
    char     stage[COLS + 1], detail[COLS + 1];
    char     fail[4 * COLS + 1];

    uint32_t cycle;
    uint32_t sync_started;

    /* One bar per cycle, in permille so that the ~80 percent slice signature
     * verification owns still moves smoothly across 400-odd callbacks. from/to
     * are the slice the current stage was given; permille is where the bar
     * actually is. */
    uint16_t permille;
    uint8_t  from_pct, to_pct;

    bool     net_up;
    int      rssi;

    bool     have_data;          /* a full cycle has succeeded at least once */
    uint32_t relay, ah;
    char     value[COLS + 1];
    uint32_t valid_sigs, authorities;
    uint64_t set_id;
    uint32_t proven_at;          /* millis() of the last successful cycle */
    bool     stale;              /* the most recent cycle did not succeed */

    uint32_t failed_at;          /* millis() of the last ui_failed() */
    uint32_t last_paint;         /* so ui_tick() repaints at most once a second */
} s;

/* ---------- plumbing ---------- */

static uint8_t find_display(void)
{
    for (uint8_t a = 0x3C; a <= 0x3D; a++) {
        Wire.beginTransmission(a);
        if (Wire.endTransmission() == 0) return a;
    }
    return 0;
}

/* Text too long for the panel is cut with a visible '~' rather than silently.
 * A clipped block number that still reads as a plausible block number is the
 * one failure a status display must not have. */
static void copy_fit(char *dst, size_t cap, const char *src)
{
    if (!src) src = "";
    size_t i = 0;
    while (src[i] && i + 1 < cap) { dst[i] = src[i]; i++; }
    dst[i] = 0;
    if (src[i] && cap >= 2) dst[cap - 2] = '~';
}

/* "12s", "4m", "2h" - short enough for a corner, coarse enough to be honest. */
static void fmt_age(uint32_t ms, char *out, size_t cap)
{
    uint32_t sec = ms / 1000;
    if (sec < 60)        snprintf(out, cap, "%us", (unsigned)sec);
    else if (sec < 3600) snprintf(out, cap, "%um", (unsigned)(sec / 60));
    else                 snprintf(out, cap, "%uh", (unsigned)(sec / 3600));
}

static void text_at(int x, int y, const char *str)
{
    oled.setCursor(x, y);
    oled.print(str);
}

/* Same rule for strings composed at draw time. */
static void text_fit(int x, int y, const char *str)
{
    char line[COLS + 1];
    copy_fit(line, sizeof line, str);
    text_at(x, y, line);
}

/* Right-aligned, stopping short of the Wi-Fi glyph in the corner. */
static void text_right(int y, const char *str)
{
    int x = 114 - 6 * (int)strlen(str);
    text_at(x < 0 ? 0 : x, y, str);
}

/* Four rising bars, or a struck-through stub when the radio is down. Signal
 * strength is worth a corner: almost every failure this device can have while
 * unattended is a network failure. */
static void draw_wifi(void)
{
    const int x0 = 116, base = 8;
    if (!s.net_up) {
        oled.drawLine(x0, 1, x0 + 8, 8, SSD1306_WHITE);
        oled.drawLine(x0 + 8, 1, x0, 8, SSD1306_WHITE);
        return;
    }
    int bars = 0;
    if (s.rssi >= -85) bars = 1;
    if (s.rssi >= -75) bars = 2;
    if (s.rssi >= -65) bars = 3;
    if (s.rssi >= -55) bars = 4;
    /* Filled bars are solid, empty ones are a stub on the baseline. An outline
     * would be indistinguishable from a fill at two pixels wide, which made
     * every signal level look like full strength. */
    for (int i = 0; i < 4; i++) {
        int h = 2 * (i + 1);
        if (i < bars) oled.fillRect(x0 + i * 3, base - h, 2, h, SSD1306_WHITE);
        else          oled.drawFastHLine(x0 + i * 3, base - 1, 2, SSD1306_WHITE);
    }
}

static void header(const char *left, const char *right)
{
    oled.setTextSize(1);
    oled.setTextColor(SSD1306_WHITE);
    text_at(0, 0, left);
    if (right) text_right(0, right);
    draw_wifi();
    oled.drawFastHLine(0, 10, W, SSD1306_WHITE);
}

static void progress_bar(int y, uint32_t permille)
{
    const int x = 0, w = W, h = 11;
    oled.drawRect(x, y, w, h, SSD1306_WHITE);
    if (permille > 1000) permille = 1000;
    int fill = (int)((uint64_t)(w - 4) * permille / 1000);
    if (fill > 0) oled.fillRect(x + 2, y + 2, fill, h - 4, SSD1306_WHITE);
}

/* ---------- views ---------- */

static void draw_boot(void)
{
    oled.setTextSize(1);
    text_at(0, 14, s.boot1);
    text_at(0, 26, s.boot2);
    text_at(0, 44, "waiting for network");
}

static void draw_join(void)
{
    oled.setTextSize(1);
    text_at(0, 20, s.stage);
    text_at(0, 34, s.detail);
}

static void draw_sync(void)
{
    oled.setTextSize(1);
    text_at(0, 14, s.stage);
    progress_bar(26, s.permille);
    text_at(0, 42, s.detail);

    /* The previous anchor stays on screen while the next one is being proven,
     * labelled as previous. A blank lower half during a 25-second refresh
     * reads as "nothing works". */
    if (s.have_data) {
        char line[COLS + 8], age[8];
        fmt_age(millis() - s.proven_at, age, sizeof age);
        snprintf(line, sizeof line, "last #%s %s", fmt_num(s.relay), age);
        text_fit(0, 54, line);
    }
}

static void draw_data(void)
{
    char line[COLS + 8];
    oled.setTextSize(1);

    snprintf(line, sizeof line, "relay  #%s", fmt_num(s.relay));
    text_fit(0, 14, line);
    snprintf(line, sizeof line, "hub    #%s", fmt_num(s.ah));
    text_fit(0, 24, line);

    text_at(0, 36, s.value);

    snprintf(line, sizeof line, "%u/%u sig  set %u", (unsigned)s.valid_sigs,
             (unsigned)s.authorities, (unsigned)s.set_id);
    text_fit(0, 48, line);

    /* Only once the numbers stop being current: a glance has to distinguish a
     * live panel from one frozen on last hour's block. */
    if (s.stale) {
        char age[8];
        fmt_age(millis() - s.proven_at, age, sizeof age);
        snprintf(line, sizeof line, "not refreshed for %s", age);
        text_fit(0, 56, line);
    }
}

static void draw_fail(void)
{
    oled.setTextSize(1);

    /* Wrap the reason on spaces. The reason is the whole point of this view, so
     * it gets the space, and the last known anchor is reduced to one line. */
    const char *p = s.fail;
    int y = 14;
    while (*p && y <= 40) {
        int take = COLS;
        if ((int)strlen(p) > COLS) {
            int brk = -1;
            for (int i = 0; i < COLS; i++) if (p[i] == ' ') brk = i;
            if (brk > 0) take = brk;
        } else {
            take = (int)strlen(p);
        }
        char line[COLS + 1];
        memcpy(line, p, take);
        line[take] = 0;
        text_at(0, y, line);
        y += 9;
        p += take;
        while (*p == ' ') p++;
    }

    if (s.have_data) {
        char line[COLS + 8], age[8];
        fmt_age(millis() - s.proven_at, age, sizeof age);
        snprintf(line, sizeof line, "last proof %s old", age);
        text_fit(0, 54, line);
    } else {
        text_at(0, 54, "nothing proven yet");
    }
}

static void render(void)
{
    if (door_enabled()) return;
    if (!addr) return;
    oled.clearDisplay();

    char left[COLS + 1], right[12];
    right[0] = 0;

    switch (s.view) {
    case V_BOOT:
        header("POLKADOT LC", 0);
        draw_boot();
        break;
    case V_JOIN:
        header("WI-FI", 0);
        draw_join();
        break;
    case V_SYNC:
        snprintf(left, sizeof left, "SYNC #%u", (unsigned)s.cycle);
        fmt_age(millis() - s.sync_started, right, sizeof right);
        header(left, right);
        draw_sync();
        break;
    case V_DATA:
        /* PROVEN means "this was checked and it held". Once a refresh fails the
         * numbers below are still true of an older block but no longer current,
         * and the header has to say so. */
        fmt_age(millis() - s.proven_at, right, sizeof right);
        header(s.stale ? "STALE" : "PROVEN", right);
        draw_data();
        break;
    case V_FAIL:
        fmt_age(millis() - s.sync_started, right, sizeof right);
        header("FAILED", right);
        draw_fail();
        break;
    }

    oled.display();
    s.last_paint = millis();

#ifdef UI_DUMP_FRAMES
    /* Layout check without being in the room: print the frame as ASCII. Only
     * the first few, and only when something worth looking at changed, or the
     * idle tick floods the log. Within a sync that means every stage, because
     * the bar is one bar across the whole cycle now and each stage is a step of
     * it - plus one frame from inside the signature slice, the only stretch
     * where the bar moves without the stage changing. */
    {
        static int left = UI_DUMP_FRAMES;
        static View seen = (View)-1;
        static char seen_stage[COLS + 1] = "";
        static bool mid = false;
        bool in_sync    = (s.view == V_SYNC);
        bool want_stage = in_sync && strcmp(s.stage, seen_stage) != 0;
        bool want_mid   = in_sync && !mid &&
                          s.permille > (uint16_t)s.from_pct * 10;
        if (left > 0 && (s.view != seen || want_stage || want_mid)) {
            if (want_mid) mid = true;
            if (in_sync) copy_fit(seen_stage, sizeof seen_stage, s.stage);
            left--; seen = s.view;
            const uint8_t *b = oled.getBuffer();
            Serial.printf("\n[frame view=%d]\n+", (int)s.view);
            for (int x = 0; x < W; x++) Serial.print("-");
            Serial.println("+");
            for (int y = 0; y < H; y++) {
                Serial.print("|");
                for (int x = 0; x < W; x++)
                    Serial.print((b[x + (y / 8) * W] >> (y & 7)) & 1 ? "#" : " ");
                Serial.println("|");
            }
            Serial.print("+");
            for (int x = 0; x < W; x++) Serial.print("-");
            Serial.println("+\n");
        }
    }
#endif
}

/* ---------- public ---------- */

void ui_begin(void)
{
    memset(&s, 0, sizeof s);
    s.view = V_BOOT;

    Wire.begin(SDA_PIN, SCL_PIN);
    Wire.setClock(I2C_HZ);
    addr = find_display();
    if (!addr) {
        Serial.println("display: none on the I2C bus, running headless");
        return;
    }
    if (!oled.begin(SSD1306_SWITCHCAPVCC, addr)) {
        Serial.println("display: found a device but SSD1306 init failed");
        addr = 0;
        return;
    }
    Serial.printf("display: SSD1306 at 0x%02X on SDA=%d SCL=%d\n", addr, SDA_PIN, SCL_PIN);
}

bool ui_present(void) { return addr != 0; }

void ui_tick(void)
{
    if (!addr) return;

    /* Hold a failure long enough to be read by someone walking past, then fall
     * back to the last proven anchor under a STALE header. Done here rather
     * than with a delay() in ui_failed(): the screen must never be able to slow
     * a refresh down. */
    if (s.view == V_FAIL && s.have_data && millis() - s.failed_at > 6000)
        s.view = V_DATA;

    if (millis() - s.last_paint >= 1000) render();   /* only the clocks moved */
}

void ui_boot(const char *line1, const char *line2)
{
    copy_fit(s.boot1, sizeof s.boot1, line1);
    copy_fit(s.boot2, sizeof s.boot2, line2);
    s.view = V_BOOT;
    render();
}

void ui_net(bool up, int rssi)
{
    s.net_up = up;
    s.rssi = rssi;
}

void ui_joining(int attempt, int attempts)
{
    snprintf(s.stage, sizeof s.stage, "joining the network");
    snprintf(s.detail, sizeof s.detail, "attempt %d of %d", attempt, attempts);
    s.net_up = false;
    s.view = V_JOIN;
    render();
}

void ui_sync_begin(uint32_t cycle)
{
    s.cycle = cycle;
    s.sync_started = millis();
    s.permille = 0;
    s.from_pct = s.to_pct = 0;
    s.stage[0] = s.detail[0] = 0;
    s.view = V_SYNC;
    /* No paint here: the caller's first ui_stage() does it. Rendering now would
     * cost a frame showing an empty body under a SYNC header. */
}

void ui_stage(const char *stage, uint8_t from_pct, uint8_t to_pct)
{
    copy_fit(s.stage, sizeof s.stage, stage);
    s.from_pct = from_pct;
    s.to_pct   = to_pct < from_pct ? from_pct : to_pct;
    /* The bar sits at the start of the slice for the whole step, so it always
     * reads as "at least this much is done" rather than running ahead of the
     * device. Only the step that can count itself moves inside its slice. */
    s.permille = (uint16_t)(from_pct * 10);
    s.detail[0] = 0;
    s.view = V_SYNC;
    render();
}

void ui_progress(uint32_t done, uint32_t total, const char *detail)
{
    if (total) {
        if (done > total) done = total;
        uint32_t span = (uint32_t)(s.to_pct - s.from_pct) * 10;
        s.permille = (uint16_t)(s.from_pct * 10 + span * done / total);
    }
    copy_fit(s.detail, sizeof s.detail, detail);
    s.view = V_SYNC;
    render();
}

void ui_proven(uint32_t relay_number, uint32_t ah_number, const char *value,
               uint32_t valid_sigs, uint32_t authorities, uint64_t set_id)
{
    s.relay = relay_number;
    s.ah = ah_number;
    copy_fit(s.value, sizeof s.value, value);
    s.valid_sigs = valid_sigs;
    s.authorities = authorities;
    s.set_id = set_id;
    s.proven_at = millis();
    s.have_data = true;
    s.stale = false;
    s.view = V_DATA;
    render();
}

void ui_failed(const char *why)
{
    door_fail();
    copy_fit(s.fail, sizeof s.fail, why);
    s.stale = true;
    s.failed_at = millis();
    s.view = V_FAIL;
    render();
}

void ui_idle(void)
{
    render();
}

// In door mode the RFID task exclusively owns OLED rendering, keeping the
// lock timer visible even while the network task waits on an unresponsive RPC.
void ui_door(bool unlocked, bool hide_label, bool fresh, bool synced,
             uint32_t age_s, uint32_t relay_block, const char *key_label,
             float icon_openness, int8_t shake_x)
{
    if (!addr) return;
    draw_door_screen(oled, unlocked, hide_label, fresh, synced, age_s,
                     relay_block, key_label, icon_openness, shake_x);
}
