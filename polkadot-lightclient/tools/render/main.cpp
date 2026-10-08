// Receives one complete state per video frame; emits 128x64 gray8 pixels.
#include <Adafruit_GFX.h>
#include <iostream>
#include <string>
#include "door_screen.h"
#include "door_animation.h"

struct Screen : GFXcanvas1 {
    Screen() : GFXcanvas1(128, 64) {}
    void clearDisplay() { fillScreen(0); }
    void display() {}
};

int main() {
    Screen screen;
    DoorAnimation animation;
    uint32_t now, age, relay, denied_ms;
    uint64_t closed_event, previous_closed_event = 0;
    bool unlocked, fresh, synced, denied;
    std::string label;
    while (std::cin >> now >> unlocked >> fresh >> synced >> age >> relay >> denied >> denied_ms >> closed_event) {
        std::getline(std::cin, label);
        if (!label.empty()) label.erase(0, 1);
        // Explicit repeated close commands replay the full closing motion.
        // Ordinary open-to-close transitions retain their current position.
        if (closed_event != previous_closed_event && !unlocked && !denied && !animation.was_unlocked) {
            animation.icon_openness = 1.0f;
            animation.animation_ms = now;
        }
        previous_closed_event = closed_event;
        animation.tick(now, unlocked, denied, denied_ms);
        draw_door_screen(screen, unlocked, animation.hide_label, fresh, synced,
                         age, relay, label.c_str(), animation.icon_openness, animation.shake_x);
        uint8_t pixels[128 * 64];
        for (int y = 0; y < 64; ++y)
            for (int x = 0; x < 128; ++x)
                pixels[y*128+x] = screen.getPixel(x, y) ? 255 : 0;
        std::cout.write(reinterpret_cast<char *>(pixels), sizeof pixels);
        if (!std::cout) return 1;
    }
    return std::cin.eof() ? 0 : 1;
}
