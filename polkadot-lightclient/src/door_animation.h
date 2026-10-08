// Shared animation state: milliseconds, independent of hardware/wall clock.
#pragma once
#include <stdint.h>
#include <math.h>

struct DoorAnimation {
    bool was_unlocked = false, opening_flash = false;
    uint32_t opening_ms = 0, animation_ms = 0;
    float icon_openness = 0.0f;
    bool animating = false, hide_label = false, shaking = false;
    int8_t shake_x = 0;

    void tick(uint32_t now, bool unlocked, bool denied, uint32_t denied_ms) {
        uint32_t denied_elapsed = now - denied_ms;
        if (unlocked && !was_unlocked) {
            opening_ms = now;
            opening_flash = true;
        }
        uint32_t opening_elapsed = now - opening_ms;
        if (!unlocked || opening_elapsed >= 600) opening_flash = false;
        // Reversals continue from the current position, without jumping.
        float step = unlocked == was_unlocked ? (uint32_t)(now-animation_ms)/600.0f : 0.0f;
        animation_ms = now;
        icon_openness = fminf(1.0f, fmaxf(0.0f, icon_openness + (unlocked ? step : -step)));
        animating = icon_openness != (unlocked ? 1.0f : 0.0f);
        was_unlocked = unlocked;
        hide_label = unlocked ? (opening_flash && opening_elapsed >= 300)
                              : (denied && denied_elapsed < 300);
        shaking = denied && denied_elapsed < 720;
        float p = shaking ? denied_elapsed/720.0f : 1.0f;
        shake_x = lroundf(3.0f*(1.0f-p)*sinf(6.0f*3.14159265358979323846*p));
    }
};
