// Shared by the SSD1306 firmware and the offline video renderer.
#pragma once
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

template <typename Display>
void draw_door_screen(Display &oled, bool unlocked, bool hide_label, bool fresh, bool synced,
             uint32_t age_s, uint32_t relay_block, const char *key_label,
             float icon_openness, int8_t shake_x)
{
    const int COLS = 21;
    auto text_fit = [&oled](int x, int y, const char *text) {
        char line[22];
        snprintf(line, sizeof line, "%s", text ? text : "");
        if (text && strlen(text) > 21) line[20] = '~';
        oled.setCursor(x, y);
        oled.print(line);
    };
    oled.clearDisplay(); oled.setTextColor(1);
    oled.setTextSize(1);
    char status[40];
    if (!synced) snprintf(status,sizeof status,"SYNC waiting");
    else {
        snprintf(status,sizeof status,"%s %lus R%lu",fresh ? "OK" : "STALE",
                 (unsigned long)age_s,(unsigned long)relay_block);
        // Preserve exact seconds; omit the block if the full number won't fit.
        if (strlen(status)>COLS)
            snprintf(status,sizeof status,"%s %lus ago",fresh ? "OK" : "STALE",
                     (unsigned long)age_s);
    }
    text_fit(0,0,status);
    if (!hide_label) {
        const char *label = unlocked ? "OPEN" : "CLOSED";
        // Center both labels in the 80-pixel text area beside the symbol.
        // The built-in font has 12-pixel cells at size 2, with a 2-pixel gap.
        const int label_width = strlen(label) * 12 - 2;
        oled.setTextSize(2);
        oled.setCursor((80 - label_width) / 2,21);
        oled.print(label);
    }
    // Rotate 0 -> 120 degrees while opening, then 120 -> 240 while closing.
    // The equilateral symbol repeats every 120 degrees. Smoothstep eases both ends.
    if (icon_openness>0.0f) {
        float p=fminf(1.0f,fmaxf(0.0f,icon_openness));
        p=p*p*(3.0f-2.0f*p);
        const float angle=(unlocked ? p : 2.0f-p)*2.0f*3.14159265358979323846/3.0f;
        const float c=cosf(angle), s=sinf(angle);
        // Equilateral geometry makes all three sectors congruent. Keep
        // subpixel coordinates until the final rotation to avoid skewing them.
        const float half_width=7.0f*sqrtf(3.0f);
        const float vertices[3][3][2]={
            {{0,-14},{-half_width,7},{0,0}},
            {{0,-14},{half_width,7},{0,0}},
            {{-half_width,7},{half_width,7},{0,0}}
        };
        // Equal eight-pixel travel along each sector's radial bisector.
        const float spread_x=4.0f*sqrtf(3.0f);
        const float offset[3][2]={{-spread_x,-4},{spread_x,-4},{0,8}};
        for (unsigned piece=0;piece<3;piece++) {
            int16_t x[3], y[3];
            for (unsigned v=0;v<3;v++) {
                float dx=vertices[piece][v][0]+offset[piece][0]*p;
                float dy=vertices[piece][v][1]+offset[piece][1]*p;
                x[v]=lroundf(103+dx*c-dy*s)+shake_x;
                y[v]=lroundf(29+dx*s+dy*c);
            }
            oled.fillTriangle(x[0],y[0],x[1],y[1],x[2],y[2],1);
        }
    } else {
        oled.fillTriangle(103+shake_x,15,91+shake_x,36,115+shake_x,36,1);
    }
    oled.setTextSize(1);
    text_fit(0,48,key_label);
    oled.display();
}
