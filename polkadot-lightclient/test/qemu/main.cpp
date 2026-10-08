#include <Arduino.h>

/* Some malformed-proof tests use sizeable stack buffers. Match main.cpp. */
SET_LOOP_TASK_STACK_SIZE(16384);
extern "C" int qemu_core_tests(void);
extern "C" int qemu_door_tests(void);

void setup() {
    Serial.begin(115200);
    delay(200);
    Serial.println("QEMU: ESP32 offline regression tests");
    Serial.println("QEMU: captured devnet proofs; no Wi-Fi, RFID or OLED hardware");
    int failed = qemu_core_tests();
    failed |= qemu_door_tests();
    Serial.println(failed ? "QEMU_TESTS_FAILED" : "QEMU_TESTS_PASSED");
    Serial.flush();
}

void loop() { delay(1000); }
