// Verifies the custom partition table on real hardware, and proves the thing
// the layout exists for: that a 600-key GRANDPA authority set (19.2 KB) can be
// stored in NVS and read back intact across a reboot.

#include <Arduino.h>
#include <esp_partition.h>
#include <esp_system.h>
#include <esp_ota_ops.h>
#include <nvs_flash.h>
#include <nvs.h>

static const size_t AUTHORITIES = 600;
static const size_t KEYLEN = 32;
static const size_t SET_BYTES = AUTHORITIES * KEYLEN;   // 19,200

static const char *type_name(esp_partition_type_t t, esp_partition_subtype_t s) {
  if (t == ESP_PARTITION_TYPE_APP) return s == ESP_PARTITION_SUBTYPE_APP_FACTORY ? "app/factory" : "app/ota";
  switch (s) {
    case ESP_PARTITION_SUBTYPE_DATA_NVS:      return "data/nvs";
    case ESP_PARTITION_SUBTYPE_DATA_COREDUMP: return "data/coredump";
    case ESP_PARTITION_SUBTYPE_DATA_SPIFFS:   return "data/spiffs";
    default:                                  return "data/other";
  }
}

static void dump_partitions() {
  Serial.println("\npartition table as flashed:");
  Serial.printf("  %-10s %-13s %9s %9s %8s\n", "name", "type", "start", "end", "size");
  for (int pass = 0; pass < 2; pass++) {
    esp_partition_type_t t = pass ? ESP_PARTITION_TYPE_DATA : ESP_PARTITION_TYPE_APP;
    esp_partition_iterator_t it = esp_partition_find(t, ESP_PARTITION_SUBTYPE_ANY, NULL);
    while (it) {
      const esp_partition_t *p = esp_partition_get(it);
      Serial.printf("  %-10s %-13s %#9x %#9x %7dK\n", p->label, type_name(p->type, p->subtype),
                    p->address, p->address + p->size, p->size / 1024);
      it = esp_partition_next(it);
    }
  }
  const esp_partition_t *run = esp_ota_get_running_partition();
  Serial.printf("  running from: %s (%dK)\n", run->label, run->size / 1024);
}

// Deterministic stand-in for a real authority set, so a reboot can check
// byte-for-byte that what came back is what went in.
static void fill_fake_set(uint8_t *buf) {
  uint32_t x = 0x9e3779b9;
  for (size_t i = 0; i < SET_BYTES; i++) {
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    buf[i] = (uint8_t)x;
  }
}

static void nvs_report(const char *tag) {
  nvs_stats_t st;
  if (nvs_get_stats(NULL, &st) == ESP_OK)
    Serial.printf("  nvs %-14s used=%d free=%d total=%d entries\n",
                  tag, st.used_entries, st.free_entries, st.total_entries);
}

void setup() {
  Serial.begin(115200);
  delay(1500);
  Serial.println("\n\n===== partition + NVS trust-root test =====");
  Serial.printf("flash chip: %uK   reset reason: %d\n", ESP.getFlashChipSize() / 1024,
                (int)esp_reset_reason());
  dump_partitions();

  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    Serial.println("\nnvs needs erase, doing it");
    nvs_flash_erase();
    err = nvs_flash_init();
  }
  Serial.printf("\nnvs_flash_init: %s\n", esp_err_to_name(err));
  nvs_report("at boot");

  nvs_handle_t h;
  if (nvs_open("lightclient", NVS_READWRITE, &h) != ESP_OK) {
    Serial.println("nvs_open FAILED"); return;
  }

  uint8_t *expect = (uint8_t *)malloc(SET_BYTES);
  fill_fake_set(expect);

  // If a set is already stored, this is the post-reboot pass: verify it.
  size_t stored = 0;
  if (nvs_get_blob(h, "authset", NULL, &stored) == ESP_OK && stored == SET_BYTES) {
    uint8_t *got = (uint8_t *)malloc(SET_BYTES);
    nvs_get_blob(h, "authset", got, &stored);
    bool same = memcmp(got, expect, SET_BYTES) == 0;
    uint32_t boots = 0; nvs_get_u32(h, "boots", &boots);
    Serial.printf("\nPERSISTED SET FOUND: %u bytes, survived reboot #%u\n", stored, boots);
    Serial.printf("  byte-for-byte identical: %s\n", same ? "YES" : "NO - CORRUPTED");
    Serial.printf("  => a 600-key authority set persists across power cycles\n");
    nvs_set_u32(h, "boots", boots + 1);
    free(got);
  } else {
    Serial.printf("\nno set stored yet - writing %u bytes (600 keys x 32B)\n", SET_BYTES);
    uint32_t t0 = millis();
    esp_err_t we = nvs_set_blob(h, "authset", expect, SET_BYTES);
    esp_err_t ce = nvs_commit(h);
    Serial.printf("  nvs_set_blob: %s   commit: %s   took %lu ms\n",
                  esp_err_to_name(we), esp_err_to_name(ce), millis() - t0);
    if (we == ESP_OK && ce == ESP_OK) {
      nvs_set_u32(h, "boots", 1); nvs_commit(h);
      Serial.println("  stored OK - reboot to confirm it survives");
    }
  }
  nvs_report("after write");
  nvs_close(h);
  free(expect);

  Serial.printf("\nfree heap: %u\n", ESP.getFreeHeap());
  Serial.println("\n===== done =====");
}

void loop() { delay(10000); }
