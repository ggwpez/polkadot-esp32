#include <Arduino.h>
#include <WiFi.h>
#include <SPI.h>
#include <MFRC522.h>
#include <mbedtls/md.h>
#include <time.h>
#include <math.h>
#include "door.h"
#include "door_policy.h"
#include "ui.h"
#include "door_animation.h"
#if __has_include("door.local.h")
#include "door.local.h"
#else
#include "door.local.h.example"
#endif

static door_policy_state state;
static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
static MFRC522 reader(5, 22);
static bool active;
// Display metadata is published with the accepted policy under mux.
static bool have_sync;
static uint32_t synced_ms, synced_relay;
static uint8_t proof_buf[8192];
static trie_node_ref nodes[64];

static void hex(const uint8_t *v, size_t len, char *out) {
    static const char digits[] = "0123456789abcdef";
    *out++='0'; *out++='x';
    for (size_t i=0;i<len;i++) { *out++=digits[v[i]>>4]; *out++=digits[v[i]&15]; }
    *out=0;
}
bool door_enabled() { return active; }
void door_fail() {
    portENTER_CRITICAL(&mux); door_policy_invalidate(&state); portEXIT_CRITICAL(&mux);
}

static void task(void *) {
    bool denied=false;
    uint32_t denied_ms=0;
    DoorAnimation animation;
    animation.animation_ms=millis();
    SPI.begin(); reader.PCD_Init(); reader.PCD_SetAntennaGain(reader.RxGain_max);
    const byte version = reader.PCD_ReadRegister(MFRC522::VersionReg);
    Serial.printf("door: MFRC522 version 0x%02X, OLED mock only\n", version);
    for (;;) {
        if (WiFi.status()!=WL_CONNECTED) door_fail();
        portENTER_CRITICAL(&mux);
        bool remote = !memcmp(state.policy,"DOR2",4);
        portEXIT_CRITICAL(&mux);
        bool scanned = !remote && reader.PICC_IsNewCardPresent() && reader.PICC_ReadCardSerial();
        if (scanned) {
            uint8_t message[9+32+1+10], digest[32];
            memcpy(message,"door-key:",9);
            uint32_t revision;
            portENTER_CRITICAL(&mux);
            memcpy(message+9,state.policy+8,32); revision=state.revision;
            portEXIT_CRITICAL(&mux);
            size_t n=reader.uid.size;
            bool valid = n==4 || n==7 || n==10;
            if (valid) {
                message[41]=(uint8_t)n; memcpy(message+42,reader.uid.uidByte,n);
                valid = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    DOOR_PEPPER,32,message,42+n,digest)==0;
            }
            portENTER_CRITICAL(&mux);
            bool admitted=valid && revision==state.revision && door_policy_scan(&state,digest,millis());
            if (!admitted) state.opened=false;
            portEXIT_CRITICAL(&mux);
            denied=!admitted;
            if (denied) denied_ms=millis();
            Serial.printf("door: tag %s\n",admitted ? "allowed / OPEN" : "denied / CLOSED");
            reader.PICC_HaltA(); reader.PCD_StopCrypto1();
        }
        unsigned key_count=0;
        portENTER_CRITICAL(&mux);
        const uint32_t now=millis();
        bool unlocked=door_policy_unlocked(&state,now);
        bool fresh=door_policy_fresh(&state,now);
        bool synced=have_sync;
        uint32_t age_s=(uint32_t)(now-synced_ms)/1000, relay=synced_relay;
        bool toggle=!memcmp(state.policy,"DOR2",4);
        if (fresh && !toggle) {
            for (unsigned slot=0;slot<11;slot++) {
                uint8_t present=0;
                for (unsigned j=0;j<32;j++) present|=state.policy[40+slot*32+j];
                if (present) key_count++;
            }
        }
        portEXIT_CRITICAL(&mux);
        char key_label[22];
        snprintf(key_label,sizeof key_label,"auth keys: %u",key_count);
        uint32_t denied_elapsed=(uint32_t)(millis()-denied_ms);
        if (denied && denied_elapsed>=3000) denied=false;
        animation.tick(now,unlocked,denied,denied_ms);
        ui_door(unlocked,animation.hide_label,fresh,synced,age_s,relay,key_label,
                animation.icon_openness,animation.shake_x);
        vTaskDelay(pdMS_TO_TICKS(animation.animating || animation.opening_flash || animation.shaking ? 25 : 100));
    }
}
void door_begin() {
    active=true;
    configTime(0,0,"pool.ntp.org","time.cloudflare.com");
    if (xTaskCreatePinnedToCore(task,"door",4096,nullptr,1,nullptr,0)!=pdPASS) {
        active=false; Serial.println("door: task allocation failed; no admission");
    }
}

bool door_read(RpcSession &session,const uint8_t root[32],const uint8_t hash[32],
               uint32_t block,uint64_t timestamp_ms,uint32_t relay_block) {
    if (!DOOR_CONFIGURED || !active) { door_fail(); return false; }
    char at[67], child[2*sizeof DOOR_CHILD_KEY+3], key[2*sizeof DOOR_STORAGE_KEY+3];
    hex(hash,32,at); hex(DOOR_CHILD_KEY,sizeof DOOR_CHILD_KEY,child);
    hex(DOOR_STORAGE_KEY,sizeof DOOR_STORAGE_KEY,key);
    const char *keys[]={child};
    trie_proof proof; trie_proof_init(&proof,nodes,64);
    const uint8_t *value; size_t len;
    if (transport_fetch_read_proof(session,keys,1,at,proof_buf,sizeof proof_buf,&proof)!=LC_T_OK ||
        trie_lookup(root,DOOR_CHILD_KEY,sizeof DOOR_CHILD_KEY,&proof,&value,&len)!=TRIE_FOUND || len!=32) {
        door_fail(); return false;
    }
    uint8_t child_root[32]; memcpy(child_root,value,32);
    keys[0]=key; trie_proof_init(&proof,nodes,64);
    if (transport_fetch_read_proof(session,keys,1,at,proof_buf,sizeof proof_buf,&proof,child)!=LC_T_OK ||
        trie_lookup(child_root,DOOR_STORAGE_KEY,sizeof DOOR_STORAGE_KEY,&proof,&value,&len)!=TRIE_FOUND) {
        door_fail(); return false;
    }
    uint64_t epoch_ms=(uint64_t)time(nullptr)*1000;
    portENTER_CRITICAL(&mux);
    bool ok=door_policy_accept(&state,value,len,block,timestamp_ms,epoch_ms,millis());
    if (ok) { have_sync=true; synced_ms=millis(); synced_relay=relay_block; }
    uint32_t revision=state.revision;
    portEXIT_CRITICAL(&mux);
    unsigned allowed=0;
    if (ok && len==DOOR_POLICY_LEN) for (size_t slot=40;slot<len;slot+=32) {
        uint8_t present=0;
        for (size_t j=0;j<32;j++) present|=value[slot+j];
        allowed+=present!=0;
    }
    Serial.printf("door: policy %s at Asset Hub #%u, revision %u, %u allowed keys, chain age %lld ms\n",
                  ok?"proven and fresh":"rejected",block,revision,allowed,(long long)epoch_ms-(long long)timestamp_ms);
    if (ok && len==9) Serial.printf("door: public toggle %s, revision %u\n",value[8]?"OPEN":"CLOSED",revision);
    return ok;
}
