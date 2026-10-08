/* Host adapter to the exact trie verifier compiled into the ESP32. */
#include "trie.h"
#include <string.h>
int door_verify(const uint8_t *root, const uint8_t *key, size_t key_len,
                const uint8_t *const *data, const size_t *lengths, size_t count,
                uint8_t *out, size_t cap) {
    trie_node_ref refs[64];
    trie_proof proof;
    if (count>64) return -1;
    trie_proof_init(&proof, refs, 64);
    for (size_t i=0;i<count;i++)
        if (trie_proof_add(&proof,data[i],lengths[i])!=TRIE_FOUND) return -2;
    const uint8_t *value; size_t len;
    if (trie_lookup(root,key,key_len,&proof,&value,&len)!=TRIE_FOUND || len>cap) return -3;
    memcpy(out,value,len);
    return (int)len;
}
