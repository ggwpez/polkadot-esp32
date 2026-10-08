/* Substrate base-16 Patricia Merkle trie, state version 1.
 *
 * Verifies a storage read against a state root using only the nodes supplied in
 * the proof. Nothing is trusted: every node is addressed by its blake2b-256
 * hash, so a node the prover did not include, or altered, cannot be substituted.
 *
 * State v1 stores values longer than 32 bytes by hash, so leaves and branches
 * come in inline-value and hashed-value forms; both are handled here.
 *
 * "Absent" is a proven result and is reported separately from "the proof is
 * incomplete". Conflating the two would let a prover deny a value by omission. */
#ifndef TRIE_H
#define TRIE_H

#include <stddef.h>
#include <stdint.h>
#include "lc_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const uint8_t *data;
    size_t len;
    uint8_t hash[LC_HASH_LEN];
} trie_node_ref;

typedef struct {
    trie_node_ref *nodes;
    size_t count;
    size_t cap;
} trie_proof;

typedef enum {
    TRIE_FOUND = 0,
    TRIE_ABSENT,            /* the proof positively shows the key has no value */
    TRIE_ERR_MISSING_NODE,  /* proof incomplete: a node on the path was not supplied */
    TRIE_ERR_MALFORMED,     /* a node did not decode */
    TRIE_ERR_LOOP,          /* walk did not terminate */
    TRIE_ERR_FULL           /* proof does not fit in the caller's array */
} trie_result;

void trie_proof_init(trie_proof *p, trie_node_ref *storage, size_t cap);

/* Hashes the node and adds it. `data` must stay valid until the lookup is done. */
trie_result trie_proof_add(trie_proof *p, const uint8_t *data, size_t len);

/* Walks from `root` to `key`. On TRIE_FOUND, *out points into the proof buffers. */
trie_result trie_lookup(const uint8_t root[LC_HASH_LEN],
                        const uint8_t *key, size_t key_len,
                        const trie_proof *p,
                        const uint8_t **out, size_t *out_len);

const char *trie_strerror(trie_result r);

#ifdef __cplusplus
}
#endif
#endif
