#include "trie.h"
#include <string.h>

/* Node header kinds, distinguished by the top bits of the first byte.
 * The order of the tests below matters: the 2-bit forms must be ruled out
 * before the 3- and 4-bit ones, whose prefixes are numerically smaller. */
enum { N_LEAF, N_BRANCH, N_BRANCH_V, N_HLEAF, N_HBRANCH };

typedef struct {
    int is_branch;
    int is_empty;
    const uint8_t *pk;          /* packed partial key nibbles */
    size_t pk_skip;             /* 1 if the first nibble is padding */
    size_t partial_len;         /* in nibbles */
    int has_value;
    int value_hashed;
    const uint8_t *value;
    size_t value_len;
    const uint8_t *child[16];
    size_t child_len[16];
} trie_node;

static inline uint8_t nib(const uint8_t *b, size_t i)
{
    return (i & 1) ? (b[i >> 1] & 0x0f) : (uint8_t)(b[i >> 1] >> 4);
}

/* Bounds-checked SCALE compact, local so trie.c has no dependency on scale.c. */
static int rd_compact(const uint8_t *b, size_t len, size_t *i, uint64_t *out)
{
    if (*i >= len) return 0;
    uint8_t b0 = b[*i];
    size_t n;
    switch (b0 & 3) {
    case 0: *out = b0 >> 2; *i += 1; return 1;
    case 1:
        if (len - *i < 2) return 0;
        *out = ((uint32_t)b[*i] | (uint32_t)b[*i + 1] << 8) >> 2;
        *i += 2; return 1;
    case 2:
        if (len - *i < 4) return 0;
        *out = ((uint32_t)b[*i] | (uint32_t)b[*i + 1] << 8 |
                (uint32_t)b[*i + 2] << 16 | (uint32_t)b[*i + 3] << 24) >> 2;
        *i += 4; return 1;
    default:
        n = (size_t)(b0 >> 2) + 4;
        if (n > 8 || len - *i - 1 < n) return 0;
        *i += 1;
        *out = 0;
        for (size_t k = n; k-- > 0;) *out = *out << 8 | b[*i + k];
        *i += n;
        return 1;
    }
}

static int decode_node(const uint8_t *b, size_t len, trie_node *n)
{
    memset(n, 0, sizeof *n);
    if (len == 0) return 0;

    size_t i = 0;
    uint8_t b0 = b[i++];
    if (b0 == 0) { n->is_empty = 1; return 1; }

    int kind;
    size_t maxn;
    if      ((b0 & 0xc0) == 0x40) { kind = N_LEAF;     maxn = 63; }
    else if ((b0 & 0xc0) == 0x80) { kind = N_BRANCH;   maxn = 63; }
    else if ((b0 & 0xc0) == 0xc0) { kind = N_BRANCH_V; maxn = 63; }
    else if ((b0 & 0xe0) == 0x20) { kind = N_HLEAF;    maxn = 31; }
    else if ((b0 & 0xf0) == 0x10) { kind = N_HBRANCH;  maxn = 15; }
    else return 0;

    size_t nk = b0 & maxn;
    if (nk == maxn) {                       /* extended partial-key length */
        for (;;) {
            if (i >= len) return 0;
            uint8_t add = b[i++];
            nk += add;
            if (nk > 0xffff) return 0;      /* far beyond any real key */
            if (add != 255) break;
        }
    }

    size_t pk_bytes = (nk + 1) / 2;
    if (len - i < pk_bytes) return 0;
    n->pk = b + i;
    n->pk_skip = nk & 1;                    /* odd length pads with a leading nibble */
    n->partial_len = nk;
    i += pk_bytes;

    n->is_branch = (kind == N_BRANCH || kind == N_BRANCH_V || kind == N_HBRANCH);

    if (!n->is_branch) {
        n->has_value = 1;
        if (kind == N_HLEAF) {
            if (len - i < LC_HASH_LEN) return 0;
            n->value_hashed = 1;
            n->value = b + i;
            n->value_len = LC_HASH_LEN;
        } else {
            uint64_t vl;
            if (!rd_compact(b, len, &i, &vl)) return 0;
            if (vl > len - i) return 0;
            n->value = b + i;
            n->value_len = (size_t)vl;
        }
        return 1;
    }

    if (len - i < 2) return 0;
    uint16_t bitmap = (uint16_t)(b[i] | b[i + 1] << 8);
    i += 2;

    if (kind == N_BRANCH_V) {
        uint64_t vl;
        if (!rd_compact(b, len, &i, &vl)) return 0;
        if (vl > len - i) return 0;
        n->has_value = 1;
        n->value = b + i;
        n->value_len = (size_t)vl;
        i += (size_t)vl;
    } else if (kind == N_HBRANCH) {
        if (len - i < LC_HASH_LEN) return 0;
        n->has_value = 1;
        n->value_hashed = 1;
        n->value = b + i;
        n->value_len = LC_HASH_LEN;
        i += LC_HASH_LEN;
    }

    for (int c = 0; c < 16; c++) {
        if (!(bitmap >> c & 1)) continue;
        uint64_t cl;
        if (!rd_compact(b, len, &i, &cl)) return 0;
        if (cl > LC_HASH_LEN || cl > len - i) return 0;  /* hash, or an inline node */
        n->child[c] = b + i;
        n->child_len[c] = (size_t)cl;
        i += (size_t)cl;
    }
    return 1;
}

void trie_proof_init(trie_proof *p, trie_node_ref *storage, size_t cap)
{
    p->nodes = storage;
    p->count = 0;
    p->cap = cap;
}

trie_result trie_proof_add(trie_proof *p, const uint8_t *data, size_t len)
{
    if (p->count >= p->cap) return TRIE_ERR_FULL;
    trie_node_ref *r = &p->nodes[p->count++];
    r->data = data;
    r->len = len;
    lc_blake2b256(r->hash, data, len);
    return TRIE_FOUND;
}

static const trie_node_ref *find(const trie_proof *p, const uint8_t h[LC_HASH_LEN])
{
    for (size_t i = 0; i < p->count; i++)
        if (memcmp(p->nodes[i].hash, h, LC_HASH_LEN) == 0) return &p->nodes[i];
    return 0;
}

/* Turns a node's value field into actual bytes, following the hash indirection
 * that state v1 uses for values longer than 32 bytes. */
static trie_result resolve(const trie_node *n, const trie_proof *p,
                           const uint8_t **out, size_t *out_len)
{
    if (!n->has_value) return TRIE_ABSENT;
    if (!n->value_hashed) {
        *out = n->value;
        *out_len = n->value_len;
        return TRIE_FOUND;
    }
    const trie_node_ref *r = find(p, n->value);
    if (!r) return TRIE_ERR_MISSING_NODE;
    *out = r->data;
    *out_len = r->len;
    return TRIE_FOUND;
}

trie_result trie_lookup(const uint8_t root[LC_HASH_LEN],
                        const uint8_t *key, size_t key_len,
                        const trie_proof *p,
                        const uint8_t **out, size_t *out_len)
{
    const size_t path_len = key_len * 2;
    size_t pos = 0;

    const uint8_t *cur_hash = root;
    const uint8_t *inline_data = 0;
    size_t inline_len = 0;

    /* Each iteration consumes at least one nibble at a branch, or terminates at
     * a leaf, so the walk is bounded by the key length. The cap is belt and
     * braces against a decode bug, not against a hostile proof. */
    for (size_t step = 0; step <= path_len + 2; step++) {
        const uint8_t *raw;
        size_t raw_len;

        if (inline_data) {
            raw = inline_data; raw_len = inline_len;
            inline_data = 0;
        } else {
            const trie_node_ref *r = find(p, cur_hash);
            if (!r) return TRIE_ERR_MISSING_NODE;
            raw = r->data; raw_len = r->len;
        }

        trie_node n;
        if (!decode_node(raw, raw_len, &n)) return TRIE_ERR_MALFORMED;
        if (n.is_empty) return TRIE_ABSENT;

        if (n.partial_len > path_len - pos) return TRIE_ABSENT;
        for (size_t k = 0; k < n.partial_len; k++)
            if (nib(n.pk, k + n.pk_skip) != nib(key, pos + k)) return TRIE_ABSENT;
        pos += n.partial_len;

        if (!n.is_branch)
            return pos == path_len ? resolve(&n, p, out, out_len) : TRIE_ABSENT;

        if (pos == path_len) return resolve(&n, p, out, out_len);

        uint8_t c = nib(key, pos++);
        if (!n.child[c]) return TRIE_ABSENT;

        if (n.child_len[c] == LC_HASH_LEN) {
            cur_hash = n.child[c];
        } else {
            inline_data = n.child[c];
            inline_len = n.child_len[c];
        }
    }
    return TRIE_ERR_LOOP;
}

const char *trie_strerror(trie_result r)
{
    switch (r) {
    case TRIE_FOUND:            return "found";
    case TRIE_ABSENT:           return "absent (proven)";
    case TRIE_ERR_MISSING_NODE: return "proof incomplete: node not supplied";
    case TRIE_ERR_MALFORMED:    return "malformed trie node";
    case TRIE_ERR_LOOP:         return "walk did not terminate";
    case TRIE_ERR_FULL:         return "too many proof nodes";
    }
    return "unknown";
}
