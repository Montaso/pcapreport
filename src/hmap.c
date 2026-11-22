#include "hmap.h"
#include "common.h"

#include <stdlib.h>
#include <string.h>

uint64_t hash_bytes(const void *data, size_t n)
{
    /* FNV-1a 64 with a final avalanche step */
    const uint8_t *p = data;
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211ull; }
    h ^= h >> 33;
    h *= 0xff51afd7ed558ccdull;
    h ^= h >> 33;
    return h ? h : 1;
}

void hmap_init(hmap_t *m)
{
    memset(m, 0, sizeof *m);
    m->cap = 1024;
    m->slots = xcalloc(m->cap, sizeof(hmap_slot_t));
}

void hmap_free(hmap_t *m)
{
    free(m->slots);
    free(m->keys);
    memset(m, 0, sizeof *m);
}

static void grow(hmap_t *m)
{
    size_t ncap = m->cap * 2;
    hmap_slot_t *ns = xcalloc(ncap, sizeof(hmap_slot_t));
    for (size_t i = 0; i < m->cap; i++) {
        hmap_slot_t *s = &m->slots[i];
        if (!s->hash) continue;
        size_t j = s->hash & (ncap - 1);
        while (ns[j].hash) j = (j + 1) & (ncap - 1);
        ns[j] = *s;
    }
    free(m->slots);
    m->slots = ns;
    m->cap = ncap;
}

int hmap_get(const hmap_t *m, const void *key, size_t klen)
{
    uint64_t h = hash_bytes(key, klen);
    size_t i = h & (m->cap - 1);
    while (m->slots[i].hash) {
        const hmap_slot_t *s = &m->slots[i];
        if (s->hash == h && s->klen == klen && memcmp(m->keys + s->koff, key, klen) == 0)
            return s->val;
        i = (i + 1) & (m->cap - 1);
    }
    return -1;
}

void hmap_put(hmap_t *m, const void *key, size_t klen, int val)
{
    if ((m->count + 1) * 10 > m->cap * 7) grow(m);
    uint64_t h = hash_bytes(key, klen);
    size_t i = h & (m->cap - 1);
    while (m->slots[i].hash) {
        hmap_slot_t *s = &m->slots[i];
        if (s->hash == h && s->klen == klen && memcmp(m->keys + s->koff, key, klen) == 0) {
            s->val = val;
            return;
        }
        i = (i + 1) & (m->cap - 1);
    }
    VEC_RESERVE(m->keys, m->kcap, m->klen + klen);
    memcpy(m->keys + m->klen, key, klen);
    m->slots[i].hash = h;
    m->slots[i].koff = (uint32_t)m->klen;
    m->slots[i].klen = (uint32_t)klen;
    m->slots[i].val = val;
    m->klen += klen;
    m->count++;
}
