/*
 * hmap.h - small open-addressing hash map: arbitrary byte-string key -> int.
 * Values are typically indexes into a separate growable array.
 */
#ifndef HMAP_H
#define HMAP_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t hash;      /* 0 = empty slot */
    uint32_t koff;
    uint32_t klen;
    int32_t  val;
} hmap_slot_t;

typedef struct {
    hmap_slot_t *slots;
    size_t       cap;     /* power of two */
    size_t       count;
    char        *keys;    /* key arena */
    size_t       klen, kcap;
} hmap_t;

void hmap_init(hmap_t *m);
void hmap_free(hmap_t *m);
/* returns stored value or -1 */
int  hmap_get(const hmap_t *m, const void *key, size_t klen);
/* inserts or overwrites */
void hmap_put(hmap_t *m, const void *key, size_t klen, int val);
uint64_t hash_bytes(const void *data, size_t n);

#endif
