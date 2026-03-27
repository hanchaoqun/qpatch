#include "hashmap.h"

#include <stdlib.h>
#include <string.h>

struct hashmap {
  size_t elsize;
  size_t cap;
  size_t count;
  uint64_t seed0;
  uint64_t seed1;
  hashmap_hash_fn hash;
  hashmap_compare_fn compare;
  void* udata;
  unsigned char* items;
};

static void* item_at(const struct hashmap* map, size_t idx) {
  return (void*)(map->items + idx * map->elsize);
}

struct hashmap* hashmap_new(size_t elsize, size_t cap, uint64_t seed0,
                            uint64_t seed1, hashmap_hash_fn hash,
                            hashmap_compare_fn compare, void* udata,
                            void* reserved) {
  (void)reserved;
  if (elsize == 0 || cap == 0 || !compare) {
    return NULL;
  }
  struct hashmap* map = (struct hashmap*)calloc(1, sizeof(*map));
  if (!map) {
    return NULL;
  }
  map->elsize = elsize;
  map->cap = cap;
  map->seed0 = seed0;
  map->seed1 = seed1;
  map->hash = hash;
  map->compare = compare;
  map->udata = udata;
  map->items = (unsigned char*)calloc(cap, elsize);
  if (!map->items) {
    free(map);
    return NULL;
  }
  return map;
}

const void* hashmap_get(const struct hashmap* map, const void* item) {
  if (!map || !item) {
    return NULL;
  }
  for (size_t idx = 0; idx < map->count; idx++) {
    void* slot = item_at(map, idx);
    if (map->compare(slot, item, map->udata) == 0) {
      return slot;
    }
  }
  return NULL;
}

const void* hashmap_set(struct hashmap* map, const void* item) {
  if (!map || !item) {
    return NULL;
  }
  for (size_t idx = 0; idx < map->count; idx++) {
    void* slot = item_at(map, idx);
    if (map->compare(slot, item, map->udata) == 0) {
      memcpy(slot, item, map->elsize);
      return slot;
    }
  }
  if (map->count >= map->cap) {
    size_t newcap = map->cap * 2;
    unsigned char* newitems =
        (unsigned char*)realloc(map->items, newcap * map->elsize);
    if (!newitems) {
      return NULL;
    }
    map->items = newitems;
    map->cap = newcap;
  }
  void* slot = item_at(map, map->count);
  memcpy(slot, item, map->elsize);
  map->count++;
  return NULL;
}

size_t hashmap_count(const struct hashmap* map) {
  if (!map) {
    return 0;
  }
  return map->count;
}

uint64_t hashmap_sip(const void* data, size_t len, uint64_t seed0,
                     uint64_t seed1) {
  const unsigned char* p = (const unsigned char*)data;
  uint64_t h = 1469598103934665603ULL ^ seed0 ^ (seed1 << 1);
  for (size_t i = 0; i < len; i++) {
    h ^= (uint64_t)p[i];
    h *= 1099511628211ULL;
  }
  return h;
}
