#ifndef __QPATCH_HASHMAP_H__
#define __QPATCH_HASHMAP_H__

#include <stddef.h>
#include <stdint.h>

struct hashmap;

typedef uint64_t (*hashmap_hash_fn)(const void* item, uint64_t seed0,
                                    uint64_t seed1);
typedef int (*hashmap_compare_fn)(const void* a, const void* b, void* udata);

struct hashmap* hashmap_new(size_t elsize, size_t cap, uint64_t seed0,
                            uint64_t seed1, hashmap_hash_fn hash,
                            hashmap_compare_fn compare, void* udata,
                            void* reserved);
const void* hashmap_get(const struct hashmap* map, const void* item);
const void* hashmap_set(struct hashmap* map, const void* item);
size_t hashmap_count(const struct hashmap* map);
uint64_t hashmap_sip(const void* data, size_t len, uint64_t seed0,
                     uint64_t seed1);

#endif /* __QPATCH_HASHMAP_H__ */
