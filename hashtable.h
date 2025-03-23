#pragma once

#include <stddef.h>
#include <stdint.h>

// hash table node
struct HashNode {
    HashNode *next = NULL;
    uint64_t hcode = 0;
};

// hash table
struct HashTable {
    // array of nodes
    HashNode ** table = NULL;
    size_t mask = 0;
    size_t size = 0;
};

struct HashMap {
    HashTable newer;
    HashTable older;
    size_t migrate_position = 0;
};

HashNode *hashMapLookup(HashMap * hashMap, HashNode *key, bool (*eq)(HashNode *, HashNode *));
void hashMapInsert(HashMap * hashMap, HashNode * node);
HashNode *hashMapDelete(HashMap * hashMap, HashNode *key, bool (*eq)(HashNode *, HashNode *));
void hashMapClear(HashMap * hashMap);
size_t hashMapSize(HashMap * hashMap);