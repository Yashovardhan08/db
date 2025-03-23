#include <cstddef>
#include <cassert>
#include <stdlib.h>
#include "hashtable.h"

const size_t K_MAX_LOAD_FACTOR = 8;
const size_t K_REHASHING_WORK = 128;  

static void hashTableInit(HashTable *hashTable, size_t n) {
    assert(n > 0 && ((n - 1) & n) == 0);    // n must be a power of 2
    hashTable->table = (HashNode **)calloc(n, sizeof(HashNode *));
    hashTable->mask = n - 1;
    hashTable->size = 0;
}

static void insertHashNode(HashTable *hashTable, HashNode *hashNode) {
    // hashNode hcode is already calculated and sent
    size_t pos = hashNode->hcode & hashTable->mask;
    HashNode *next = hashTable->table[pos];
    hashNode->next = next;
    hashTable->table[pos] = hashNode;
    hashTable->size++;
}

static HashNode **hashTableLookup(HashTable * hashTable, HashNode * key, bool (*eq)(HashNode *,HashNode *)) {
    // returns parent pointer to the node found in case of deletion
    if(!hashTable->table) {
        return NULL;
    }
    size_t pos = key->hcode & hashTable->mask;
    HashNode **from = &hashTable->table[pos];
    for (HashNode * curr; (curr = *from)!= NULL ; from = &curr->next) {
        if (curr->hcode == key->hcode && eq(curr, key)) {
            return from;
        }
    }
    return NULL;
}

static HashNode *hashDetach(HashTable *hashTable, HashNode **from) {
    HashNode *node = *from;
    *from = node->next;
    hashTable->size --;
    return node;
}

static void hashMapHelpRehashing(HashMap *hashMap) {
    size_t nwork = 0;
    while( nwork < K_REHASHING_WORK && hashMap->older.size >0) {
        HashNode ** from = &hashMap->older.table[hashMap->migrate_position];
        if(!*from) {
            hashMap->migrate_position++;
            continue;
        }
        insertHashNode(&hashMap->newer, hashDetach(&hashMap->older,from));
        nwork++;
    }

    if(hashMap->older.size ==0 && hashMap->older.table){
        free(hashMap->older.table);
        hashMap->older = HashTable{};
    }
}


// hashMap has two hashTables, newer is used while older is unused
// when the load factor is high then migrate newer to older 
// and replace newer with a larger empty hash table
static void hashMapTriggerRehashing(HashMap *hashMap) {
    hashMap->older = hashMap->newer;
    hashTableInit(&hashMap->newer, (hashMap->newer.mask +1)*2);
    hashMap->migrate_position = 0;
}

// during rehashing we need to query both tables
HashNode *hashMapLookup(HashMap * hashMap, HashNode *key, bool (*eq)(HashNode *, HashNode *)) {
    hashMapHelpRehashing(hashMap);// migrate some keys
    HashNode **from = hashTableLookup(&hashMap->newer, key, eq);
    if(!from) {
        from = hashTableLookup(&hashMap->older,key,eq);
    }
    return from ? *from :NULL;
}

HashNode *hashMapDelete(HashMap * hashMap, HashNode *key, bool (*eq)(HashNode *, HashNode *)) {
    hashMapHelpRehashing(hashMap);// migrate some keys
    if( HashNode **from = hashTableLookup(&hashMap->newer, key, eq)) {
        return hashDetach(&hashMap->newer, from);
    }
    if( HashNode **from = hashTableLookup(&hashMap->older, key, eq)) {
        return hashDetach(&hashMap->older, from);
    }
    return NULL;
}


void hashMapInsert(HashMap * hashMap, HashNode * node){
    if (!hashMap->newer.table) {
        hashTableInit(&hashMap->newer,4);
    }
    insertHashNode(&hashMap->newer,node);
    if (!hashMap->older.table) {
        size_t threshold = (hashMap->newer.mask + 1) * K_MAX_LOAD_FACTOR;
        if (hashMap->newer.size >= threshold) {
            hashMapTriggerRehashing(hashMap);
        }
    }
    hashMapHelpRehashing(hashMap);// migrate some keys
}
 
