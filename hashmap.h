/*
 * @author f1est 
 */
 
#ifndef HASHMAP_H
#define HASHMAP_H

#include "struct.h"

typedef struct entry_s entry_t;
typedef struct hashtable_s hashtable_t;

struct entry_s {
        const char *key;
	base_t *value;
        struct entry_s *prev, *next;
};

struct hashtable_s {
        int size;
        int count_elems;
        struct entry_s **table;        
};

/* Create a new hashtable. */
hashtable_t *ht_create(int size);

int ht_is_not_empty(hashtable_t *hashtable);

/* Insert a key-value pair into a hash table. 
 * return:
 *              0 on success add, 
 *              -1 on failure, 
 *              1 if key alredy exist,
 *              2 if hashtable is full 
 */
int ht_add(hashtable_t *hashtable, const char *key, base_t *value);

/* Remove a key-value pair from a hash table and deallocate resources.
 * Return 0 on success, -1 on failure */
int ht_remove(hashtable_t *hashtable, const char *key);

/* 
 * Get a value of key from hashtable 
 * Return NULL on failure ar pointer on value 
 */
base_t *ht_get_value(hashtable_t *hashtable, const char *key);

/* Return size of table */
int ht_get_size(hashtable_t *hashtable);

/* 
 * on success return pointer on pair from table on index 
 * return NULL on fail
 */
entry_t *ht_get_entry_on_index(hashtable_t *hashtable, int index);

/* Deallocate the hashtable */
void ht_free(hashtable_t *hashtable);

/* Printing all data in table */
void ht_print_table(hashtable_t *hashtable);

#endif /* HASHMAP_H */
