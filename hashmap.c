/*
 * @author f1est 
 */
 
#include "hashmap.h"
#include "common.h"
#include "log.h"

int ht_is_empty(hashtable_t *hashtable)
{
        return hashtable->count_elems;
}

/* Create a new hashtable. */
hashtable_t *ht_create(int size) 
{

        hashtable_t *hashtable = NULL;
        int i;

        if(size < 1) {
                debug_msg("Size of hashtable MUST be more 1");
                return NULL;
        }

        /* Allocate the table itself. */
        if((hashtable = malloc(sizeof(hashtable_t))) == NULL) {
                return NULL;
        }

        /* Allocate pointers to the head nodes. */
        if((hashtable->table = malloc(sizeof(entry_t *) * size)) == NULL) {
                free(hashtable);
                return NULL;
        }

        for(i = 0; i < size; i++) {
                hashtable->table[i] = NULL;
        }

        hashtable->size = size;
        hashtable->count_elems = 0;

        return hashtable;        
}

/* Hash a string for a particular hash table. */
static int ht_hash(hashtable_t *hashtable, const char *key) 
{

        unsigned long int hashval = 0;
        int i = 0;

        if(!hashtable || !key)
                return -1;

        /* Convert our string to an integer */
        while(hashval < ULONG_MAX && i < strlen(key)) {
                hashval = hashval << 8;
                hashval += key[i];
                i++;
        }

        return hashval % hashtable->size;
}

/* Create a key-value pair. */
static entry_t *ht_newpair(char *key, void *value) 
{
        entry_t *newpair;

        if(!key || !value)
                return NULL;

        if((newpair = malloc(sizeof(entry_t))) == NULL) {
                return NULL;
        }

        if((newpair->key = strdup(key)) == NULL) {
                free(newpair);
                return NULL;
        }

        if((newpair->value = strdup(value)) == NULL) {
                free(key);
                free(newpair);
                return NULL;
        }

        newpair->next = NULL;
        newpair->prev = NULL;

        return newpair;
}

/* Find and return the table in hashtable */
static entry_t **ht_find_table(hashtable_t * hashtable, const char *key)
{
        int i = hashtable->size - 1;

        while(i >= 0) {
                if(hashtable->table[i] != NULL && hashtable->table[i]->key != NULL 
                        && strncmp(hashtable->table[i]->key, key, strlen(hashtable->table[i]->key)) == 0)
                        return &hashtable->table[i];
                i--;
        }

        debug_msg("key '%s' not found!\n", key);
        return NULL;
}

/* Insert a key-value pair into a hash table. 
 * return:
 *              0 on success add, 
 *              -1 on failure, 
 *              1 if key alredy exist,
 *              2 if hashtable is full
 *              3 otherwise
 */
int ht_add(hashtable_t *hashtable, char *key, void *value)
{
        int bin = 0;
        int i;
        entry_t *newpair = NULL;
        entry_t *next = NULL;
        entry_t *last = NULL;

        if(!hashtable || !key || !value) 
                return -1;

        if(strlen(key) == 0)
                return 3;

        bin = ht_hash(hashtable, key);

        next = hashtable->table[bin];


        while(next != NULL && next->key != NULL && strncmp(key, next->key, strlen(next->key)) != 0) {
                last = next;
                next = next->next;
        }

        /* There's already a pair.  Let's replace that string. */
        if(next != NULL && next->key != NULL && strncmp(key, next->key, strlen(next->key)) == 0) {
                
                debug_msg("key '%s' alredy exist\n", key);

/* if need change value*/
//                free(next->value);
//                next->value = strdup(value);

                return 1;

        /* Nope, could't find it.  Time to grow a pair. */
        } else {

                if(hashtable->count_elems > hashtable->size) {
                        debug_msg("hashtable is FULL!!!");
                        return 2;
                }
                
                /* Find the free slot */
                if(next != hashtable->table[bin]) {
                        
                        i = hashtable->size - 1;
                        
                        while(i >= 0) {
                                if(hashtable->table[i] == NULL)
                                        break;
                                        i--;
                        }
                        
                        if(i <= 0) {
                                debug_msg("free slots in hashtable ended!!!\n");
                                return 2;
                        }
                }
                
                newpair = ht_newpair(key, value);
                
                if(!newpair)
                        return -1;
                        
                
                /* We're at the start of the linked list in this bin. */
                if(next == hashtable->table[bin]) {
                        
                        if(next != NULL && next->next != NULL)
                                newpair->next = next->next;
                        else 
                                newpair->next = NULL;
                        
                        newpair->prev = last;
                        hashtable->table[bin] = newpair;
                
                /* We're at the end of the linked list in this bin. */
                } else if (next == NULL) {
                        
                        last->next = newpair;
                        newpair->prev = last;
                        newpair->next = NULL;
                        hashtable->table[i] = newpair;
                        
                /* We're in the middle of the list. */
                } else  {
                        
                        newpair->next = next->next;
                        newpair->prev = last;
                        last->next = newpair;
                        next->prev = newpair;
                        hashtable->table[i] = newpair;
                }
                
                hashtable->count_elems++;
        }
        
        debug_msg("pair '%s'->'%s' SUCCESSFULLY added!\n", key, value);
        return 0;
}

/* Retrieve a key-value pair from a hash table. */
static entry_t *ht_get_pair(hashtable_t *hashtable, const char *key)
{
        int bin = 0;
        entry_t *pair;
        
        if(!hashtable || !key)
                return NULL;
  
        bin = ht_hash(hashtable, key);

        /* Step through the bin, looking for our value. */
        pair = hashtable->table[bin];

        while(pair != NULL && pair->key != NULL && strncmp(key, pair->key, strlen(pair->key)) != 0) {
                pair = pair->next;
        }

        /* Did we actually find anything? */
        if(pair == NULL || pair->key == NULL || strncmp(key, pair->key, strlen(pair->key)) != 0) {

                debug_msg("Key '%s' not found\n", key);
                return NULL;

        } else
                return pair;
        
        return NULL;
}

/* Get a value of key from hashtable */
void *ht_get_value(hashtable_t *hashtable, const char *key)
{
        entry_t *pair = ht_get_pair(hashtable, key);

        if(!pair)
                return NULL;

        return pair->value;
}

/* Remove a key-value pair from a hash table. */
/* Return 0 on success, -1 on failure */
int ht_remove(hashtable_t *hashtable, const char *key)
{
        entry_t **table = ht_find_table(hashtable, key);
        
        if(!table)
                return -1;

        if ((*table)->prev)
                (*table)->prev->next = (*table)->next;

        if ((*table)->next)
                (*table)->next->prev = (*table)->prev;

        free ((*table)->key);
        (*table)->key = NULL;

        free ((*table)->value);
        (*table)->value = NULL;

        free ((*table));
        (*table) = NULL;
        table = NULL;
        
        hashtable->count_elems--;
        debug_msg("pair with key '%s' SUCCESSFULLY removed!\n",key);

        return 0;
}

/* Return size of table */
int ht_get_size(hashtable_t *hashtable)
{
        return hashtable->size;
}

/* Deallocate the hashtable */
void ht_free(hashtable_t *hashtable)
{
        int i = hashtable->size - 1;
#ifndef NDEBUG
        int deleted = 0;
#endif
        while(i >= 0) {
                if(hashtable->table[i]) {
                        
                        if(hashtable->table[i]->key) {
                                free(hashtable->table[i]->key);
                                hashtable->table[i]->key = NULL;
                        }
                        
                        if(hashtable->table[i]->value) {
                                free(hashtable->table[i]->value);
                                hashtable->table[i]->value = NULL;
                        }
                        
                        free(hashtable->table[i]);
                        hashtable->table[i] = NULL;

                }
#ifndef NDEBUG
                deleted++;
#endif
                i--;
        }

        free(hashtable->table);
        hashtable->table = NULL;

        free(hashtable);
        hashtable = NULL;
#ifndef NDEBUG
        debug_msg("deleted %d rows", deleted);;
#endif
}

/* 
 * on success return pointer on pair from table on index 
 * return NULL on fail
 */
entry_t *ht_get_entry_on_index(hashtable_t *hashtable, int index)
{
        int i = 0;

        if(index > hashtable->size)
                return NULL;

        while(i != hashtable->size) {
                if(i == index)
                        return hashtable->table[i];
                i++;
        }

        return NULL;
}

/* Printing all data in table */
void ht_print_table(hashtable_t *hashtable)
{
#ifndef NDEBUG
        int i = hashtable->size - 1;
        
        fprintf(stderr, "hashtable: \n"); 
        while(i >= 0) {
                if(hashtable->table[i]) {
                        
                        if(hashtable->table[i]->key) 
                                fprintf(stderr, "\t '%s'", hashtable->table[i]->key); 
//                                debug_msg("\t %s", hashtable->table[i]->key); 
                        
                        if(hashtable->table[i]->value) 
                                fprintf(stderr, "\t '%s' \n", hashtable->table[i]->value); 
//                                debug_msg("\t %s \n", hashtable->table[i]->value); 
                }
                i--;
        }
#endif
}

