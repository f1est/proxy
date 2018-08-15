/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#include "hashmap.h"
#include "log.h"

static int delete_oldest_session(hashtable_t *hashtable, entry_t **last, entry_t **next);

int ht_is_not_empty(hashtable_t *hashtable)
{
        return hashtable->count_elems;
}

/* Return size of table */
int ht_get_size(hashtable_t *hashtable)
{
        return hashtable->size;
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
        if((hashtable = malloc(sizeof(hashtable_t))) == NULL) 
                return NULL;
        

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

/* Create a key-value pair. */
static entry_t *ht_newpair(const char *key, base_t *value) 
{
        entry_t *newpair;

        if(!key || !value)
                return NULL;

        if((newpair = malloc(sizeof(entry_t))) == NULL) 
                return NULL;
        

        if((newpair->key = strdup(key)) == NULL) {
                free(newpair);
                return NULL;
        }

        if(value->clone == NULL || (newpair->value = value->clone(value)) == NULL) {
                free(newpair);
                return NULL;
        }

        if(newpair->value->type == type_session) { 
                ((session_t *)newpair->value)->SID = newpair->key;
                session_add_expires_event((session_t *)newpair->value, newpair->key);
        }

        newpair->next = NULL;
        newpair->prev = NULL;

        return newpair;
}

/* Insert a key-value pair into a hash table. 
 * return:
 *              0 on success add, 
 *              -1 on failure, 
 *              1 if key alredy exist,
 *              2 if hashtable is full
 *              3 otherwise
 */
int ht_add(hashtable_t *hashtable, const char *key, base_t *value)
{
        int bin = 0;
        int i;
        entry_t *newpair = NULL;
        entry_t *next = NULL;
        entry_t *last = NULL;

        if(!hashtable || !key || !value) {
#ifdef DEBUG_HASHTABLE
                debug_msg("hashtable, key or value is NULL");
#endif
                return -1;
        }

        if(strlen(key) == 0) {
#ifdef DEBUG_HASHTABLE
                debug_msg("length of key is 0");
#endif
                return -1;
        }
        
        next = hashtable->table[bin];

        while(next != NULL && next->key != NULL 
                        && (strlen(key) > 0
                        && strncmp(key, next->key, strlen(key)) != 0)) {
                next->prev = last;
                last = next;
                next = next->next;
        }

        /* There's already a pair. */
        if(next != NULL && next->key != NULL
                        && (strlen(key) > 0
                        && strncmp(key, next->key, strlen(key)) == 0)) {
#ifdef DEBUG_HASHTABLE
                debug_msg("key '%s' alredy exist\n", key);
#endif
                return 1;

        /* Nope, could't find it.  Time to grow a pair. */
        } else {
                if(hashtable->count_elems >= hashtable->size) {
                        
                        if(value->type == type_session) {

#ifdef DEBUG_HASHTABLE
                                debug_msg("hashtable is FULL!!! Will be removed outdated session");
#endif
                                delete_oldest_session(hashtable, &last, &next);
                        }
                        else {
#ifdef DEBUG_HASHTABLE
                                debug_msg("hashtable is FULL!!!");
#endif
                                return 2;
                        }
                }
                        
                        /* Find the free slot */
                        if(next != hashtable->table[bin]) { 
                                
                                i = 0;
                                while(i < hashtable->size) {
                                        if(hashtable->table[i] == NULL)
                                                break;
                                        i++;
                                }
                                if(i >= hashtable->size) {
#ifdef DEBUG_HASHTABLE
                                        debug_msg("free slots in hashtable ended!!!\n");
#endif
                                        return 2;
                                }
                        }

                        newpair = ht_newpair(key, value);
                        if(!newpair) {
#ifdef DEBUG_HASHTABLE
                                debug_msg("Couldn't create newpair!!!");
#endif
                                return -1;
                        }

                        /* We're at the start of the linked list in this bin. */
                        if(next == hashtable->table[bin]) { 
                                
                                if(next != NULL) {
                                        newpair->next = next->next;
                                        next->prev = last;
                                }
                                else 
                                        newpair->next = NULL;

                                newpair->prev = last;

                                if(last != NULL)
                                        last->next = newpair;

                                hashtable->table[bin] = newpair;
                        
                        /* We're at the end of the linked list in this bin. */
                        } else if (next == NULL) {
                                
                                if(last != NULL)
                                        last->next = newpair;

                                newpair->prev = last;
                                newpair->next = NULL;

                                hashtable->table[i] = newpair;
        
                        /* We're in the middle of the list. */
                        } else  {
                                
                                newpair->next = next;
                                newpair->prev = last;

                                if(last != NULL)
                                        last->next = newpair;

                                if(next != NULL)
                                       next->prev = newpair;

                                hashtable->table[i] = newpair;
                        }

                        hashtable->count_elems++;
        }

#ifdef DEBUG_HASHTABLE
        debug_msg("key '%s' SUCCESSFULLY added!\n",key);
#endif

        return 0;
}

/* Retrieve a key-value pair from a hash table. */
static entry_t *ht_get_pair(hashtable_t *hashtable, const char *key)
{
        int bin = 0;
        entry_t *pair;
        
        if(!hashtable || !key)
                return NULL;

        /* Step through the bin, looking for our value. */
        pair = hashtable->table[bin];

        while(pair != NULL && pair->key != NULL 
                        && (strlen(key) > 0
                        && strncmp(key, pair->key, strlen(key)) != 0)) 
                pair = pair->next;


        

        /* Did we actually find anything? */
        if(pair == NULL || pair->key == NULL 
                || (strlen(key) > 0 && strncmp(key, pair->key, strlen(key)) != 0)) {

                debug_msg("Key '%s' not found\n", key);
                return NULL;

        } else
                return pair;
        
        return NULL;
}

/* 
 * Get a value of key from hashtable 
 * Return NULL on failure ar pointer on value 
 */
base_t *ht_get_value(hashtable_t *hashtable, const char *key)
{
        entry_t *pair = ht_get_pair(hashtable, key);

        if(!pair)
                return NULL;

        return pair->value;
}

/* Find and return the table in hashtable */
static entry_t **ht_find_table(hashtable_t * hashtable, const char *key)
{
        int i = 0;

        while(i < hashtable->size) {
                if(hashtable->table[i] != NULL && hashtable->table[i]->key != NULL 
                        && (strlen(hashtable->table[i]->key) > 0
                        && strncmp(hashtable->table[i]->key, key, strlen(hashtable->table[i]->key)) == 0))
                        return &hashtable->table[i];
                i++;
        }

        debug_msg("key '%s' not found!\n", key);
        return NULL;
}

static int ht_remove_entry(entry_t *entry, entry_t **last, entry_t **next)
{
        if(!entry)
                return -1;


        if (entry->prev) 
                entry->prev->next = entry->next;
        
        if (entry->next) 
                entry->next->prev = entry->prev;
        
        entry->prev = NULL;
        entry->next = NULL;

#ifdef DEBUG_HASHTABLE
        debug_msg("Remove key-value pair with key: %s ", entry->key);
#endif
        if(last != NULL 
                && *last != NULL 
                && *last == entry)
                *last = NULL;
        
        if(next != NULL
                && *next != NULL
                && *next == entry)
                *next = NULL;

        free ((void*)entry->key);
        entry->key = NULL;

        st_data_free(entry->value);
        entry->value = NULL;

        free (entry);
        entry = NULL;

        
        return 0;
}

/* Remove a key-value pair from a hash table and deallocate resources.
 * Return 0 on success, -1 on failure */
int ht_remove(hashtable_t *hashtable, const char *key)
{
        int res;
        entry_t **entry = ht_find_table(hashtable, key);
       
        if((res = ht_remove_entry(*entry, NULL, NULL)) == 0)
                hashtable->count_elems--;

        *entry = NULL;

#ifdef DEBUG_HASHTABLE
        debug_msg("SUCCESSFULLY removed! After remove hashtable->count_elems = %d\n", hashtable->count_elems);
        ht_print_table(hashtable);
#endif

        return res;
}

/*
 * Delete row from hashtable with oldest session. 
 * Return 0 on success, -1 on failure 
 */
static int delete_oldest_session(hashtable_t *hashtable, entry_t **last, entry_t **next)
{
        int i = 0; 
        struct timeval oldest;
        int res;
        int remove_index;
        
        /* set the 'oldest' */
        while(i < hashtable->size) {
                if(hashtable->table[i]) {
                        if(hashtable->table[i]->value->type == type_session) {
                                oldest.tv_sec = ((session_t *)hashtable->table[i]->value)->expires.tv_sec;
                                oldest.tv_usec = ((session_t *)hashtable->table[i]->value)->expires.tv_usec;
                                remove_index = i;
                                break;
                        }
                }
                i++;
        }
        
        /* find an oldest session */
        while(i < hashtable->size) {
                if(hashtable->table[i]) {
                        if(hashtable->table[i]->value->type == type_session) {
                                
                                if(oldest.tv_sec > ((session_t *)hashtable->table[i]->value)->expires.tv_sec) {
                                        oldest.tv_sec = ((session_t *)hashtable->table[i]->value)->expires.tv_sec;
                                        oldest.tv_usec = ((session_t *)hashtable->table[i]->value)->expires.tv_usec;
                                        remove_index = i;

                                } else if(oldest.tv_sec == ((session_t *)hashtable->table[i]->value)->expires.tv_sec) {

                                        if(oldest.tv_usec > ((session_t *)hashtable->table[i]->value)->expires.tv_usec) {
                                                oldest.tv_usec = ((session_t *)hashtable->table[i]->value)->expires.tv_usec;
                                                remove_index = i;
                                        }
                                }
                        }
                }
                i++;
        }
        
        if((res = ht_remove_entry(hashtable->table[remove_index], last, next)) == 0)
                hashtable->count_elems--;

        hashtable->table[remove_index] = NULL;

#ifdef DEBUG_HASHTABLE
        debug_msg("SUCCESSFULLY removed! After remove hashtable->count_elems = %d\n", hashtable->count_elems);
        ht_print_table(hashtable);
#endif
        return res;
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
#ifndef NDEBUG
                                debug_msg(" will be delete a key: %s", hashtable->table[i]->key);
#endif
                                free((void*)hashtable->table[i]->key);
                                hashtable->table[i]->key = NULL;
                        }
                        
                        if(hashtable->table[i]->value) {
                                st_data_free(hashtable->table[i]->value);
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

/* Printing all data in table */
void ht_print_table(hashtable_t *hashtable)
{
#ifndef NDEBUG
        int i = 0;
        
        if (hashtable == NULL)
                return;

        fprintf(stderr, "hashtable: \n"); 
        while(i < hashtable->size) {
                if(hashtable->table[i]) {
                        
                        if(hashtable->table[i]->key) 
                                fprintf(stderr, "'%s'\t", hashtable->table[i]->key); 
                        
                        if(hashtable->table[i]->value
                                && hashtable->table[i]->value->type == type_session) {
                                fprintf(stderr, "tv_sec = %ld", ((session_t*)hashtable->table[i]->value)->expires.tv_sec);
                                fprintf(stderr, " tv_usec = %ld", ((session_t*)hashtable->table[i]->value)->expires.tv_usec);

                                fprintf(stderr, "\t table_ptr = %p", hashtable->table[i]);

                                if(hashtable->table[i]->prev != NULL)
                                        fprintf(stderr, "\t table_prev_ptr = %p", hashtable->table[i]->prev);
                                else 
                                        fprintf(stderr, "\t table_prev_ptr = NULL");
                        
                                if(hashtable->table[i]->next != NULL)
                                        fprintf(stderr, "\t table_next_ptr = %p\n", hashtable->table[i]->next);
                                else 
                                        fprintf(stderr, "\t table_next_ptr = NULL\n");
                        }
                        else
                                st_print(hashtable->table[i]->value);
                }
                i++;
        }
#endif
}

