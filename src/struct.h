/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#ifndef STRUCT_H
#define STRUCT_H

#include "common.h"
#include "log.h"


typedef struct base_s base_t;

struct base_s {
        enum {
                type_string,
                type_session
        } type;
        base_t *(*clone)(base_t *this);
        void (*free_content)(base_t *this);
};

typedef struct {
        base_t base;
        const char * str;
} string_t;

typedef struct {
        base_t base;
        
        /* Session ID */
        const char *SID;

        /* Event on which freeing session when time expired.
         * This value not copy or allocate in clone function,
         * thus need to call in manually */
        struct event *cleanup;

        const char *expires_str;
        struct timeval expires;

} session_t;

/* working with struct string_t */
string_t *st_string_t_init_ptr();

void st_string_t_init(string_t *data, char * str);

const char *st_string_t_get_str(string_t * str);

/* working with struct session_t */
session_t *st_session_t_init();

int st_session_t_add_expires_str(session_t *session, const char *expires_str);

void session_add_expires_event(session_t *session, const char *hash); 


/* deallocate */
void st_data_free(base_t *this);

void st_print(base_t *this);


/* callbacks */
void fn_content_free(base_t *this);

base_t *fn_data_clone(base_t *this);

#endif
