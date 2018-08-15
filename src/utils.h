/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#ifndef UTILS_H
#define UTILS_H

#include "common.h"
#include "cJSON.h"

void daemonize(const char* program_name);

/* handling signals */
void set_signals();

/* dealloca */
void free_signals();

/* change user when run on root */
/* Return 0 on success. -1 on failure */
int change_user();

/* parse JSON file with key-value pairs: uri:security_headers */
cJSON *parse_json_file(const char *filename);

#endif /*UTILS_H*/
