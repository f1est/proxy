/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#ifndef PARSER_H
#define PARSER_H
#include "common.h"
#include "hashmap.h"
#include "http_handler.h"
#include "event2/keyvalq_struct.h"

/* return 1 if end of string, else return 0 */
int check_end_of_string(char c);

/* 
 * Return NULL on fail,
 * on success return pointer on new allocated hashtable.
 * Return value needs to be deallocated by the caller 
 */
hashtable_t *_parse_cookie_header(const char *header_value);
hashtable_t *_parse_set_cookie_header(const char *header_value);

#endif /* PARSER_H */
