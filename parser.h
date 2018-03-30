/*
 * @author f1est 
 */
 
#ifndef PARSER_H
#define PARSER_H
#include "common.h"
#include "hashmap.h"
#include "http_handler.h"

/* return 1 if end of string, else return 0 */
int check_end_of_string(char c);

/* 
 * Return NULL on fail,
 * on success return pointer on new allocated hashtable.
 * Return value needs to be deallocated by the caller 
 */
hashtable_t *_parse_cookie_header(struct evhttp_request* req, enum route_of_headers route_req);
hashtable_t *_parse_set_cookie_header(struct evhttp_request* req,  enum route_of_headers route_req);

#endif /* PARSER_H */
