/*
 * @author f1est 
 */
 
#ifndef PARSER_H
#define PARSER_H
#include "common.h"
#include "hashmap.h"
#include "http_handler.h"

/* 
 * check existence of a SID, and it not empty!
 * on success return pointer to value of SID (i.e. after SID=)
 * return NULL on fail
 */
const char *cookie_check_SID(struct evhttp_request* req);

/* return value needs to be deallocated by the caller */
//const char *cookie_get_SID(struct evhttp_request* req);

/* 
 * Return NULL on fail,
 * on success return pointer on new allocated hashtable.
 * Return value needs to be deallocated by the caller 
 */
hashtable_t *parse_cookie_header(struct evhttp_request* req, enum route_of_headers route_req);
hashtable_t *parse_set_cookie_header(struct evhttp_request* req,  enum route_of_headers route_req);

#endif /* PARSER_H */
