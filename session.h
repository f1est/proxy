/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#ifndef SESSION_H
#define SESSION_H

#include "common.h"
#include "parser.h"
#include "log.h"
#include "hashmap.h"
#include "transport.h"
#include "struct.h"

/* 
 * create Session ID 
 * return length of SID on succes, or -1 on failure 
 */ 
int session_create_id(req_proxy_to_server_t *proxy_req, char *SID);

/*
 * create cookie-name
 * return cookie-name on success or NULL on failure
 */
const char *session_create_name();

/* 
 * return 0 if header Cookie not exist 
 * return -1 if Cookie-header exist, but it have not EmbeddedSID. 
 * return 1 if Cookie-header exist and it have EmbeddedSID
 */ 
int cookie_check(struct evhttp_request *req_client_to_proxy);

/*
 * concatenate and return string of all pairs of cookies
 * Return NULL on fail, return pointer on new allocated string. 
 * Because in this function used malloc and realloc,
 * return value needs to be deallocated by the caller. 
 * if @param cut_key not NULL, it will be cut
 */
const char *_cookie_get_all_pairs_as_string(hashtable_t *hashtable, const char *cut_key);

/* 
 * check existence of a EmbeddedSID, and it not empty!
 * on success return pointer to value of EmbeddedSID (i.e. after EmbeddedSID=)
 * return NULL on fail
 */
const char *cookie_check_EmbeddedSID(struct evhttp_request* req);

/* 
 * check existence the EmbeddedSID in hashtable of SID's and 
 * check the validity it and to belong to IP-address and User-agent of client
 * return -1 on failure, 0 on success
 */
int check_valid_EmbeddedSID(req_proxy_to_server_t * proxy_req);

/* 
 * remove session from hashtable and dealloca resources
 * when there will be an event 
 */
void clean_session_when_expired_cb(int sock, short which, void *arg); 

#endif /* SESSION_H */
