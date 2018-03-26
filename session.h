/*
 * @author f1est 
 */
 
#ifndef SESSION_H
#define SESSION_H

#include "common.h"
#include "parser.h"
#include "log.h"
#include "hashmap.h"
#include "transport.h"

#define HASH_LENGTH 18

typedef struct session_s session_t;
struct session_s {
        
        /* Session ID */
        const char *SID;
};

/* generate random/pseudorandom 
 * here device:
 * 1. /dev/random  should be used for long lived GPG/SSL/SSH keys.
 * 2. /dev/urandom should be used in other cases (pseudorandom).
 * If arg 'device' is NULL - enable the default value /dev/urandom
 * return 0 on success, -1 on filure.
 */

//int get_random_bytes(void *bytes, size_t size, const char * device);

//size_t bin_to_readable(unsigned char *in, size_t inlen, char *out, char nbits);

/* 
 * create Session ID 
 * return value needs to be deallocated by the caller if necessary.
 * return SID-string on succes, or NULL on failure 
 */ 
const char *session_create_id();

/*
 * create cookie-name
 * return cookie-name on success or NULL on failure
 */
const char *session_create_name();

/* 
 * return 0 if header Cookie not exist 
 * return -1 if Cookie-header exist, but it have not SID. In this case,
 * will be send 403-reply and close connection/
 * return 1 if Cookie-header exist and it have SID
 */ 
int cookie_check(struct evhttp_request *req_client_to_proxy);

/*
 * concatenate and return string of all pairs of cookies
 * return NULL on fail
 * return value needs to be deallocated by the caller.
 * if @param cut_key not NULL, it will be cut
 */
const char *cookie_get_all_pairs_as_string(hashtable_t *hashtable, const char *cut_key);

/* 
 * return hash for peer connection and User-agent header of client on success
 * return NULL on failure 
 * return value needs to be deallocated by the caller.
 */
const char *get_hash_of_client(req_proxy_to_server_t *proxy_req);

/* 
 * check existence the SID in hashtable of SID's and 
 * check the validity it and to belong to IP-address and User-agent of client
 * return -1 on failure, 0 on success
 */
int check_valid_SID(req_proxy_to_server_t * proxy_req);
#endif /* SESSION_H */
