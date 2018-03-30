/*
 * @author f1est 
 */
 
#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "common.h"
#include "hashmap.h"

typedef struct http_proxy_core_s http_proxy_core_t;
struct http_proxy_core_s {
        struct evhttp *http_server;
        struct evhttp_bound_socket *evhttp_socket;
        hashtable_t *SIDs; 
};

typedef struct http_proxy_peer_client_s http_proxy_peer_client_t;
struct http_proxy_peer_client_s {
        char *peer_address;
        char *user_agent;
};

typedef struct req_proxy_to_server_s req_proxy_to_server_t;
struct req_proxy_to_server_s {
        struct evhttp_connection *serv_conn;
        struct evhttp_request *req_proxy_to_server;
        struct evhttp_request *req_client_to_proxy;
        struct event *cleanup;

        /* table will be filled after parsing a Cookie-header */
        hashtable_t *cookies_tbl;

        /* If a new request contains SID, param hasSID will be TRUE (1). 
         * Hence, we know should create and add SID to response or not */
        int hasSID; 
};

void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,struct sockaddr *a, int slen, void *p);
http_proxy_core_t *http_request_init(struct evconnlistener *listener);
void free_proxy_core(http_proxy_core_t *core);


#endif /* TRANSPORT_H */
