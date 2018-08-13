/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H
#include "common.h"
#include "transport.h"


#define HEAD_FIRST(head)       ((head)->tqh_first)
#define HEAD_NEXT(elm, field)  ((elm)->field.tqe_next)
#define HEAD_END(head)         NULL
#define HEAD_FOREACH(var, head, field) \
    for ((var) = HEAD_FIRST(head); \
            (var) != HEAD_END(head); \
            (var) = HEAD_NEXT(var, field))

enum route_of_headers {input,output};

void print_input_req(struct evhttp_request* req);
void print_output_req(struct evhttp_request* req);
void print_evbuffer(struct evbuffer* buf);
void print_parsed_uri(const struct evhttp_uri* uri);

int copy_request_parameters(struct evhttp_request *old_req, 
                enum route_of_headers route_old_req,
                struct evhttp_request *new_req,
                enum route_of_headers route_new_req);

/* copy headers from output to input */
int copy_only_request_headers(struct evkeyvalq* input, struct evkeyvalq* output);

int change_header_value(struct evhttp_request* req,
                enum route_of_headers route,
                const char *header,
                const char* new_value);

/* 
 * check scheme and port
 * return 1 if scheme and port matched, else return 0. On error return -1.
 * For example if scheme is https and port == 443, or
 * if scheme is http and port == 80 will be returned 1,
 * else will be returned 0
 */
int is_matched_scheme_and_port(struct evhttp_uri *uri, int port);

/* 
 * change host and port in URI 
 * return 0 on success, -1 on failure
 */
int change_URI_host_port(const char *source_uri, 
                                char* dst_uri, 
                                size_t dst_len,
                                const char* host_dst, 
                                int port_dst);

/* create reply for send to client */
void proxy_create_reply(req_proxy_to_server_t * proxy_req);

/* send reply from proxy to client */
void proxy_send_reply(req_proxy_to_server_t * proxy_req);

/* Delete all cookies from the query by setting its an expiration date in the past */
void removeAllCookies(struct evhttp_request* req);

/* send 403 reply and close connection */
void proxy_send_403_reply(struct evhttp_request* req);

void http_handler_cb(struct evhttp_request* req, void* ctx);

#endif

