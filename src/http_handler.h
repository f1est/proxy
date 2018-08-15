/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H
#include "common.h"
#include "transport.h"

enum route_of_headers {input,output};

void print_input_req(struct evhttp_request* req);
void print_output_req(struct evhttp_request* req);
void print_evbuffer(struct evbuffer* buf);
void print_parsed_uri(struct evhttp_uri* uri);

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

/* create reply for send to client */
void proxy_create_reply(req_proxy_to_server_t * proxy_req);

/* send reply from proxy to client */
void proxy_send_reply(req_proxy_to_server_t * proxy_req);

/* send 403 reply and close connection */
void proxy_send_403_reply(struct evhttp_request* req);

void http_handler_cb(struct evhttp_request* req, void* ctx);

#endif

