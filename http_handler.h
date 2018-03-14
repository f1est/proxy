/*
 * @author f1est 
 */
 
#ifndef HTTP_HANDLER_H
#define HTTP_HANDLER_H
#include "common.h"

enum route_of_headers {input,output};

void print_input_req(struct evhttp_request* req);
void print_output_req(struct evhttp_request* req);
void print_evbuffer(struct evbuffer* buf);

int copy_request_parameters(struct evhttp_request *old_req, 
                enum route_of_headers route_old_req,
                struct evhttp_request *new_req,
                enum route_of_headers route_new_req);
int copy_request_only_headers(struct evkeyvalq* input, struct evkeyvalq* output);
//struct evhttp_request* clone_request(struct evhttp_request *req);

//int proxy_send_reply(

int change_header_value(struct evhttp_request* req,
                enum route_of_headers route,
                const char *header,
                const char* new_value);

void http_handler_cb(struct evhttp_request* req, void* ctx);

#endif

