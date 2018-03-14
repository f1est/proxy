/*
 * @author f1est 
 */
 
#include "http_handler.h"
#include "log.h"
#include <event2/keyvalq_struct.h>

static void print_headers(struct evhttp_request *req, enum route_of_headers route)
{
#ifndef NDEBUG
        struct evkeyvalq *header = NULL;
        struct evkeyval* kv = NULL;
        const char* str_route = NULL;
        struct evbuffer *buffer_body = NULL;
        size_t len;
        char *body = NULL;
        switch(route){
                case input:
                        header = evhttp_request_get_input_headers(req);
                        buffer_body = evhttp_request_get_input_buffer(req);
                        str_route = "input";
                        break;
                case output:
                        header = evhttp_request_get_output_headers(req);
                        buffer_body = evhttp_request_get_output_buffer(req);
                        str_route = "output";
                        break;
                default:
                        break;
        }
        if(!header || !buffer_body)
                return;
                
        kv = header->tqh_first;
        printf("\tURI: %s\n", evhttp_request_get_uri(req));
        while (kv) {
                printf("\t%s header: %s: %s\n", str_route, kv->key, kv->value);
                kv = kv->next.tqe_next;
        }
                printf("\tget_host: %s\n", evhttp_request_get_host(req));

        len = evbuffer_get_length(buffer_body);
        if(len > 0) {
                body = malloc(len);
                evbuffer_copyout(buffer_body, body, len);
                printf("\n\tsize_body = %zu body:\n %s\n",len, body);
        }

        if(body)
                free(body);
#endif
}

void print_input_req(struct evhttp_request* req)
{
        print_headers(req,input);
}
void print_output_req(struct evhttp_request* req)
{
        print_headers(req,output);
}

void print_evbuffer(struct evbuffer* buf)
{
#ifndef NDEBUG
        size_t len;
        char *body = NULL;
        len = evbuffer_get_length(buf);
        if(len > 0) {
                body = malloc(len);
                evbuffer_copyout(buf, body, len);
                printf("\n\tsize_evbuffer = %zu evbuffer:\n %s\n",len, body);
        }

        if(body)
                free(body);
#endif
}

/*
 * returns 0 on success, -1  otherwise.
 */
int copy_request_parameters(struct evhttp_request *old_req, 
                enum route_of_headers route_old_req,
                struct evhttp_request *new_req,
                enum route_of_headers route_new_req)
{
        struct evkeyvalq *headers_old_req = NULL;
        struct evkeyvalq *headers_new_req = NULL;
        struct evkeyval* kv = NULL;
        struct evbuffer *buffer_body_old_req = NULL;
        struct evbuffer *buffer_body_new_req = NULL;

        switch(route_old_req) {
                case input:
                        headers_old_req = evhttp_request_get_input_headers(old_req);
                        buffer_body_old_req = evhttp_request_get_input_buffer(old_req);
                        break;
                case output:
                        headers_old_req = evhttp_request_get_output_headers(old_req);
                        buffer_body_old_req = evhttp_request_get_output_buffer(old_req);
                        break;
                default:
                        break;
        }

        if(!headers_old_req || !buffer_body_old_req) {
                debug_msg("Couldn't get headers or buffer of old_req\n");
                return -1;
        }
                
        switch(route_new_req) {
                case input:
                        headers_new_req = evhttp_request_get_input_headers(new_req);
                        buffer_body_new_req = evhttp_request_get_input_buffer(new_req);
                        break;
                case output:
                        headers_new_req = evhttp_request_get_output_headers(new_req);
                        buffer_body_new_req = evhttp_request_get_output_buffer(new_req);
                        break;
                default:
                        break;
        }
        
        if(!headers_new_req || !buffer_body_new_req) {
                debug_msg("Couldn't get header or buffer of new_req\n");
                return -1;
        }

        kv = headers_old_req->tqh_first;
        while (kv) {
                if(evhttp_add_header(headers_new_req, kv->key, kv->value) != 0){
                        debug_msg("evhttp_add_header error! header: %s value: %s\n",
                                        kv->key, kv->value);
                        return -1;
                }
                kv = kv->next.tqe_next;
        }
        if(evbuffer_add_buffer(buffer_body_old_req, buffer_body_new_req) != 0) {
                debug_msg("Couldn't copy buffer_body \n");
                return -1;
        }
        return 0;
}

int copy_request_only_headers(struct evkeyvalq* input, struct evkeyvalq* output)
{
        struct evkeyval* kv = output->tqh_first;
        while (kv) {
                if(evhttp_add_header(input, kv->key, kv->value) != 0){
                        debug_msg("evhttp_add_header error! header: %s value: %s\n",
                                        kv->key, kv->value);
                        return -1;
                }
                kv = kv->next.tqe_next;
        }
        return 0;
        
}

int change_header_value(struct evhttp_request* req, 
                enum route_of_headers route,
                const char* header,
                const char* new_value)
{
        struct evkeyvalq *headers = NULL;
        
        switch(route){
                case input:
                        headers = evhttp_request_get_input_headers(req);
                        break;
                case output:
                        headers = evhttp_request_get_output_headers(req);
                        break;
                default:
                        break;
        }
        if(!headers) {
                debug_msg("Couldn't get headers of req\n");
                return -1;
        }

        if(evhttp_remove_header(headers, header) != 0) {
                debug_msg("Couldn't remove header: %s\n", header);
                return -1;
        }
        if(evhttp_add_header(headers, header, new_value) != 0) {
                debug_msg("Couldn't add header: %s with value: %s\n",
                        header, new_value);
                return -1;
        }
        return 0;
}

/*
void http_handler_cb(struct evhttp_request* req, void* ctx)
{
        printf("http_handler_cb !!!!!!!!!!!!!!!!!!!!!\n");
        printf("http_handler_cb !!!!!!!!!!!!!!!!!!!!!\n");
        printf("http_handler_cb !!!!!!!!!!!!!!!!!!!!!\n");
        printf("http_handler_cb !!!!!!!!!!!!!!!!!!!!!\n");

        struct evkeyvalq* output_headers;
        struct evkeyvalq* input_headers;
        output_headers = evhttp_request_get_output_headers(req);
        input_headers = evhttp_request_get_input_headers(req);

        print_input_req(req);

        printf("out header = %s in header = %s\n", 
                evhttp_find_header(output_headers, "Host"), 
                evhttp_find_header(input_headers, "Host"));

//        printf("out buffer = \n %s in buffer = \n %s\n", 
                
        if(evhttp_request_get_connection(req) != NULL) {
                char *address = NULL;
                ev_uint16_t port = 0;
                evhttp_connection_get_peer(evhttp_request_get_connection(req), &address ,&port);
                printf("CONNECTION NOT NULL!!!\n");
                printf("\t evhttp_connection_get_peer address = %s port = %d \n",
                        address, port);

                printf("0_______________________\n");
                struct sockaddr_in *addr_in = (struct sockaddr_in *)evhttp_connection_get_addr(evhttp_request_get_connection(req));
                printf("1_______________________\n");
                char *s = inet_ntoa(addr_in->sin_addr);
                printf("2_______________________\n");
                if(s)
                        printf("IP address: TRUE\n");
                else
                        printf("IP address: NULL\n");


                s = malloc(INET_ADDRSTRLEN);
                inet_ntop(AF_INET, &(addr_in->sin_addr), s, INET_ADDRSTRLEN);
                printf("IP address: %s \n", s);



        }
        else
                printf("CONNECTION is NULL!!!\n");

        evhttp_send_error(req, 500, "Internal Error");
}
*/
