/*
 * @author f1est 
 */
 
#include "http_handler.h"
#include "log.h"
#include "utils.h"
#include "session.h"
#include "hashmap.h"

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

        fprintf(stderr,"\tResponse code: %d\n", evhttp_request_get_response_code(req));
        fprintf(stderr,"\tURI: %s\n", evhttp_request_get_uri(req));

        while (kv) {
                fprintf(stderr,"\t\t %s header: %s: %s\n", str_route, kv->key, kv->value);
                kv = kv->next.tqe_next;
        }
        
        fprintf(stderr,"\tget_host: %s\n\n", evhttp_request_get_host(req));

        len = evbuffer_get_length(buffer_body);

        debug_msg(" length of evbuffer = %zu", len);
        if(len > 0) {
                if((body = malloc(len)) == NULL) return;
                evbuffer_copyout(buffer_body, body, len);
                fprintf(stderr,"\tsize_body = %zu body:\n\n %s\n",len, body);
        }

        else
                fprintf(stderr, "\tlength of body is %zu \n\n",len);

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
                if((body = malloc(len)) == NULL) return;
                evbuffer_copyout(buf, body, len);
                fprintf(stderr,"\n\tsize_evbuffer = %zu evbuffer:\n %s\n",len, body);
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

int copy_only_request_headers(struct evkeyvalq* input, struct evkeyvalq* output)
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

        if(evutil_ascii_strncasecmp(
                evhttp_find_header(headers, header), new_value, strlen(new_value)) != 0) {
        
                if(evhttp_remove_header(headers, header) != 0) {
                        debug_msg("Couldn't remove header: %s\n", header);
                        return -1;
                }

                if(evhttp_add_header(headers, header, new_value) != 0) {
                        debug_msg("Couldn't add header: %s with value: %s\n",
                                header, new_value);
                        return -1;
                }
        }

        return 0;
}


/* create Session ID, put it to Set-Cookie header of proxy
 * and save SID to hashmap */
static void proxy_add_cookie(req_proxy_to_server_t * proxy_req)
{
        debug_msg("TODO: need check exist or not and save SID to hashmap !!! \n");
        extern http_proxy_core_t *proxy_core; 
        const char *SID;
        const char *hash;
        session_t *session;
        
        if(!proxy_core)
                return;
        if(!proxy_core->SIDs)
                return;
        
        if(!proxy_req)
                return;

        if((hash = get_hash_of_client(proxy_req)) == NULL)
                return;

        if((session = ht_get_value(proxy_core->SIDs, hash)) != NULL) /* already exist */
                return;

        if((SID = session_create_id()) != NULL) {
                size_t cookie_length = MAX_SID_LENGTH + strlen(DEFAULT_SID_NAME) + 1; /* +1 for sign '=' */
                char cookie[cookie_length]; 
                memset(cookie, '\0', cookie_length);
                evutil_snprintf(cookie, cookie_length, "%s=%s", session_create_name(), SID);
                evhttp_add_header(evhttp_request_get_output_headers(proxy_req->req_client_to_proxy), "Set-Cookie", cookie);
        }

        session = malloc(sizeof(session_t));
        session->SID = SID;
}

/* send reply from proxy to client */
void proxy_send_reply(req_proxy_to_server_t * proxy_req)
{
        if(!proxy_req)
                return;

        struct evkeyvalq *proxy_headers_output_reply = evhttp_request_get_output_headers(proxy_req->req_client_to_proxy);

        copy_only_request_headers(proxy_headers_output_reply,
                                        evhttp_request_get_input_headers(proxy_req->req_proxy_to_server));

        proxy_add_cookie(proxy_req);

        /* handle a chunked reply */
        const char *value = evhttp_find_header(proxy_headers_output_reply,"Transfer-Encoding");

        if(value && (evutil_ascii_strncasecmp(value, "chunked", 7) == 0)) {

                debug_msg("TODO: !!!!! Correctly process sending chunked reply !!!!!\n");

                evhttp_send_reply_start(proxy_req->req_client_to_proxy, 
                                evhttp_request_get_response_code(proxy_req->req_proxy_to_server),
                                evhttp_request_get_response_code_line(proxy_req->req_proxy_to_server));

                evhttp_send_reply_chunk(proxy_req->req_client_to_proxy,
                                evhttp_request_get_input_buffer(proxy_req->req_proxy_to_server));

                evhttp_send_reply_end(proxy_req->req_client_to_proxy);
        }
        else
                evhttp_send_reply(proxy_req->req_client_to_proxy, evhttp_request_get_response_code(proxy_req->req_proxy_to_server),
                                evhttp_request_get_response_code_line(proxy_req->req_proxy_to_server),
                                evhttp_request_get_input_buffer(proxy_req->req_proxy_to_server));




        debug_msg("App->Proxy RESP:");
        print_input_req(proxy_req->req_proxy_to_server);

        debug_msg("Proxy->Browser RESP:");
        print_output_req(proxy_req->req_client_to_proxy);
       
}

/* send 403 reply and close connection */
void proxy_send_403_reply(struct evhttp_request* req)
{
        change_header_value(req, input, "Connection", "close");
        evhttp_send_reply(req, 403,"Forbidden", NULL);
}
