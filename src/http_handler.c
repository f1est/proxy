/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#include "http_handler.h"
#include "log.h"
#include "utils.h"
#include "session.h"
#include "hashmap.h"
#include "times.h"
#include "config.h"
#include "mod_security.h"

#include <event2/keyvalq_struct.h>

/* for debugging */
static void print_headers(struct evhttp_request *req, enum route_of_headers route)
{
#ifndef NDEBUG
        struct evkeyvalq *header = NULL;
        struct evkeyval* kv = NULL;
        const char* str_route = NULL;
        struct evbuffer *buffer_body = NULL;
	const char *method;
        char *address = NULL;
        ev_uint16_t port;
        struct evhttp_connection *evcon;

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
               
        evcon = evhttp_request_get_connection(req);
        if(evcon)
                evhttp_connection_get_peer(evcon, &address, &port);

        if(address)
                fprintf(stderr,"\tPEER ADDRESS: \t%s:%d\n\n", address, port);
                

	switch (req->type) {
	case EVHTTP_REQ_GET:
		method = "GET";
		break;
	case EVHTTP_REQ_POST:
		method = "POST";
		break;
	case EVHTTP_REQ_HEAD:
		method = "HEAD";
		break;
	case EVHTTP_REQ_PUT:
		method = "PUT";
		break;
	case EVHTTP_REQ_DELETE:
		method = "DELETE";
		break;
	case EVHTTP_REQ_OPTIONS:
		method = "OPTIONS";
		break;
	case EVHTTP_REQ_TRACE:
		method = "TRACE";
		break;
	case EVHTTP_REQ_CONNECT:
		method = "CONNECT";
		break;
	case EVHTTP_REQ_PATCH:
		method = "PATCH";
		break;
	default:
		method = NULL;
		break;
	}


        kv = header->tqh_first;

        fprintf(stderr,"\tMETHOD: \t%s\n", method);
        fprintf(stderr,"\tResponse code: \t%d %s\n", evhttp_request_get_response_code(req),
                                        evhttp_request_get_response_code_line(req));
        fprintf(stderr,"\tURI: \t\t%s\n", evhttp_request_get_uri(req));
        print_parsed_uri(evhttp_request_get_evhttp_uri(req));
        fprintf(stderr,"\n");

        while (kv) {
                fprintf(stderr,"\t\t %s header: ", str_route);
                if(kv->key) 
                        fprintf(stderr,"%s: ", kv->key);
                else
                        fprintf(stderr,"key_is_NULL: ");
                
                if(kv->value)
                        fprintf(stderr, "%s\n", kv->value);
                else
                        fprintf(stderr,"value_is_NULL\n");

                kv = kv->next.tqe_next;
        }
        
        fprintf(stderr,"\tget_host: %s\n\n", evhttp_request_get_host(req));

        print_evbuffer(buffer_body);

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

/* for debugging */
void print_evbuffer(struct evbuffer* buf)
{
#if !defined(NDEBUG) && !defined(CLANG_SANITIZER)

        size_t len = 0;
        char *body = NULL;

        len = evbuffer_get_length(buf);

        debug_msg("print_evbuffer !!! length of evbuffer = %zu", len);
        if(len > 0) {
                if((body = malloc(len+1)) == NULL) return;
                evbuffer_copyout(buf, body, len);
                fprintf(stderr,"\n\tsize_evbuffer = %zu evbuffer:\n======'\n%s\n'======\n",len, body);
        }
        else
                fprintf(stderr, "\tlength of body is %zu \n\n",len);

        if(body)
                free(body);
#endif
}

void print_parsed_uri(const struct evhttp_uri* uri)
{
#ifndef NDEBUG
        if(uri == NULL) {
                debug_msg("uri is NULL");
                return;
        }

        fprintf(stderr, "parsed URI: \n");
        if(evhttp_uri_get_scheme(uri))
                fprintf(stderr,"\t\tscheme: %s\n", evhttp_uri_get_scheme(uri));

        if(evhttp_uri_get_userinfo(uri))
                fprintf(stderr,"\t\tuserinfo: %s\n", evhttp_uri_get_userinfo(uri));

        if(evhttp_uri_get_host(uri))
                fprintf(stderr,"\t\thost: %s\n", evhttp_uri_get_host(uri));
        
        if(evhttp_uri_get_port(uri) >= 0)
                fprintf(stderr,"\t\tport: %d\n", evhttp_uri_get_port(uri));

        if(evhttp_uri_get_path(uri))
                fprintf(stderr,"\t\tpath: %s\n", evhttp_uri_get_path(uri));
        
        if(evhttp_uri_get_query(uri))
                fprintf(stderr,"\t\tquery: %s\n", evhttp_uri_get_query(uri));
        
        if(evhttp_uri_get_fragment(uri))
                fprintf(stderr,"\t\tfragment: %s\n", evhttp_uri_get_fragment(uri));
        

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
                debug_msg("Couldn't get headers or buffer of new_req\n");
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

        if(evbuffer_add_buffer(buffer_body_new_req, buffer_body_old_req) != 0) {
                debug_msg("Couldn't copy buffer_body \n");
                return -1;
        }

        return 0;
}

/* copy headers from output to input */
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
static void proxy_add_Embedded_cookie(req_proxy_to_server_t *proxy_req)
{
        extern http_proxy_core_t *proxy_core; 
        extern int use_ssl;        /* boolean */
        char SID[MAX_SID_LENGTH];
        session_t *session = NULL;
        
        if(!proxy_core)
                return;
        if(!proxy_core->SIDs)
                return;
        
        if(!proxy_req)
                return;

        if(proxy_req->hasSID != NULL)
                return;

        if((session_create_id(proxy_req, SID)) > 0) {
                
                size_t buff_len = sizeof(HTTP_TIME_FORMAT);
                size_t expires_len = sizeof("Expires=") + buff_len;
                char buf[buff_len];
                char expires[expires_len];
                size_t cookie_length = MAX_SID_LENGTH 
                                        + strlen(DEFAULT_EMBEDDED_SID_NAME) 
                                        + strlen("; Path=/")
                                        + strlen("; Secure")
                                        + strlen("; HttpOnly")
                                        + expires_len 
                                        + 4; /* +4 for signs '=', ';' (for Expires) and two ' ' (spases) */
                char cookie[cookie_length];
                struct timeval tv;
                int expires_time = config_get_expires_of_cookie();
                
                if(expires_time == -1)
                        expires_time = EXPIRES_OF_COOKIES;
                expires_time *= 60; /* transfer to seconds */

                memset(cookie, '\0', cookie_length);
                memset(expires, '\0', expires_len);
                memset(buf, '\0', buff_len);
                
                if(gettimeofday(&tv, NULL) !=0)
                        debug_msg("Couldn't get time of day. Error: %s", strerror(errno));

                tv.tv_sec += expires_time;
                get_http_cookie_expires_str(buf, buff_len, &tv.tv_sec);
                strncat(expires, "Expires=", 8); 
                strncat(expires, buf, buff_len); 
                
                if(use_ssl)
                        evutil_snprintf(cookie, cookie_length, "%s=%s; %s; %s", session_create_name(), SID, expires, "Path=/; Secure; HttpOnly");

                else
                        evutil_snprintf(cookie, cookie_length, "%s=%s; %s; %s", session_create_name(), SID, expires, "Path=/; HttpOnly");

                evhttp_add_header(evhttp_request_get_output_headers(proxy_req->req_client_to_proxy), "Set-Cookie", cookie);
                
                session = st_session_t_init();
                session->expires.tv_sec = tv.tv_sec;
                session->expires.tv_usec = tv.tv_usec;
                st_session_t_add_expires_str(session, buf);

                if(ht_add(proxy_core->SIDs, SID, (base_t*)session) == 0) {
                        
                        proxy_req->hasSID = ht_get_value(proxy_core->SIDs, SID);
                        
                        debug_msg("New Embedded-cookie added to hashtable");
                        ht_print_table(proxy_core->SIDs);
                }

        }

        if(session)
                st_data_free((base_t*)session);
}

/* create reply for send to client */
void proxy_create_reply(req_proxy_to_server_t * proxy_req)
{
        const char *value;
        struct bufferevent *bev_serv;
        struct bufferevent *bev_client;

        if(proxy_req == NULL)
                return;
        
        if(proxy_req->req_client_to_proxy == NULL)
                return;
        
        if(proxy_req->req_proxy_to_server == NULL)
                return;

        /* create headers of reply */
        struct evkeyvalq *proxy_headers_output_reply = evhttp_request_get_output_headers(proxy_req->req_client_to_proxy);

        copy_only_request_headers(proxy_headers_output_reply,
                                        evhttp_request_get_input_headers(proxy_req->req_proxy_to_server));

        /* add EmbeddedSID */
        if(proxy_req->hasSID == NULL)
                proxy_add_Embedded_cookie(proxy_req);

        /* change a Expires in Set-Cookie-header of reply */
        value = evhttp_find_header(proxy_headers_output_reply,"Set-Cookie");
        

//TODO: FIND and chage ALL headers Set-Cookie !!!
        debug_msg("TODO: FIND and change ALL headers Set-Cookie !!!");

        if(value) {
                hashtable_t *parsed_set_cookie = _parse_set_cookie_header(proxy_req->req_proxy_to_server, input);
                base_t *expires = ht_get_value(parsed_set_cookie, "Expires");
                if(expires != NULL && proxy_req->hasSID != NULL) {
                        if(expires->type == type_string) {

                                if(((string_t*)expires)->str != NULL)
                                        free((void*)((string_t*)expires)->str);

                                ((string_t*)expires)->str = ((session_t*)proxy_req->hasSID)->expires_str;
                                
                                const char * new_value_set_cookie = _cookie_get_all_pairs_as_string(parsed_set_cookie, NULL);

                                if(new_value_set_cookie != NULL) {

                                        evhttp_remove_header(proxy_headers_output_reply, "Set-Cookie");
                                        evhttp_add_header(proxy_headers_output_reply, "Set-Cookie", new_value_set_cookie);

                                        free((void*)new_value_set_cookie);

                                }
                                ((string_t*)expires)->str = NULL;
                        }
                }
                if(parsed_set_cookie != NULL)
                       ht_free(parsed_set_cookie);
        }

        /* add security headers from json-file */
        add_security_headers_to_response(proxy_req);
}

static void is_JQUERY(int i)
{
        debug_msg("%d is /js/jquery-1.11.1.min.js?v=20170519164616 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", i);
}

/* send reply from proxy to client */
void proxy_send_reply(req_proxy_to_server_t * proxy_req)
{
        
        /* handle a chunked reply */
        if(proxy_req->req_proxy_to_server->chunked &&
                proxy_req->req_client_to_proxy->chunked) { 
                evhttp_send_reply_end(proxy_req->req_client_to_proxy);
debug_msg("\t CHUNK END !!!!!!!!!!!!!!!!!!!!!!!!!!!!! END");
        }

        /* a not chunked reply */
        else {
                proxy_create_reply(proxy_req);

if(strstr(evhttp_request_get_uri(proxy_req->req_client_to_proxy),"jquery-1.11.1.min.js")) {
is_JQUERY(1);
print_evbuffer(evhttp_request_get_input_buffer(proxy_req->req_proxy_to_server));
}
                evhttp_send_reply(proxy_req->req_client_to_proxy, evhttp_request_get_response_code(proxy_req->req_proxy_to_server),
                                evhttp_request_get_response_code_line(proxy_req->req_proxy_to_server),
                                evhttp_request_get_input_buffer(proxy_req->req_proxy_to_server));


        }
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
