/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#include "transport.h"
#include "log.h"
#include "http_handler.h"
#include "session.h"
#include "config.h"
#include "utils.h"


static void drained_writecb(struct bufferevent *bev, void *ctx);
static void eventcb(struct bufferevent *bev, short what, void *ctx);

static req_proxy_to_server_t *init_struct_req_proxy_to_server()
{
        req_proxy_to_server_t *proxy_req;
        if((proxy_req = malloc(sizeof(req_proxy_to_server_t))) == NULL)
                return NULL;

        memset(proxy_req, 0, sizeof(struct req_proxy_to_server_s));

        proxy_req->serv_conn = NULL;
        proxy_req->client_conn = NULL;
        proxy_req->req_proxy_to_server = NULL;
        proxy_req->req_client_to_proxy = NULL;
        proxy_req->cleanup = NULL;
        proxy_req->cookies_tbl = NULL;
        proxy_req->uri = NULL;
        proxy_req->hasSID = NULL;



        return proxy_req;
}

void readcb(struct bufferevent *bev, void *ctx)
{
        struct bufferevent *partner = ctx;
        struct evbuffer *src, *dst;
        extern int use_core_webtoolkit;

        if (!bev || !partner) 
                return;

        src = bufferevent_get_input(bev);

#if !defined(NDEBUG) && !defined(CLANG_SANITIZER)
        size_t len;
        char *data_src = NULL;
        len = evbuffer_get_length(src);
        if(len > 0) {
                if((data_src = malloc(len)) == NULL) return;
                evbuffer_copyout(src, data_src, len);
                fprintf(stderr,"!!! BUFFER SRC: len: %d data:\n %s\n", 
                        (int)len, data_src);
        }
#endif
        dst = bufferevent_get_output(partner);
        evbuffer_add_buffer(dst, src);

#if !defined(NDEBUG) && !defined(CLANG_SANITIZER)
        char *data_dst = NULL;
        size_t len_dst;
        len_dst = evbuffer_get_length(dst);
        if(len_dst > 0) {
                if((data_dst = malloc(len_dst)) == NULL) return;
                evbuffer_copyout(dst, data_dst, len_dst);

                fprintf(stderr,"!!! BUFFER DST: len: %d data:\n %s\n", 
                        (int)len_dst, data_dst);
        }
#endif

        if (evbuffer_get_length(dst) >= MAX_OUTPUT) {

        debug_msg("WARNING!!! Destination buffer > MAX_OUTPUT(%d) STOP READING !!!\n",
                                MAX_OUTPUT);
                /* Если длина больше чем MAX_OUTPUT, значит мы передаем данные
                 * быстрее чем другая сторона может обработать, поэтому приостановим 
                 * чтение пока на другой стороне не освободится MAX_OUTPUT/2 байт. */
                bufferevent_setcb(partner, readcb, drained_writecb, eventcb, bev);
                bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2, MAX_OUTPUT);
                bufferevent_disable(bev, EV_READ);
        }
#if !defined(NDEBUG) && !defined(CLANG_SANITIZER)
        if(data_src)
                free(data_src);
        if(data_dst)
                free(data_dst);
#endif
}

static void drained_writecb(struct bufferevent *bev, void *ctx)
{
        struct bufferevent *partner = ctx;

        bufferevent_setcb(bev, readcb, NULL, eventcb, partner);
        bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
        if (partner) {
        /* Продолжим чтение */
        debug_msg("RESTORE READING !!!\n");
                bufferevent_enable(partner, EV_READ);
        }
}

static void close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
        struct evbuffer *b = bufferevent_get_output(bev);

        if (evbuffer_get_length(b) == 0) {

                if(bev == NULL)
                        return;
                
                bufferevent_free(bev);
        }
}

static void eventcb(struct bufferevent *bev, short what, void *ctx)
{
        struct bufferevent *partner = ctx;

        if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
                if (what & BEV_EVENT_ERROR) {
                        unsigned long err;
                        while ((err = (bufferevent_get_openssl_error(bev)))) {
                                const char *msg = (const char*)ERR_reason_error_string(err);
                                const char *lib = (const char*)ERR_lib_error_string(err);
                                const char *func = (const char*)ERR_func_error_string(err);
                                fprintf(stderr,"%s in %s %s\n", msg, lib, func);
                        }
                        if (errno)
                                perror("connection error");
                }

                if (partner) {
                        /* Сброс всех ожидающих данных */
                        readcb(bev, ctx);

                        /* Закроем соединение с другой стороной */
                        if (evbuffer_get_length(bufferevent_get_output(partner))) {
                                bufferevent_setcb(partner, NULL, close_on_finished_writecb, eventcb, NULL);
                                bufferevent_disable(partner, EV_READ);
                        } else {
                                bufferevent_free(partner);
                        }
                }
                
                bufferevent_free(bev);
        }
}
/* этот callback вызывается когда не используются какие-либо WebToolKit-модули */
void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,struct sockaddr *a, int slen, void *p)
{
        extern SSL_CTX *ssl_ctx;
        extern struct sockaddr_storage connect_to_addr;
        extern int connect_to_addrlen;
        extern int use_ssl;
        extern struct event_base *base;
        struct bufferevent *b_in;
        struct bufferevent *b_out;


        if (use_ssl) {
                SSL *ssl = SSL_new(ssl_ctx);
                b_in = bufferevent_openssl_socket_new(base, fd, ssl, BUFFEREVENT_SSL_ACCEPTING,
                    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
                b_out = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
        } else {
                b_in = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
                b_out = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
        }

        assert(b_in && b_out);

        if (bufferevent_socket_connect(b_out,(struct sockaddr*)&connect_to_addr, connect_to_addrlen) < 0) {
                perror("bufferevent_socket_connect");
                bufferevent_free(b_out);
                bufferevent_free(b_in);
                b_in = NULL;
                b_out = NULL;
                return;
        }


        bufferevent_setcb(b_in, readcb, NULL, eventcb, b_out);
        bufferevent_setcb(b_out, readcb, NULL, eventcb, b_in);

        bufferevent_enable(b_in, EV_READ|EV_WRITE);
        bufferevent_enable(b_out, EV_READ|EV_WRITE);
}

static struct bufferevent * http_accept_cb(struct event_base *base, void * ctx)
{
        extern int use_ssl;
        extern SSL_CTX *ssl_ctx;
        struct bufferevent *b_in = NULL;
        http_proxy_core_t *proxy_core =  ctx;

        if (use_ssl) {
                SSL *ssl = SSL_new(ssl_ctx);
                b_in = bufferevent_openssl_socket_new(base, evconnlistener_get_fd(evhttp_bound_socket_get_listener(proxy_core->evhttp_socket)), ssl, BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);
//                    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
//                    BEV_OPT_CLOSE_ON_FREE);
        } else {
//                b_in = bufferevent_socket_new(base, evconnlistener_get_fd(evhttp_bound_socket_get_listener(proxy_core->evhttp_socket)), BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
//                b_in = bufferevent_socket_new(base, evconnlistener_get_fd(evhttp_bound_socket_get_listener(proxy_core->evhttp_socket)), BEV_OPT_CLOSE_ON_FREE);
                b_in = bufferevent_socket_new(base, evconnlistener_get_fd(evhttp_bound_socket_get_listener(proxy_core->evhttp_socket)), BEV_OPT_CLOSE_ON_FREE);
        }

        bufferevent_setcb(b_in, NULL, NULL, eventcb, NULL);
        return b_in;
}


static void http_connection_free(req_proxy_to_server_t * proxy_req)
{
        if(proxy_req == NULL)
                return;

        if(proxy_req->cleanup)
                event_free(proxy_req->cleanup);
        
        if(proxy_req->serv_conn)
                evhttp_connection_free(proxy_req->serv_conn);

        proxy_req->hasSID = NULL;

        /* proxy_req->req_proxy_to_server will be freed when free proxy_req->serv_conn !!! */
        /* param 'uri' will be freed when free proxy_req->req_client_to_proxy */
        
        if(proxy_req->cookies_tbl)
                ht_free(proxy_req->cookies_tbl);


        free(proxy_req);
}

static void http_connection_free_cb(int sock, short which, void *arg) 
{
        req_proxy_to_server_t *proxy_req = arg;
        http_connection_free(proxy_req);
}

static void http_request_error_cb(enum evhttp_request_error error, void *arg)
{
        debug_msg("CATCH ERROR!!!");

        switch(error) {
                case EVREQ_HTTP_TIMEOUT:
                        debug_msg("\t EVREQ_HTTP_TIMEOUT");
                        break;
                
                case EVREQ_HTTP_EOF:
                        debug_msg("\t EVREQ_HTTP_EOF");
                        break;
                
                case EVREQ_HTTP_INVALID_HEADER:
                        debug_msg("\t EVREQ_HTTP_INVALID_HEADER");
                        break;
                
                case EVREQ_HTTP_BUFFER_ERROR:
                        debug_msg("\t EVREQ_HTTP_BUFFER_ERROR");
                        break;
                
                case EVREQ_HTTP_REQUEST_CANCEL:
                        debug_msg("\t EVREQ_HTTP_REQUEST_CANCEL");
                        break;
                
                case EVREQ_HTTP_DATA_TOO_LONG:
                        debug_msg("\t EVREQ_HTTP_DATA_TOO_LONG");
                        break;

                default:
                        debug_msg("\t UNKNOWN ERROR!!!");
                        break;
        }
}

/* 
 * Handles responses to our proxy from connect_addr (from an application)
 * and deliver them to listen_addr (to a web-browser)
 * Here 'resp_server_to_proxy' is request to connect_addr.
 */
static void http_response_handler_cb(struct evhttp_request* resp_server_to_proxy, void *ctx)
{
        extern struct event_base *base;
        req_proxy_to_server_t *proxy_req = (req_proxy_to_server_t *) ctx;
        struct timeval timeout;

        if(!resp_server_to_proxy) {
                debug_msg("ERROR!!! Request to connect_addr is NULL!!!\n");
                debug_msg("ERROR!!! TODO: HANDLE THIS ERROR!!!\n");

                http_connection_free(proxy_req);
                return;
        }
debug_msg("http_response_handler_cb !!!!!!!!!!!!!!!!!!!!");

        proxy_send_reply(proxy_req);

//        timeout.tv_sec = 5;
        timeout.tv_sec = 50;
        timeout.tv_usec = 0;
        
        proxy_req->cleanup = evtimer_new(base, http_connection_free_cb, (void *)proxy_req);
        evtimer_add(proxy_req->cleanup, &timeout);
}

static void close_connection_cb(struct evhttp_connection *evcon, void *arg)
{
        char *address = NULL;
        ev_uint16_t port;

debug_msg("close_connection_cb !!!!!!!!!!!!!!!!!!!!");
        
        if(evcon == NULL) {
                debug_msg("evcon is NULL !!!");
                return;
        }

        evhttp_connection_get_peer(evcon, &address, &port);

        debug_msg("!!! closed connection with peer:");

        if(address)
                debug_msg("\tPEER ADDRESS: \t%s:%d\n", address, port);
}

static void write_chunk_on_conn_cb(struct evhttp_connection *evcon, void *arg)
{
        debug_msg("!!!!!!!!!!!!!!!!!!!!!!!!write_chunk_on_conn_cb WRITING CHUNK!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        debug_msg("!!!!!!!!!!!!!!!!!!!!!!!!write_chunk_on_conn_cb WRITING CHUNK!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        debug_msg("!!!!!!!!!!!!!!!!!!!!!!!!write_chunk_on_conn_cb WRITING CHUNK!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        debug_msg("!!!!!!!!!!!!!!!!!!!!!!!!write_chunk_on_conn_cb WRITING CHUNK!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}

static void http_stream_in_chunk_cb(struct evhttp_request *req, void *arg)
{
debug_msg("http_stream_in_chunk_cb !!!!!!!!!!!!!!!!");
        req_proxy_to_server_t *proxy_req = (req_proxy_to_server_t*)arg;
        
        if(proxy_req == NULL)
                return;

        if(proxy_req->req_client_to_proxy == NULL)
                return;

        if(proxy_req->req_proxy_to_server == NULL)
                return;

        if(proxy_req->req_proxy_to_server->chunked &&
                proxy_req->req_client_to_proxy->chunked) {
debug_msg("2 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! EV_INT64_MAX = %ld", EV_INT64_MAX);
debug_msg("2 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! EV_INT32_MAX = %d", EV_INT32_MAX);
debug_msg("2 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! EV_SSIZE_MAX = %ld", EV_SSIZE_MAX);
debug_msg("2 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! EV_SIZE_MAX = %ld", EV_SIZE_MAX);

debug_msg("\t CHUNK !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ");
print_evbuffer(evhttp_request_get_input_buffer(proxy_req->req_proxy_to_server));
        
//                evhttp_send_reply_chunk(proxy_req->req_client_to_proxy, 
//                        evhttp_request_get_input_buffer(proxy_req->req_proxy_to_server));
                evhttp_send_reply_chunk_with_cb(proxy_req->req_client_to_proxy, 
                        evhttp_request_get_input_buffer(proxy_req->req_proxy_to_server),
                        write_chunk_on_conn_cb, NULL);
        }
}

static int http_stream_in_chunk_start_cb(struct evhttp_request *req, void *arg)
{
debug_msg("http_stream_in_chunk_start_cb !!!!!!!!!!!!!!!!");
        req_proxy_to_server_t *proxy_req = (req_proxy_to_server_t*)arg;
        
        if(proxy_req == NULL)
                return -1;

        if(proxy_req->req_client_to_proxy == NULL)
                return -1;

        if(proxy_req->req_proxy_to_server == NULL)
                return -1;
        
        if(evhttp_find_header(evhttp_request_get_input_headers(proxy_req->req_proxy_to_server),"Transfer-Encoding") != NULL)
        {
debug_msg("http_stream_in_chunk_start_cb !!!!!!!!!!!!!!!! started !!!");
        
                evhttp_request_set_chunked_cb(proxy_req->req_proxy_to_server, http_stream_in_chunk_cb);
                proxy_create_reply(proxy_req);

                evhttp_remove_header(evhttp_request_get_output_headers(proxy_req->req_client_to_proxy),"Transfer-Encoding");

                evhttp_send_reply_start(proxy_req->req_client_to_proxy, 
                                evhttp_request_get_response_code(proxy_req->req_proxy_to_server),
                                evhttp_request_get_response_code_line(proxy_req->req_proxy_to_server));
                return 0;
        }

        return 0;
}

/* 
 * Handles requests to our proxy from listen_addr (from a web-browser) 
 * and deliver them to connect_addr (to an application) 
 */
static void http_request_handler_cb(struct evhttp_request* req_client_to_proxy, void *ctx)
{
        
        extern struct event_base *base;
        extern struct sockaddr_storage connect_to_addr;
        extern http_proxy_core_t *proxy_core;
        struct bufferevent *b_out = NULL;
        char addrbuf[128];
        char host_port[MAX_LENGTH_HOSTNAME];
        const char *host_connect = NULL;
        int port_connect;
        req_proxy_to_server_t *proxy_req;
        int is_cookie_header = cookie_check(req_client_to_proxy);

        if((proxy_req = init_struct_req_proxy_to_server()) == NULL) return;
        
        memset(host_port, '\0', MAX_LENGTH_HOSTNAME);
        memset(addrbuf, '\0', strlen(addrbuf));

if(evhttp_find_header(evhttp_request_get_input_headers(req_client_to_proxy), "Transfer-Encoding")) {
        debug_msg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! input request from browser has Transfer-Encoding-header !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        debug_msg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! input request from browser has Transfer-Encoding-header !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        debug_msg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! input request from browser has Transfer-Encoding-header !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        debug_msg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! input request from browser has Transfer-Encoding-header !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        debug_msg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! input request from browser has Transfer-Encoding-header !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        debug_msg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! input request from browser has Transfer-Encoding-header !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        debug_msg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! input request from browser has Transfer-Encoding-header !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        debug_msg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! input request from browser has Transfer-Encoding-header !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
        debug_msg("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! input request from browser has Transfer-Encoding-header !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
}

        proxy_req->req_client_to_proxy = req_client_to_proxy;
        proxy_req->client_conn = evhttp_request_get_connection(proxy_req->req_client_to_proxy);

        /* Find host and port of connect_to_addr */
        if (((struct sockaddr*)&connect_to_addr)->sa_family == AF_INET) {
                void* inaddr;
                struct sockaddr_in *sin = (struct sockaddr_in *)&connect_to_addr;
                inaddr = &sin->sin_addr;
                port_connect = ntohs(sin->sin_port);
                host_connect = evutil_inet_ntop(sin->sin_family, inaddr,
                                        addrbuf, sizeof(addrbuf));
        }

        else if(((struct sockaddr*)&connect_to_addr)->sa_family == AF_INET6) {
                void* inaddr;
                struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&connect_to_addr;
                inaddr = &sin->sin6_addr;
                port_connect = ntohs(sin->sin6_port);
                host_connect = evutil_inet_ntop(sin->sin6_family, inaddr,
                                        addrbuf, sizeof(addrbuf));
        }

        if(host_connect == NULL) {
                debug_msg("evutil_inet_ntop failed\n");
                http_connection_free(proxy_req);
                return;
        }

        /* create bufferevent for output events to application (connect_to_addr) */
//        b_out = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
        b_out = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
//        b_out = bufferevent_socket_new(base, -1, 0);
        if(!b_out) {
		debug_msg("bufferevent_socket_new() failed\n");
                http_connection_free(proxy_req);
                return ;
        }

	proxy_req->serv_conn = evhttp_connection_base_bufferevent_new(base, NULL, b_out, host_connect, port_connect);
	if (!proxy_req->serv_conn) {
		debug_msg("evhttp_connection_base_bufferevent_new() failed\n");
//                bufferevent_free(b_out);
                http_connection_free(proxy_req);
                return;
	}
// TODO: set timout and retries to bufferevent

//        evhttp_connection_set_timeout(proxy_req->client_conn, 5);
//        evhttp_connection_set_timeout(proxy_req->serv_conn, 5);
        evhttp_connection_set_retries(proxy_req->client_conn, 3);
        evhttp_connection_set_retries(proxy_req->serv_conn, 3);

        /* set callbacks for closing connections */
        evhttp_connection_set_closecb(proxy_req->client_conn, close_connection_cb, proxy_req);
        evhttp_connection_set_closecb(proxy_req->serv_conn, close_connection_cb, proxy_req);

//evhttp_connection_set_max_body_size(proxy_req->client_conn, 100);
//evhttp_connection_set_max_body_size(proxy_req->serv_conn, 1000);

	proxy_req->req_proxy_to_server = evhttp_request_new(http_response_handler_cb, proxy_req);
	if (!proxy_req->req_proxy_to_server) {
		debug_msg("evhttp_request_new() failed\n");
//                bufferevent_free(b_out);
                http_connection_free(proxy_req);
                return;
	}
	
        /* setting a callbacks for various events of server reply */
        evhttp_request_set_header_cb(proxy_req->req_proxy_to_server, http_stream_in_chunk_start_cb);
        evhttp_request_set_error_cb(proxy_req->req_proxy_to_server,  http_request_error_cb);

        if(copy_request_parameters(req_client_to_proxy, input, proxy_req->req_proxy_to_server, output) != 0) {
                debug_msg("Couldn't copy request\n");
//                bufferevent_free(b_out);
                evhttp_request_free(proxy_req->req_proxy_to_server); /* because dont made request to server */
                http_connection_free(proxy_req);
                return;
        }
        
        /* if Cookie-header exist, but EmbeddedSID is absent, remove whole header for send to app. 
         * Will be handle this client as a new */
        if(is_cookie_header == -1) {
                debug_msg("In a Cookie-header not found an EmbeddedSID! Remove the Cookie-header!");
                evhttp_remove_header(evhttp_request_get_output_headers(proxy_req->req_proxy_to_server), "Cookie");
        }
        
        /* check and handle EmbeddedSID, remove it from Cookie-header for send it to app */
        if(is_cookie_header > 0) {
        
                /* parsing the Cookie-header and save to hashmap */
                proxy_req->cookies_tbl = _parse_cookie_header(proxy_req->req_proxy_to_server, output);

                evhttp_remove_header(evhttp_request_get_output_headers(proxy_req->req_proxy_to_server), "Cookie");

                if(proxy_req->cookies_tbl) {

                        const char *all_cookies;
                        if(check_valid_EmbeddedSID(proxy_req) != 0) {
                                debug_msg("SID in a cookie and in a hashtable not match or not exist!");
                                proxy_send_403_reply(req_client_to_proxy);
                        
                                /* deallocate the request 'req_proxy_to_server' because was not done request to server */
                                evhttp_request_free(proxy_req->req_proxy_to_server); 
                                http_connection_free(proxy_req);

                                return;
                        }
                        
                        proxy_req->hasSID = ht_get_value(proxy_req->cookies_tbl, DEFAULT_EMBEDDED_SID_NAME);

                        if((all_cookies = _cookie_get_all_pairs_as_string(proxy_req->cookies_tbl, DEFAULT_EMBEDDED_SID_NAME)) != NULL &&
                                strlen(all_cookies) != 0)
                                evhttp_add_header(evhttp_request_get_output_headers(proxy_req->req_proxy_to_server), "Cookie", all_cookies);
                        else
                                if(proxy_req->cookies_tbl->count_elems > 1)
                                        debug_msg("Couldn't concatenate cookies from table! Cookie-header will not exist in request to server");

                        if(all_cookies)
                                free((void *)all_cookies);
                }
        }
        
        proxy_req->uri = (struct evhttp_uri *)evhttp_request_get_evhttp_uri(req_client_to_proxy);
        
        if(proxy_req->uri) {
                print_parsed_uri(proxy_req->uri);

                char* p_decoded_path = NULL;
                const char* path = evhttp_uri_get_path(proxy_req->uri);
                if(path == NULL)
                        path = "/";
                
                p_decoded_path = evhttp_uridecode(path, 0, NULL);

                if(p_decoded_path == NULL) 
                        debug_msg("uridecode failed");
                
                //.. in url is unfase for us
                if(strstr(p_decoded_path, "..")) {
                        debug_msg("url path constains .. , unsafe");
                        
                        proxy_send_403_reply(req_client_to_proxy);
                        
                        /* deallocate because was not done request to server */
                        evhttp_request_free(proxy_req->req_proxy_to_server); 
                        http_connection_free(proxy_req);
                        free((void*)p_decoded_path);
                        
                        return;
                }
                free((void*)p_decoded_path);
        }

        /* concatenate host and port to one string host:port */
        strncpy(host_port, host_connect, MAX_LENGTH_HOSTNAME);
        strncat(host_port, ":", MAX_LENGTH_HOSTNAME - strlen(host_connect));
        char str_port[6];
        memset(str_port, '\0', 6);
        sprintf(str_port, "%d", port_connect);
        strncat(host_port, str_port, MAX_LENGTH_HOSTNAME - strlen(host_connect) - 1);

        /* change Host-header to an application */
        change_header_value(proxy_req->req_proxy_to_server, output, "Host", host_port); 
       
        /* send new request to an application */
        
        if(evhttp_make_request(proxy_req->serv_conn, proxy_req->req_proxy_to_server, 
                evhttp_request_get_command(req_client_to_proxy), 
                evhttp_request_get_uri(req_client_to_proxy)) != 0) {

                debug_msg("evhttp_make_request() failed\n");
//                bufferevent_free(b_out);
                http_connection_free(proxy_req);
                return;
        }

        debug_msg("Browser->Proxy REQ:\n");
        print_input_req(req_client_to_proxy);
        debug_msg("Proxy->App REQ:\n");
        print_output_req(proxy_req->req_proxy_to_server);
}

http_proxy_core_t *http_core_init(struct evconnlistener *listener)
{
        extern struct event_base *base;
        extern int backlog;
        int timeout = -1;
        const char *json_file = config_get_json_sec_headers_file_name();

        http_proxy_core_t *proxy_core = malloc(sizeof(http_proxy_core_t));

        if(proxy_core == NULL) {
                debug_msg("Couldn't alloc proxy_core!");
                return NULL;
        }

        memset(proxy_core, 0, sizeof(http_proxy_core_t));
        
        proxy_core->json_security_headers = parse_json_file(json_file);
        
        if(proxy_core->json_security_headers == NULL) {
                fprintf(stderr, "Failed parse of file '%s'\n", json_file);
                syslog(LOG_WARNING, "Failed parse of file '%s'\n", json_file);
        }

        proxy_core->http_server = evhttp_new(base);

        if (proxy_core->http_server == NULL) {
                fprintf(stderr, "Couldn't create http server.\n");
                free_proxy_core(proxy_core);
                return NULL;
        }

        evhttp_set_default_content_type(proxy_core->http_server, NULL);

        evhttp_set_gencb(proxy_core->http_server, http_request_handler_cb, NULL);
        evhttp_set_bevcb(proxy_core->http_server, http_accept_cb, proxy_core); // use ssl or not

        config_get_http_server_timeout(&timeout);

        if(timeout > 0)
                evhttp_set_timeout(proxy_core->http_server, timeout);

        proxy_core->evhttp_socket = evhttp_bind_listener(proxy_core->http_server, listener);

        if(proxy_core->evhttp_socket == NULL) {
                fprintf(stderr, "Couldn't bind evhttp.\n");
                free_proxy_core(proxy_core);
                return NULL;
        }

        proxy_core->SIDs = ht_create(backlog);

        if(proxy_core->SIDs == NULL) {
                free_proxy_core(proxy_core);
                return NULL;
        }
        
        return proxy_core;
}

void free_proxy_core(http_proxy_core_t *proxy_core)
{
        if(proxy_core == NULL){
                debug_msg("http_proxy_core is NULL!");
                return;
        }

        if(proxy_core->http_server)
                evhttp_free(proxy_core->http_server);
                
        if(proxy_core->SIDs)
                ht_free(proxy_core->SIDs);
        
        if(proxy_core->json_security_headers)
                cJSON_Delete(proxy_core->json_security_headers);

        free(proxy_core);
}
