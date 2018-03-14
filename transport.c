/*
 * @author f1est 
 */
 
#include "transport.h"
#include "log.h"
#include "http_handler.h"
#include "config.h"


#define MAX_OUTPUT (512*1024)
#define MAX_LENGTH_HOSTNAME INET6_ADDRSTRLEN+7 // +7 is ':' + length of port(max 5) + \0

/*      
struct http_proxy_connect {
        const char *host_connect;
        int port_connect;
        // server 
        struct evhttp_bound_socket *evhttp_socket;
        struct evhttp *http_server;
        struct bufferevent *b_in;

        // client 
        struct bufferevent *b_out;
        struct evhttp_connection *evcon_out;
        struct evhttp_request *req;
};
*/

static void drained_writecb(struct bufferevent *bev, void *ctx);
static void eventcb(struct bufferevent *bev, short what, void *ctx);

static void readcb(struct bufferevent *bev, void *ctx)
{
        struct bufferevent *partner = ctx;
        struct evbuffer *src, *dst;
        size_t len;
        extern int use_core_webtoolkit;
        if (!partner) 
                return;

        src = bufferevent_get_input(bev);
        len = evbuffer_get_length(src);

#if !defined(NDEBUG) && !defined(CLANG_SANITIZER)
        char *data_src = NULL;
        if(len > 0) {
                data_src = malloc(len);
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
                data_dst = malloc(len_dst);
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
        struct evconnlistener *listener = ctx;

        if (use_ssl) {
                SSL *ssl = SSL_new(ssl_ctx);
                b_in = bufferevent_openssl_socket_new(base, evconnlistener_get_fd(listener), ssl, BUFFEREVENT_SSL_ACCEPTING,
//                b_in = bufferevent_openssl_socket_new(base, -1, ssl, BUFFEREVENT_SSL_ACCEPTING,
                    BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
        } else {
                b_in = bufferevent_socket_new(base, evconnlistener_get_fd(listener), BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
//                b_in = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
        }
        return b_in;
}

/* 
 * Handles responses to our proxy from connect_addr (from an application)
 * and deliver them to listen_addr (to a web-browser)
 * Here 'req' is request to connect_addr.
 */
static void http_response_handler_cb(struct evhttp_request* req, void *ctx)
{
        struct evhttp_request *old_req = (struct evhttp_request *)ctx;
        struct evbuffer * buffer_body = evbuffer_new();
        if(!buffer_body) {
                debug_msg("evbuffer_new failed\n");
                return;
        }

        if(!req) {
                debug_msg("ERROR!!! Request to connect_addr is NULL!!!\n");
                debug_msg("ERROR!!! TODO: HANDLE THIS ERROR!!!\n");
                return;
        }

debug_msg("App->Proxy RESP http_response_handler_cb !!!!!!!!!!!!! ");
/*
	fprintf(stderr, "Response line: %d %s\n",
	    evhttp_request_get_response_code(req),
	    evhttp_request_get_response_code_line(req));

//        if(evbuffer_add(buffer_body, evhttp_request_get_input_buffer(req), 
//                evbuffer_get_length(evhttp_request_get_input_buffer(req))) != 0) {

//        if(evbuffer_add_reference(buffer_body, evhttp_request_get_input_buffer(req),
//                evbuffer_get_length(evhttp_request_get_input_buffer(req)),
//                NULL, NULL) != 0) {
        if(evbuffer_add_buffer_reference(buffer_body, 
                evhttp_request_get_input_buffer(req)) != 0) {
                debug_msg("Couldn't copy buffer_body \n");
                evbuffer_free(buffer_body);
                return;
        }
printf("RESPONSE buffer: \n");
print_evbuffer(evhttp_request_get_input_buffer(req));
printf("@@@ size buffer_body: %zu\n", evbuffer_get_length(buffer_body));
printf("buffer_body: \n");
print_evbuffer(evhttp_request_get_input_buffer(req));
*/
        struct evkeyvalq *proxy_headers_output_reply = NULL;
        proxy_headers_output_reply = evhttp_request_get_output_headers(old_req);
        copy_request_only_headers(proxy_headers_output_reply, evhttp_request_get_input_headers(req));

        const char *value = evhttp_find_header(proxy_headers_output_reply,"Transfer-Encoding");
        if(value && evutil_ascii_strcasecmp(value, "chunked") == 0)
        {
debug_msg("TODO: Correctly process send chunked reply!!!\n");
                evhttp_send_reply_start(old_req, 
                                evhttp_request_get_response_code(req),
                                evhttp_request_get_response_code_line(req));
                evhttp_send_reply_chunk(old_req,
                                evhttp_request_get_input_buffer(req));
                evhttp_send_reply_end(old_req);
        }
        else
                evhttp_send_reply(old_req, evhttp_request_get_response_code(req),
                                evhttp_request_get_response_code_line(req),
                                evhttp_request_get_input_buffer(req));
//                              buffer_body);
        
        printf("2 REQ:\n");
        print_input_req(req);
        printf("\n2 OLD REQ:\n");
        print_output_req(old_req);
        printf("\n2 OLD REQ input:\n");
        print_input_req(old_req);
       
       if(buffer_body)
               evbuffer_free(buffer_body);
//        bufferevent_free(evhttp_connection_get_bufferevent(evhttp_request_get_connection(req)));
//        evhttp_connection_free(evhttp_request_get_connection(req));
//        evhttp_request_free(req);
}

/* 
 * Handles requests to our proxy from listen_addr (from a web-browser) 
 * and deliver them to connect_addr (to an application) 
 */
static void http_request_handler_cb(struct evhttp_request* req, void *ctx)
{
fprintf(stderr, "http_request_handler_cb!!!\n");
        
        extern struct event_base *base;
        extern struct sockaddr_storage connect_to_addr;
        struct bufferevent *b_out = NULL;
        struct evhttp_connection *evcon_out = NULL;
        struct evhttp_request *new_req;
        char host_port[MAX_LENGTH_HOSTNAME];
        const char *host_connect;
        int port_connect;
        
        memset(host_port, '\0', MAX_LENGTH_HOSTNAME);

/* найдем хост и порт connect_to_addr */
        if (((struct sockaddr*)&connect_to_addr)->sa_family == AF_INET) {
                char addrbuf[128];
                void* inaddr;
                struct sockaddr_in *sin = (struct sockaddr_in *)&connect_to_addr;
                inaddr = &sin->sin_addr;
                port_connect = ntohs(sin->sin_port);
                host_connect = evutil_inet_ntop(sin->sin_family, inaddr,
                                        addrbuf, sizeof(addrbuf));
        }
        else if(((struct sockaddr*)&connect_to_addr)->sa_family == AF_INET6) {
                char addrbuf[128];
                void* inaddr;
                struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&connect_to_addr;
                inaddr = &sin->sin6_addr;
                port_connect = ntohs(sin->sin6_port);
                host_connect = evutil_inet_ntop(sin->sin6_family, inaddr,
                                        addrbuf, sizeof(addrbuf));
        }
        if(!host_connect) {
                debug_msg("evutil_inet_ntop failed\n");
                return;
        }

/* создадим bufferevent для исходящих событий к приложению (connect_to_addr) */
        b_out = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
        if(!b_out) {
		debug_msg("bufferevent_socket_new() failed\n");
                return ;
        }

	evcon_out = evhttp_connection_base_bufferevent_new(base, NULL, b_out, host_connect, port_connect);
	if (!evcon_out) {
		debug_msg("evhttp_connection_base_bufferevent_new() failed\n");
                bufferevent_free(b_out);
                return;
	}
// TODO: set timout and retries to bufferevent

	new_req = evhttp_request_new(http_response_handler_cb, req);
	if (!new_req) {
		debug_msg("evhttp_request_new() failed\n");
                bufferevent_free(b_out);
                evhttp_connection_free(evcon_out);
                return;
	}
        if(copy_request_parameters(req, input, new_req, output) != 0) {
                debug_msg("Couldn't copy request\n");
                bufferevent_free(b_out);
                evhttp_connection_free(evcon_out);
                evhttp_request_free(new_req);
                return;
        }

        strncpy(host_port, host_connect, MAX_LENGTH_HOSTNAME);
        strncat(host_port, ":", MAX_LENGTH_HOSTNAME - strlen(host_connect));
        char str_port[6];
        memset(str_port, '\0', 6);
        sprintf(str_port, "%d", port_connect);
        strncat(host_port, str_port, MAX_LENGTH_HOSTNAME - strlen(host_connect) - 1);
        change_header_value(new_req, output, "Host", host_port); 
       
        if(evhttp_make_request(evcon_out, new_req, evhttp_request_get_command(req), evhttp_request_get_uri(req)) != 0) {
                debug_msg("evhttp_make_request() failed\n");
                bufferevent_free(b_out);
                evhttp_connection_free(evcon_out);
                evhttp_request_free(new_req);
                return;
        }

        printf("OLD REQ:\n");
        print_input_req(req);
        printf("\nNEW REQ:\n");
        print_output_req(new_req);
}


int http_request_init(struct evconnlistener *listener)
{
        extern struct event_base *base;
        struct evhttp *http_server;
        struct evhttp_bound_socket *evhttp_socket;
        int timeout = -1;
        
        http_server = evhttp_new(base);

        if (!http_server) {
                fprintf(stderr, "Couldn't create http server.\n");
                return -1;
        }

        evhttp_set_gencb(http_server, http_request_handler_cb, NULL);
        evhttp_set_bevcb(http_server, http_accept_cb, listener); // use ssl or not
#ifdef HAVE_CONFIG
        config_get_http_server_timeout(&timeout);
#endif
        if(timeout > 0)
                evhttp_set_timeout(http_server, timeout);
        evhttp_socket = evhttp_bind_listener(http_server, listener);
        if(!evhttp_socket) {
                fprintf(stderr, "Couldn't bind evhttp.\n");
                evhttp_free(http_server);
                return -1;
        }

/*
        int rv = evhttp_bind_socket(http_server,
                                "172.17.10.31",
                                            8888);
        if(rv < 0) {
                printf("evhttp_bind_socket failed!\n");
                return -1;
        }
*/

        return 0;
}
