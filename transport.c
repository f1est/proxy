/*
 * @author f1est 
 */
 
#include "transport.h"


#define MAX_OUTPUT (512*1024)


static void drained_writecb(struct bufferevent *bev, void *ctx);
static void eventcb(struct bufferevent *bev, short what, void *ctx);

static void readcb(struct bufferevent *bev, void *ctx)
{
        struct bufferevent *partner = ctx;
        struct evbuffer *src, *dst;
        size_t len;
        if (!partner) 
                return;

        src = bufferevent_get_input(bev);
        len = evbuffer_get_length(src);

#if !defined(NDEBUG) && !defined(CLANG_SANITIZER)
        char *data_src = NULL;
        if(len > 0) {
                data_src = malloc(len);
                evbuffer_copyout(src, data_src, len);
                fprintf(stderr,"!!! BUFFER SRC: len: %d data:\n %s\n", (int)len, data_src);
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

                fprintf(stderr,"!!! BUFFER DST: len: %d data:\n %s\n", (int)len_dst, data_dst);
        }
#endif

        if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
#ifndef NDEBUG
        fprintf(stderr,"WARNING!!! Destination buffer > MAX_OUTPUT(%d) STOP READING !!!\n", MAX_OUTPUT);
#endif
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
#ifndef NDEBUG
        fprintf(stderr,"RESTORE READING !!!\n");
#endif
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

void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,struct sockaddr *a, int slen, void *p)
{
        struct bufferevent *b_out = NULL;
        struct bufferevent *b_in = NULL;
        extern SSL_CTX *ssl_ctx;
        extern struct sockaddr_storage connect_to_addr;
        extern int connect_to_addrlen;
        extern int use_ssl;
        extern struct event_base *base;

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
                b_out = b_in = NULL;
                return;
        }

        bufferevent_setcb(b_in, readcb, NULL, eventcb, b_out);
        bufferevent_setcb(b_out, readcb, NULL, eventcb, b_in);

        bufferevent_enable(b_in, EV_READ|EV_WRITE);
        bufferevent_enable(b_out, EV_READ|EV_WRITE);
}

