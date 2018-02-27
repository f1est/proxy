#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "common.h"

#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>


void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,struct sockaddr *a, int slen, void *p);

#endif /* TRANSPORT_H */
