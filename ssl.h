/*
 * @author f1est 
 */
 
#ifndef TLS_SSL_H
#define TLS_SSL_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

int init_ssl();
void free_ssl();


#endif /* TLS_SSL_H */
