/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#ifndef TLS_SSL_H
#define TLS_SSL_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

int init_ssl();
void free_ssl();


#endif /* TLS_SSL_H */
