/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sysexits.h>
#include <fcntl.h>
#include <limits.h>     /* ULONG_MAX */

#include <signal.h>
#include <sys/types.h>  /* umask */
#include <sys/stat.h>   /* umask */
#include <ctype.h>      /* isxdigit */

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>
#include <event2/http_struct.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

//#define _POSIX_C_SOURCE 1

#define MAX_OUTPUT (512*1024)
#define MAX_LENGTH_HOSTNAME INET6_ADDRSTRLEN+7 // +7 is ':' + length of port(max 5) + \0

#define EXTRA_RAND_BYTES 60
#define MAX_RANDOM_BYTES_LENGTH 256

#define DEFAULT_EMBEDDED_SID_NAME "EmbeddedSID"
#define MAX_SID_LENGTH EVP_MAX_MD_SIZE+2
#define MAX_LENGTH_OF_COOKIE    4096      /* https://tools.ietf.org/html/rfc6265#section-6.1 */
#define MAX_NUM_OF_COOKIES      100
#define HASH_LENGTH MAX_SID_LENGTH //EVP_MAX_MD_SIZE 
#define HTTP_TIME_FORMAT "Wed, 02 Sep 1981 07:30:00 GMT"
#define EXPIRES_OF_COOKIES 60   /* minutes */

/* for debug*/
#define DEBUG_HASHTABLE

#endif /* COMMON_H */
