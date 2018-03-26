/*
 * @author f1est 
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

/* Define boolean values */
#ifndef FALSE
# define FALSE 0
# define TRUE (!FALSE)
#endif

#define DEFAULT_SID_NAME "SID"
#define MAX_SID_LENGTH EVP_MAX_MD_SIZE/2

#endif /* COMMON_H */
