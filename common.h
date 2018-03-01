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

#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>

//#define _POSIX_C_SOURCE 1

/* Define boolean values */
#ifndef FALSE
# define FALSE 0
# define TRUE (!FALSE)
#endif


#endif /* COMMON_H */
