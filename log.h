/*
 * @author f1est 
 */
 
#ifndef LOG_H
#define LOG_H
#include "common.h"
#include <syslog.h>

#define syslog(priority, format...) fprintf(stderr, "syslog: " format); \
                                syslog(priority, format);


#ifndef NDEBUG
        #define debug_msg(fmt, args...) do { \
                fprintf(stderr, "%s[%d]->%s(): " fmt "\n", __FILE__, __LINE__, __FUNCTION__, ##args); \
        }while(0)

/* Redirect all Libevent log messages to the C stdio file 'f'. */
void set_logfile(FILE *f);

#else 
        #define debug_msg(fmt, args...) do {} while(0)
#endif


#endif /* LOG_H */
