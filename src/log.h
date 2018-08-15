/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#ifndef LOG_H
#define LOG_H
#include "common.h"
#include <syslog.h>

#define syslog(priority, format...) do { \
                                fprintf(stderr, "syslog: " format); \
                                syslog(priority, format);  \
                                } while(0)


#ifndef NDEBUG
        #define debug_msg(fmt, args...) do { \
                fprintf(stderr, "%s[%d]->%s(): " fmt "\n", __FILE__, __LINE__, __FUNCTION__, ##args); \
        } while(0)

/* Redirect all Libevent log messages to the C stdio file 'f'. */
void set_logfile(FILE *f);

#else 
        #define debug_msg(fmt, args...) do {} while(0)
#endif


#endif /* LOG_H */
