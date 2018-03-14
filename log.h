/*
 * @author f1est 
 */
 
#ifndef LOG_H
#define LOG_H
#include <syslog.h>

#define syslog(priority, format...) fprintf(stderr, "syslog: " format); \
                                syslog(priority, format);


#ifndef NDEBUG
        #define debug_msg(fmt, args...) do { \
                fprintf(stderr, "%s[%d]-%s: " fmt "\n", __FILE__, __LINE__, __FUNCTION__, ##args); \
        }while(0)
#else 
        #define debug_msg(fmt, args...) do {} while(0)
#endif


#endif /* LOG_H */
