#ifndef LOG_H
#define LOG_H
#include <syslog.h>

#define syslog(priority, format...) fprintf(stderr, "syslog: " format);

#endif /* LOG_H */
