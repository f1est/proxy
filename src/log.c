/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#include "log.h"

#ifndef NDEBUG
static FILE *logfile = NULL;
static void write_to_file_cb(int severity, const char *msg)
{
        const char *s;
        if (!logfile)
                return;
        switch (severity) {
                case _EVENT_LOG_DEBUG: s = "debug"; break;
                case _EVENT_LOG_MSG:   s = "msg";   break;
                case _EVENT_LOG_WARN:  s = "warn";  break;
                case _EVENT_LOG_ERR:   s = "error"; break;
                default:               s = "?";     break; /* never reached */
        }
        fprintf(logfile, "[%s] %s\n", s, msg);
}

/* Redirect all Libevent log messages to the C stdio file 'f'. */
void set_logfile(FILE *f)
{
        debug_msg(" set_logfile()");
//        event_enable_debug_logging(EVENT_DBG_ALL);
        logfile = f;
        event_set_log_callback(write_to_file_cb);
}

#endif
