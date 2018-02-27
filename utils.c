#include "utils.h"
#include "config.h"
#include "log.h"

#include <signal.h>

void general_signal_cb(evutil_socket_t sig, short events, void *user_data)
{
        struct event_base *base = (struct event_base*) user_data;

//        struct timeval delay = { 2, 0 };
        char signame[8];
        memset(signame,0,sizeof(signame));
        switch(sig){
                case SIGHUP:    strncpy(signame, "SIGHUP", sizeof(signame));  break;
                case SIGINT:    strncpy(signame, "SIGINT", sizeof(signame));  break;
                case SIGPIPE:   strncpy(signame, "SIGPIPE", sizeof(signame));  break;
                case SIGTERM:   strncpy(signame, "SIGTERM", sizeof(signame));  break; 
                default:        strncpy(signame, "UNKNOWN", sizeof(signame));  break;
        }
        syslog(LOG_INFO, "Caught an %s signal; Shutting down.\n", signame);
        event_base_loopexit(base, NULL);
//        event_base_loopexit(base, &delay);
}

void change_user()
{
#ifdef HAVE_CONFIG        
        int gid = config_get_GID();
        int uid = config_get_UID();
        if (setgid (gid) < 0) {
                fprintf (stderr,
                        "Unable to change to group '%d'.\n", gid);
                exit (EX_NOPERM);
        }

#ifdef HAVE_SETGROUPS
        /* Drop all supplementary groups, otherwise these are inherited from the calling process */
        if (setgroups (0, NULL) < 0) {
                fprintf (stderr,
                        "Unable to drop supplementary groups.\n");
                exit (EX_NOPERM);
        }
#endif

        syslog(LOG_INFO, "Now running as group '%d'.\n", gid);
        
        if (setuid (uid) < 0) {
                fprintf (stderr,
                        "Unable to change to user '%d'.\n", uid);
                exit (EX_NOPERM);
        }

        syslog(LOG_INFO, "Now running as user '%d'.\n", uid);
#endif
}
