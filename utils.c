/*
 * @author f1est 
 */
 
#include "utils.h"
#include "config.h"
#include "log.h"
#include "common.h"

static struct event *signal_SIGINT_event = NULL;
static struct event *signal_SIGHUP_event = NULL;
static struct event *signal_SIGPIPE_event = NULL;
static struct event *signal_SIGTERM_event = NULL;
static struct event *signal_SIGCHLD_event = NULL;

/* http://www.enderunix.org/docs/eng/daemon.php */
void daemonize(const char* program_name)
{
        pid_t pid;
        
        /* Fork off the parent process */
        pid = fork();
        
        /* An error occurred */
        if (pid < 0) {
                fprintf(stderr,"error: failed fork\n");
                exit(EXIT_FAILURE);
        }
                
        /* Success: Let the parent terminate */
        if (pid > 0)
                exit(EXIT_SUCCESS);
        
        /* On success: The child process becomes session leader */
        if (setsid() < 0) {
                fprintf(stderr,"error: failed setsid\n");
                exit(EXIT_FAILURE);
        }
        
        /* Fork off for the second time*/
        pid = fork();
        
        /* An error occurred */
        if (pid < 0) {
                fprintf(stderr,"error: failed fork 2\n");
                exit(EXIT_FAILURE);
        }
        
        /* Success: Let the parent terminate */
        if (pid > 0)
                exit(EXIT_SUCCESS);
        
        /* Set new file permissions */
        umask(027);
        
        /* Only allow u+rw bits. This may be required for some versions
         * of glibc so that mkstemp() doesn't make us vulnerable.
         */
//        umask (0177);
        
        /* Change the working directory to the root directory */
        /* or another appropriated directory */
        if (chdir ("/") != 0) {
                fprintf(stderr,"Could not change directory to /");
        }

        
        /* Close all open file descriptors */
        int fd; 
        for (fd = sysconf(_SC_OPEN_MAX); fd >= 0; --fd) {
#ifndef NDEBUG
        if(fd == 2 || fd ==1)
                continue;
#endif
        close(fd);
        }


        int lfp;
        char str[10];
        const char *PID_file_name;
        
        memset(str,0,sizeof(str));
#ifdef HAVE_CONFIG
        PID_file_name = config_get_pid_file_name();
#else
        PID_file_name = DEFAULT_PID_FILE_NAME;
#endif

printf("1  daemonize PID_file_name: %s ~~~~~~~~~~~~~~~~~~~~\n", PID_file_name);
        lfp=open(PID_file_name,O_RDWR|O_CREAT,0640);
        if (lfp < 0) {
                /* can not open */
                fprintf(stderr, "WARNING: Couldn't open pid_file: %s\n",PID_file_name); 
                fprintf(stderr, "WARNING: Perhaps you do not have enough privileges\n"); 
                exit(EXIT_FAILURE);
        }
        if (lockf(lfp,F_TLOCK,0) < 0) { 
                /* can not lock */
                fprintf(stderr, "WARNING: Couldn't lock pid_file: %s\n",PID_file_name); 
                fprintf(stderr, "WARNING: Server already running!\n"); 
                exit(EXIT_FAILURE);
        }
        sprintf(str,"%d\n",getpid());
        write(lfp,str,strlen(str)); /* record pid to lockfile */

#ifdef NDEBUG        
         stdin=fopen("/dev/null","r");   //fd=0
         stdout=fopen("/dev/null","w+");  //fd=1
         stderr=fopen("/dev/null","w+");  //fd=2
#endif
        /* Open the log file */
        openlog(program_name, LOG_PID, LOG_DAEMON);
}

static void general_signal_cb(evutil_socket_t sig, short events, void *user_data)
{
        struct event_base *base = (struct event_base*) user_data;

        syslog(LOG_INFO, "Caught an %d signal; Shutting down.\n", sig);
        event_base_loopexit(base, NULL);
}

/*
 * handling signals
 */
void set_signals()
{
        extern struct event_base *base;
        signal_SIGINT_event = evsignal_new(base, SIGINT, general_signal_cb, (void *)base);
        if (!signal_SIGINT_event || event_add(signal_SIGINT_event, NULL)<0) {
                fprintf(stderr, "Could not create/add a signal event: SIGINT!\n");
                exit(EXIT_FAILURE);
        }
        
        signal_SIGHUP_event = evsignal_new(base, SIGHUP, general_signal_cb, (void *)base);
        if (!signal_SIGHUP_event || event_add(signal_SIGHUP_event, NULL)<0) {
                fprintf(stderr, "Could not create/add a signal event: SIGHUP!\n");
                exit(EXIT_FAILURE);
        }

        signal_SIGPIPE_event = evsignal_new(base, SIGPIPE, general_signal_cb, (void *)base);
        if (!signal_SIGPIPE_event || event_add(signal_SIGPIPE_event, NULL)<0) {
                fprintf(stderr, "Could not create/add a signal event: SIGPIPE!\n");
                exit(EXIT_FAILURE);
        }

        signal_SIGTERM_event = evsignal_new(base, SIGTERM, general_signal_cb, (void *)base);
        if (!signal_SIGTERM_event || event_add(signal_SIGTERM_event, NULL)<0) {
                fprintf(stderr, "Could not create/add a signal event: SIGTERM!\n");
                exit(EXIT_FAILURE);
        }
        signal_SIGCHLD_event = evsignal_new(base, SIGCHLD, general_signal_cb, (void *)base);
        if (!signal_SIGCHLD_event || event_add(signal_SIGCHLD_event, NULL)<0) {
                fprintf(stderr, "Could not create/add a signal event: SIGCHLD!\n");
                exit(EXIT_FAILURE);
        }
}

void free_signals()
{
        if(signal_SIGINT_event)
                event_free(signal_SIGINT_event);
        if(signal_SIGHUP_event)
                event_free(signal_SIGHUP_event);
        if(signal_SIGPIPE_event)
                event_free(signal_SIGPIPE_event);
        if(signal_SIGTERM_event)
                event_free(signal_SIGTERM_event);
}

/* Return 0 on success. -1 on failure */
int change_user()
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

        return 0;
#endif
        return -1;
}
