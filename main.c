#include "common.h"
#include "transport.h"
#include "utils.h"
#include "ssl.h"
#include "log.h"

#ifdef HAVE_CONFIG
#include "config.h"
#endif

#include <sysexits.h>
#include <signal.h>
#include <sys/types.h>  /* umask */
#include <sys/stat.h>   /* umask */

struct sockaddr_storage listen_on_addr;
struct sockaddr_storage connect_to_addr;
int connect_to_addrlen = 0;
        
const char *certificate_chain_file = NULL;
const char *private_key_file = NULL;

int use_daemon = 1;     /* boolean */
int use_ssl = 0;        /* boolean */
int backlog = -1;

struct event_base *base;

#ifndef HAVE_CONFIG
static char **addresses = NULL;         /* addresses[0] == listen address; addresses[1] == connect address */
#endif

static void syntax(const char* program_name)
{
#ifdef HAVE_CONFIG
        fprintf(stderr, "Usage: %s [options]\n", program_name);
#else        
        fprintf(stderr, "Usage: %s [options] <listen-on-addr> <connect-to-addr>\n", program_name);
#endif
        fprintf(stderr, "\n"
                        "Options are:\n"
                        "  -d        Do not daemonize (run in foreground).\n"
#ifdef HAVE_CONFIG
                        "  -f FILE   Use an alternate configuration file.\n"
#else        
                        "  -s        Use SSL/TLS.\n"
                        "  -c        SSL Certificate chain file.\n"
                        "  -k        SSL Private key file.\n"
                        "  -m        Max count listeners.\n"
#endif
                        "  -h        Display this usage information.\n");

        fputs("\n\n",stderr);
#ifndef HAVE_CONFIG
        fputs("Example:\n", stderr);
        fprintf(stderr,"   %s -d -s -c cert.pem -k key.pem 0.0.0.0:8888 127.0.0.1:8080\n", program_name);
        fprintf(stderr,"   %s -d 0.0.0.0:8888 127.0.0.1:8080\n", program_name);
#endif

        exit(EX_OK);
}

static void process_cmdline (int argc, char **argv)
{
        int opt;

#ifdef HAVE_CONFIG
        const char *config_fname = NULL;
        while ((opt = getopt (argc, argv, "f:dh")) != -1) {
#else        
        int numInputFiles;
        while ((opt = getopt (argc, argv, "dsc:k:m:h")) != -1) {
#endif
                switch (opt) {
                case 'd':
                        use_daemon = 0;
                        break;

#ifdef HAVE_CONFIG
                case 'f':
                        config_fname = strdup(optarg);
                        if (!config_fname) {
                                fprintf (stderr,
                                        "%s: Could not allocate memory for config name.\n",
                                        argv[0]);
                                exit (EX_SOFTWARE);
                        }
                        break;
#else        
                case 's':
                        use_ssl = 1;
                        break;
                case 'c':
                        certificate_chain_file = strdup(optarg);
                        if (!certificate_chain_file) {
                                fprintf (stderr,
                                        "%s: Could not allocate memory for certificate_chain_file.\n",
                                        argv[0]);
                                exit (EX_SOFTWARE);
                        }
                        break;
                case 'k':
                        private_key_file = strdup(optarg);
                        if (!private_key_file) {
                                fprintf (stderr,
                                        "%s: Could not allocate memory for private_key_file.\n",
                                        argv[0]);
                                exit (EX_SOFTWARE);
                        }
                        break;
                case 'm':
                        backlog = atoi(optarg);
                        break;
#endif

                case 'h':
                        syntax(argv[0]);
                        exit (EX_OK);

                default:
                        syntax(argv[0]);
                        exit (EX_USAGE);
                }
        }

#ifdef HAVE_CONFIG
        if(config_fname) 
                load_config(config_fname); 
        else 
                load_config(DEFAULT_CONFIG_FILE_NAME); 
#else        
        numInputFiles = argc - optind;
        if(numInputFiles != 2)
                syntax(argv[0]);
        addresses = argv + optind;
#endif
}

int main(int argc, char **argv)
{

#ifdef HAVE_CONFIG
        const char * address = NULL;
#endif
        int socklen;

        struct evconnlistener *listener;
        struct event *signal_SIGINT_event;
        struct event *signal_SIGHUP_event;
        struct event *signal_SIGPIPE_event;
        struct event *signal_SIGTERM_event;
        
        /* Only allow u+rw bits. This may be required for some versions
         * of glibc so that mkstemp() doesn't make us vulnerable.
         */
        umask (0177);
        
        process_cmdline(argc, argv);
        if(use_daemon) {
                if(daemon(1,1) < 0 ){
                        fprintf (stderr,
                                 "start daemon error: %s\n", strerror (errno));
                        exit (EX_OSERR);
                }
        }
                

        socklen = sizeof(listen_on_addr);
        connect_to_addrlen = sizeof(connect_to_addr);
        memset(&listen_on_addr, 0, socklen);
        memset(&connect_to_addr, 0, connect_to_addrlen);

#ifdef HAVE_CONFIG
        address = config_get_listen_address();
        if(address) {
                if (evutil_parse_sockaddr_port(address,(struct sockaddr*)&listen_on_addr, &socklen) < 0) 
                {
                        fprintf(stderr, "Can not parse listen address!!!\n");
                        exit(EXIT_FAILURE);
                }
        }
        address = NULL;
        address = config_get_connect_address();
        if(address) {
                if (evutil_parse_sockaddr_port(address,(struct sockaddr*)&connect_to_addr, &connect_to_addrlen) < 0)
                {
                        fprintf(stderr, "Can not parse connect address!!!\n");
                        exit(EXIT_FAILURE);
                }
        }

        config_get_backlog(&backlog);
        config_check_use_ssl(&use_ssl);

#else
        if (evutil_parse_sockaddr_port(addresses[0],(struct sockaddr*)&listen_on_addr, &socklen) < 0) 
                syntax(argv[0]);
        if (evutil_parse_sockaddr_port(addresses[1],(struct sockaddr*)&connect_to_addr, &connect_to_addrlen) < 0)
                syntax(argv[0]);
#endif
/*
        if (use_ssl) {
                if (!certificate_chain_file || !private_key_file) {
                        fputs("Should specify certificate_chain_file and private_key_file when in SSL/TLS mode.\n", stderr);
                        return 1;
                }
        }
*/
        base = event_base_new();
        if (!base) {
                perror("event_base_new()");
                return 1;
        }
#ifndef NDEBUG
        fprintf(stderr, "default method: %s\n", event_base_get_method(base));
#endif

        if (use_ssl && (init_ssl() != 0)) {
                return 1;
        }
        listener = evconnlistener_new_bind(base, accept_cb, NULL,
            LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
            backlog, (struct sockaddr*)&listen_on_addr, socklen);

        if (! listener) {
                fprintf(stderr, "Couldn't open listener.\n");
                event_base_free(base);
                return 1;
        }

/* 
 * handling signals
 */
        signal_SIGINT_event = evsignal_new(base, SIGINT, general_signal_cb, (void *)base);
        if (!signal_SIGINT_event || event_add(signal_SIGINT_event, NULL)<0) {
                fprintf(stderr, "Could not create/add a signal event: SIGINT!\n");
                return 1;
        }
        
        signal_SIGHUP_event = evsignal_new(base, SIGHUP, general_signal_cb, (void *)base);
        if (!signal_SIGHUP_event || event_add(signal_SIGHUP_event, NULL)<0) {
                fprintf(stderr, "Could not create/add a signal event: SIGHUP!\n");
                return 1;
        }

        signal_SIGPIPE_event = evsignal_new(base, SIGPIPE, general_signal_cb, (void *)base);
        if (!signal_SIGPIPE_event || event_add(signal_SIGPIPE_event, NULL)<0) {
                fprintf(stderr, "Could not create/add a signal event: SIGPIPE!\n");
                return 1;
        }

        signal_SIGTERM_event = evsignal_new(base, SIGTERM, general_signal_cb, (void *)base);
        if (!signal_SIGTERM_event || event_add(signal_SIGTERM_event, NULL)<0) {
                fprintf(stderr, "Could not create/add a signal event: SIGTERM!\n");
                return 1;
        }


        /* Switch to a different user if we're running as root */
        if (geteuid () == 0)
                change_user();
        else
                syslog(LOG_WARNING,
                             "Not running as root, so not changing UID/GID. \n");

        event_base_dispatch(base);


        evconnlistener_free(listener);
        event_free(signal_SIGINT_event);
        event_free(signal_SIGHUP_event);
        event_free(signal_SIGPIPE_event);
        event_free(signal_SIGTERM_event);
        
        event_base_free(base);

#ifdef HAVE_CONFIG
        free_config();
#endif
        free_ssl();
        fprintf(stderr, "done\n");
        return 0;
}
