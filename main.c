/*
 * @author f1est 
 */
 
#include "common.h"
#include "transport.h"
#include "utils.h"
#include "ssl.h"
#include "log.h"

#ifdef HAVE_CONFIG
#include "config.h"
#endif

#include <sysexits.h>

struct sockaddr_storage listen_on_addr;
struct sockaddr_storage connect_to_addr;
int connect_to_addrlen = 0;
        
const char *certificate_chain_file = NULL;
const char *private_key_file = NULL;

int use_daemon = 1;     /* boolean */
int use_ssl = 0;        /* boolean */
int use_core_webtoolkit = 0;        /* boolean */
int backlog = -1;

struct event_base *base = NULL;

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
                        "  -c FILE   Use an alternate configuration file.\n"
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
        while ((opt = getopt (argc, argv, "c:dh")) != -1) {
#else        
        int numInputFiles;
        while ((opt = getopt (argc, argv, "dsc:k:m:h")) != -1) {
#endif
                switch (opt) {
                case 'd':
                        use_daemon = 0;
                        break;

#ifdef HAVE_CONFIG
                case 'c':
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

#ifndef NDEBUG
        printf(" ################### DEBUG \n");
#else
        printf(" ################### NDEBUG \n");
#endif

        
        process_cmdline(argc, argv);
        
        if(use_daemon) {
                daemonize(argv[0]);
/*
                if(daemon(0,0) < 0 ){
                        fprintf (stderr,
                                 "start daemon error: %s\n", strerror (errno));
                        exit (EXIT_FAILURE);
                }
*/
        }
                
        base = event_base_new();
        if (!base) {
                perror("event_base_new()");
                return 1;
        }
        set_signals();

        debug_msg("default method: %s\n", event_base_get_method(base));

        /* Switch to a different user if we're running as root */
        if (geteuid () == 0) {
                syslog(LOG_WARNING,
                             "You try running as root, so need changing UID/GID. "
                             "I try get settings from config file\n");
                if(change_user() !=0) {
                        syslog(LOG_INFO, "Couldn't change UID/GID. Exit\n");
                        goto EXIT;
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
        config_check_core_module();

#else
        if (evutil_parse_sockaddr_port(addresses[0],(struct sockaddr*)&listen_on_addr, &socklen) < 0) 
                syntax(argv[0]);
        if (evutil_parse_sockaddr_port(addresses[1],(struct sockaddr*)&connect_to_addr, &connect_to_addrlen) < 0)
                syntax(argv[0]);
#endif
        if (use_ssl && (init_ssl() != 0)) {
                return 1;
        }
        listener = evconnlistener_new_bind(base, accept_cb, NULL,
            LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
            backlog, (struct sockaddr*)&listen_on_addr, socklen);

        if (!listener) {
                fprintf(stderr, "Couldn't open listener.\n");
                event_base_free(base);
#ifdef HAVE_CONFIG
                free_config();
#endif
                free_ssl();
                return 1;
        }
        if(use_core_webtoolkit) {
                if(http_request_init(listener) != 0) {
                        fprintf(stderr, "Couldn't create http server.\n");
                        evconnlistener_free(listener);
                        event_base_free(base);
#ifdef HAVE_CONFIG
                        free_config();
#endif
                        free_ssl();
                        return 1;
                }
        }


        event_base_dispatch(base);

EXIT:
        if(listener)
                evconnlistener_free(listener);
        
        event_base_free(base);

#ifdef HAVE_CONFIG
        free_config();
#endif
        free_ssl();
        free_signals();
        closelog();
        fprintf(stderr, "done\n");
        return 0;
}
