/*
 * @author f1est 
 */
 
#include "common.h"
#include "transport.h"
#include "utils.h"
#include "ssl.h"
#include "log.h"
#include "config.h"

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

struct http_proxy_core_s *proxy_core = NULL;
struct event_base *base = NULL;

static void syntax(const char* program_name)
{
        fprintf(stderr, "Usage: %s [options]\n", program_name);
        fprintf(stderr, "\n"
                        "Options are:\n"
                        "  -d        Do not daemonize (run in foreground).\n"
                        "  -c FILE   Use an alternate configuration file.\n"
                        "  -h        Display this usage information.\n");

        fputs("\n\n",stderr);
        exit(EX_OK);
}

static void process_cmdline (int argc, char **argv)
{
        int opt;

        const char *config_fname = NULL;
        while ((opt = getopt (argc, argv, "c:dh")) != -1) {
                switch (opt) {
                case 'd':
                        use_daemon = 0;
                        break;

                case 'c':
                        config_fname = strdup(optarg);
                        if (!config_fname) {
                                fprintf (stderr,
                                        "%s: Could not allocate memory for config name.\n",
                                        argv[0]);
                                exit (EX_SOFTWARE);
                        }
                        break;
                case 'h':
                        syntax(argv[0]);
                        exit (EX_OK);

                default:
                        syntax(argv[0]);
                        exit (EX_USAGE);
                }
        }

        if(config_fname) 
                load_config(config_fname); 
        else 
                load_config(DEFAULT_CONFIG_FILE_NAME);
        if(config_fname)
                free((void *)config_fname);

}

int main(int argc, char **argv)
{
        const char *address = NULL;
        int socklen;

        struct evconnlistener *listener;

#ifndef NDEBUG
        printf(" ################### DEBUG \n");
        set_logfile(stderr);
#else
        printf(" ################### NDEBUG \n");
#endif


        
        process_cmdline(argc, argv);
        
        if(use_daemon) 
                daemonize(argv[0]);
                
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

        config_get_listen_address(&address);
        if(address) {
                if (evutil_parse_sockaddr_port(address,(struct sockaddr*)&listen_on_addr, &socklen) < 0) 
                {
                        fprintf(stderr, "Can not parse listen address!!!\n");
                        exit(EXIT_FAILURE);
                }
        }
        address = NULL;
        config_get_connect_address(&address);
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

        if (use_ssl && (init_ssl() != 0)) {
                return 1;
        }
        listener = evconnlistener_new_bind(base, accept_cb, NULL,
            LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
            backlog, (struct sockaddr*)&listen_on_addr, socklen);

        if (!listener) {
                fprintf(stderr, "Couldn't open listener.\n");
                event_base_free(base);
                free_config();
                free_ssl();
                return 1;
        }
        if(use_core_webtoolkit) {
                proxy_core = http_request_init(listener);
                if(proxy_core == NULL) {
                        fprintf(stderr, "Couldn't create http server.\n");
                        evconnlistener_free(listener);
                        event_base_free(base);
                        free_config();
                        free_ssl();
                        return 1;
                }
        }


        event_base_dispatch(base);

EXIT:
        if(use_core_webtoolkit)
                free_proxy_core(proxy_core);
        else if(listener)
                evconnlistener_free(listener);
        
        event_base_free(base);

        free_config();
        free_ssl();
        free_signals();
        closelog();
        fprintf(stderr, "done\n");
        return 0;
}
