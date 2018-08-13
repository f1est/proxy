/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#include "common.h"
#include "transport.h"
#include "utils.h"
#include "ssl.h"
#include "log.h"
#include "config.h"

#include <sysexits.h>

struct sockaddr_storage connect_to_addr;
int connect_to_addrlen = 0;
        
const char *certificate_chain_file = NULL;
const char *private_key_file = NULL;

int use_daemon = 1;     /* boolean */
int use_ssl = 0;        /* boolean */
int use_core_webtoolkit = 0;        /* boolean */
int backlog = -1;

http_proxy_core_t *proxy_core = NULL;
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
        const char *listen_http_address = NULL;
        const char *listen_https_address = NULL;
        const char *connect_address = NULL;
        struct sockaddr_storage listen_on_http_addr;
        struct sockaddr_storage listen_on_https_addr;
        int socklen;

        struct evconnlistener *main_listener; // HTTPS if listen in two sockets (HTTP and HTTPS)
        struct evconnlistener *second_listener; // HTTP if listen in two sockets (HTTP and HTTPS)
        
        fprintf(stderr, "Libevent version: %s \n" , event_get_version());
#ifndef NDEBUG
        fprintf(stderr," ################### DEBUG \n");
        set_logfile(stderr);
#else
        fprintf(stderr," ################### NDEBUG \n");
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

        socklen = sizeof(listen_on_http_addr);
        connect_to_addrlen = sizeof(connect_to_addr);
        memset(&listen_on_http_addr, 0, socklen);
        memset(&connect_to_addr, 0, connect_to_addrlen);

        listen_http_address = config_get_listen_address_http();
        listen_https_address = config_get_listen_address_https();


        if(listen_http_address) {
                if (evutil_parse_sockaddr_port(listen_http_address,(struct sockaddr*)&listen_on_http_addr, &socklen) < 0) 
                {
                        fprintf(stderr, "Can not parse listen HTTP address!!!\n");
                        exit(EXIT_FAILURE);
                }
        }
        
        if(listen_https_address) {
                if (evutil_parse_sockaddr_port(listen_https_address,(struct sockaddr*)&listen_on_https_addr, &socklen) < 0) 
                {
                        fprintf(stderr, "Can not parse listen HTTPS address!!!\n");
                        exit(EXIT_FAILURE);
                }
                else {
                        use_ssl = 1;
                        config_check_use_ssl();
                }
        }

        config_get_connect_address(&connect_address);
        if(connect_address) {
                if (evutil_parse_sockaddr_port(connect_address,(struct sockaddr*)&connect_to_addr, &connect_to_addrlen) < 0)
                {
                        fprintf(stderr, "Can not parse connect address!!!\n");
                        exit(EXIT_FAILURE);
                }
        }

        config_get_backlog(&backlog);
        config_check_core_module();

        if (use_ssl && (init_ssl() != 0)) {
                return 1;
        }
        
        if(use_ssl) {
                main_listener = evconnlistener_new_bind(base, accept_cb, &use_ssl,
                        LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
                        backlog, (struct sockaddr*)&listen_on_https_addr, socklen);

                second_listener = evconnlistener_new_bind(base, accept_cb, NULL,
                        LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
                        backlog, (struct sockaddr*)&listen_on_http_addr, socklen);
        }
        else {
                main_listener = evconnlistener_new_bind(base, accept_cb, NULL,
                        LEV_OPT_CLOSE_ON_FREE|LEV_OPT_CLOSE_ON_EXEC|LEV_OPT_REUSEABLE,
                        backlog, (struct sockaddr*)&listen_on_http_addr, socklen);

                second_listener = NULL;
        }

        if (!main_listener) { 
                fprintf(stderr, "Couldn't open listener.\n");
                goto EXIT;
        }

        if(use_core_webtoolkit) {
                proxy_core = http_core_init(main_listener, second_listener, listen_https_address);
                if(proxy_core == NULL) {
                        fprintf(stderr, "Couldn't create http server.\n");
                        evconnlistener_free(main_listener);
                        goto EXIT;
                }
        }

        event_base_dispatch(base);

EXIT:
        if(use_core_webtoolkit)
                free_proxy_core(proxy_core);
        else {
                if(main_listener)
                        evconnlistener_free(main_listener);
                if(second_listener)
                        evconnlistener_free(second_listener);
        }

        event_base_free(base);

        free_config();
        free_ssl();
        free_signals();
        closelog();
        fprintf(stderr, "done\n");
        return 0;
}
