/*
 * @author f1est 
 */
 

#include "config.h"
#include "common.h"
#include "log.h"

#include <ctype.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

static config_t cfg;
//static config_setting_t *setting = NULL;

extern int use_core_webtoolkit;

void load_config (const char *config_fname)
{
        config_init(&cfg);

        if(!config_read_file(&cfg, config_fname)) {
                fprintf(stderr, "Can not read file '%s'\n", config_fname);
                fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
                        config_error_line(&cfg), config_error_text(&cfg));
                config_destroy(&cfg);
                exit(EXIT_FAILURE);
        }
        debug_msg("The configuration file '%s' was read successfully!\n", config_fname);
}

void free_config() 
{
        config_destroy(&cfg);
}

const char* config_get_pid_file_name()
{
        const char *PID_file_name;
        if(!config_lookup_string(&cfg, "pid_file", &PID_file_name)) {
                syslog(LOG_INFO, "Could not find 'pid_file' setting in configuration file.\n");
                return DEFAULT_PID_FILE_NAME;
        }
        else {        
                syslog(LOG_INFO, "pid_file is '%s' \n",PID_file_name);
                return PID_file_name;
        }
}

void config_get_listen_address(const char **address)
{
        if(!config_lookup_string(&cfg, "listen_address", address)) {
                syslog(LOG_INFO, "Could not find 'listen_address' setting in configuration file.\n");
        }
        else {        
                syslog(LOG_INFO, "listen_address is '%s' \n",*address);
        }
}

void config_get_connect_address(const char **address)
{
        if(!config_lookup_string(&cfg, "connect_address", address)) {
                syslog(LOG_INFO, "Could not find 'connect_address' setting in configuration file.\n");
        }
        else {
                syslog(LOG_INFO, "connect_address is '%s' \n",*address);
        }
}

void config_get_backlog(int *backlog)
{
        if(!config_lookup_int(&cfg, "max_listeners", backlog)) {
                syslog(LOG_INFO, "Could not find 'max_listeners' setting in configuration file.\n");
                return;
        }
        else {
                syslog(LOG_INFO, "max_listeners is '%d' \n",*backlog);
        }
}

void config_check_use_ssl(int *use_ssl)
{
        if(!config_lookup_bool(&cfg, "ssl", use_ssl)) {
//                if(!config_lookup_bool(&cfg, "tls", use_ssl)) {
                        syslog(LOG_INFO, "Could not find 'ssl' setting in configuration file.\n");
                        return;
//                }
        }
        else {
                extern const char *certificate_chain_file;
                extern const char *private_key_file;
                if(!config_lookup_string(&cfg, "ssl_certificate_file", &certificate_chain_file) ||
                        !config_lookup_string(&cfg, "ssl_private_key_file", &private_key_file)) {
                        syslog(LOG_INFO, "TLS/SSL: Could not find 'ssl_certificate_file' or 'ssl_private_key_file' setting in configuration file.\n");
                }
        }
}


/* return -1 on failure, else return ID */
static int config_get_id(const char *setting)
{
        const char *user_group = NULL;
        int id = -1;
        if(!config_lookup_string(&cfg, setting, &user_group)) {
                if(!config_lookup_int(&cfg, setting, &id)) {
                        syslog(LOG_INFO, "Could not find '%s' setting in configuration file.\n", setting);
                        return -1;
                }
        }

        if(user_group) {
        /* проверим не указан ли ID строкой (например user = "1000") */
                const char *str = user_group;
                while (*str != 0) {
                        if (!isdigit (*str))
                                break;
                        str++;
                        if(*str == 0) {
                                id = atoi(user_group);
                                syslog(LOG_INFO, "%s is '%s' \n", setting, user_group);
                                goto EXIT;
                        }
                }
        /* Найдем ID если у нас строка (например user = "anybody") */
                if(id < 0) {
                        if(!strncmp("user", setting, 4)) {

                                struct passwd *thisuser = getpwnam (user_group);

                                if (!thisuser) {
                                        fprintf (stderr,
                                                 "Unable to find user '%s'.\n",
                                                 user_group);
                                        exit (EX_NOUSER);
                                }

                                id = thisuser->pw_uid;
                                syslog(LOG_INFO, "%s is '%s' \n", setting, user_group);
                                goto EXIT;
                        }
                        else if(!strncmp("group", setting, 5)) {

                                struct group *thisgroup = getgrnam (user_group);

                                if (!thisgroup) {
                                        fprintf (stderr,
                                                 "Unable to find group '%s'.\n",
                                                 user_group);
                                        exit (EX_NOUSER);
                                }

                                id = thisgroup->gr_gid;
                                syslog(LOG_INFO, "%s is '%s' \n", setting, user_group);
                                goto EXIT;
                        }
                        else {
                                fprintf(stderr, "Setting '%s' is wrong!\n", setting);
                                return -1;
                        }
                }
        }

EXIT:
        if(id == 0) {
                fprintf(stderr, "'user' or 'group' in config file can't be 0 or 'root'.\n");
                return -1;
        }
        
        return id;
}

int config_get_UID()
{
        return config_get_id("user");
}

int config_get_GID()
{
        return config_get_id("group");
}

void config_check_core_module()
{
        if(!config_lookup_bool(&cfg, "core_module", &use_core_webtoolkit)) {
                use_core_webtoolkit = 0;
        }
}

void config_get_http_server_timeout(int* timeout)
{
        if(!config_lookup_int(&cfg, "http_server_timeout", timeout)) {
                syslog(LOG_INFO, "Could not find 'http_server_timeout' setting in configuration file.\n");
                return;
        }
        else 
                syslog(LOG_INFO, "http_server_timeout is '%d' \n", *timeout);
}

int config_get_max_length_of_cookie()
{
        int length = -1;
        if(!config_lookup_int(&cfg, "max_length_of_cookie", &length)) {
                syslog(LOG_INFO, "Could not find 'max_length_of_cookie' setting in configuration file! max_length_of_cookie will be default = %d\n", MAX_LENGTH_OF_COOKIE);
                return -1;
        }
        return length;
}

int config_get_max_num_of_cookies()
{
        int num = -1;
        if(!config_lookup_int(&cfg, "max_num_of_cookies", &num)) {
                syslog(LOG_INFO, "Could not find 'max_num_of_cookies' setting in configuration file! max_num_of_cookies will be default = %d\n", MAX_NUM_OF_COOKIES);
                return -1;
        }
        return num;
}

int config_get_expires_of_cookie()
{
        int num = -1;
        if(!config_lookup_int(&cfg, "expires_of_cookie", &num)) {
                syslog(LOG_INFO, "Could not find 'expires_of_cookie' setting in configuration file! expires_of_cookie will be default = %d\n", EXPIRES_OF_COOKIES);
                return -1;
        }
        return num;
}
