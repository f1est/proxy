/*
 * 	 @author 	 f1est 
 * 	 telegram: 	 @F1estas (https://t.me/F1estas) 
 * 	 e-mail: 	 www-b@mail.ru 
 */
 
#ifndef CONFIG_H
#define CONFIG_H

#include <libconfig.h>

#define DEFAULT_CONFIG_FILE_NAME "/etc/embedded/embeddedproxy.conf"
#define DEFAULT_PID_FILE_NAME "/var/run/embeddedProxy.pid"
#define DEFAULT_SEC_HEADERS_FILE_NAME "/tmp/security_headers.json"

void load_config(const char *config_fname);
void free_config();
const char* config_get_pid_file_name();

void config_get_listen_address(const char **address);
const char* config_get_listen_address_http();
const char* config_get_listen_address_https();

void config_get_connect_address(const char **address);

void config_get_backlog(int *backlog);
void config_check_use_ssl();
int config_get_UID();
int config_get_GID();
void config_check_core_module(); 
void config_get_http_server_timeout(int*);
int config_get_max_length_of_cookie();
int config_get_max_num_of_cookies();
int config_get_expires_of_cookie();
const char* config_get_json_sec_headers_file_name();




#endif /* CONFIG_H */

