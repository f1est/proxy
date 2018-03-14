/*
 * @author f1est 
 */
 
#ifndef CONFIG_H
#define CONFIG_H

#include <libconfig.h>

#define DEFAULT_CONFIG_FILE_NAME "/etc/proxy/proxy.conf"
#define DEFAULT_PID_FILE_NAME "/var/run/proxy.pid"

void load_config(const char *config_fname);
void free_config();
const char* config_get_pid_file_name();
const char* config_get_listen_address();
const char* config_get_connect_address();
void config_get_backlog(int *backlog);
void config_check_use_ssl(int *use_ssl);
int config_get_UID();
int config_get_GID();
void config_check_core_module(); 
void config_get_http_server_timeout(int*);




#endif /* CONFIG_H */

