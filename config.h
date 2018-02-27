#ifndef CONFIG_H
#define CONFIG_H

#include <libconfig.h>

#define DEFAULT_CONFIG_FILE_NAME "/etc/proxy/proxy.conf"

void load_config(const char *config_fname);
void free_config();
const char* config_get_listen_address();
const char* config_get_connect_address();
void config_get_backlog(int *backlog);
void config_check_use_ssl(int *use_ssl);
int config_get_UID();
int config_get_GID();





#endif /* CONFIG_H */

