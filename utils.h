#ifndef UTILS_H
#define UTILS_H

#include "common.h"

void general_signal_cb(evutil_socket_t sig, short events, void *user_data);

void change_user();

#endif /*UTILS_H*/
