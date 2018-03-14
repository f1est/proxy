/*
 * @author f1est 
 */
 
#ifndef UTILS_H
#define UTILS_H

#include "common.h"

void daemonize(const char* program_name);
void set_signals();
void free_signals();

int change_user();

#endif /*UTILS_H*/
