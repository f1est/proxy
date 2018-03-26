/*
 * @author f1est 
 */
 
#ifndef UTILS_H
#define UTILS_H

#include "common.h"

void daemonize(const char* program_name);

/* handling signals */
void set_signals();

/* dealloca */
void free_signals();

/* change user when run on root */
/* Return 0 on success. -1 on failure */
int change_user();


#endif /*UTILS_H*/
