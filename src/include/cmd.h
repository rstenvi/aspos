#ifndef __CMD_H
#define __CMD_H

#include "lib.h"

void aerror(int errno, const char* msg);
int cmd_cat(char* arg, int fdo);

#endif
