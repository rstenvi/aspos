#ifndef __UBSAN_H
#define __UBSAN_H

#include "lib.h"


#define F_UBSAN_MAGIC ('u')
#define FCNTL_UBSAN_ALL_TESTS  FCNTL_ID(1, F_UBSAN_MAGIC)
#define FCNTL_UBSAN_DIV_ZERO   FCNTL_ID(2, F_UBSAN_MAGIC)

#endif
