#ifndef __KASAN_H
#define __KASAN_H

#include "lib.h"

#define KASAN_FREE_QUARANTINE 1
#define KASAN_QUARANTINE_MAX (16)

#define SHADOW_BYTES_PER (8)

#define KASAN_REDZONE_BEFORE (16)
#define KASAN_REDZONE_AFTER  (16)

#define F_KASAN_MAGIC ('u')
#define FCNTL_KASAN_ALL_TESTS  FCNTL_ID(0x10, F_KASAN_MAGIC)

int kasan_alloc_size(void* addr);

#endif
