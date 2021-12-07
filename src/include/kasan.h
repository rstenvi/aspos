#ifndef __KASAN_H
#define __KASAN_H

#include "lib.h"

#if defined(UMODE)
/*
* Currently not working in user-mode becuse we need to allocate quarantine buffer.
*/
#define KASAN_FREE_QUARANTINE 0
#else
#define KASAN_FREE_QUARANTINE 1
#endif

#define KASAN_QUARANTINE_MAX (16)

#define SHADOW_BYTES_PER (8)

#define KASAN_REDZONE_BEFORE (16)
#define KASAN_REDZONE_AFTER  (16)

#define F_KASAN_MAGIC ('u')
#define FCNTL_KASAN_ALL_TESTS  FCNTL_ID(0x10, F_KASAN_MAGIC)

void kasan_init(void);
void kasan_mark_valid(ptr_t addr, ptr_t len);
int kasan_alloc_size(void* addr);
void kasan_mmap(void* addr, size_t size);
void kasan_munmap(void* addr);
void kasan_print_allocated(void);

#endif
