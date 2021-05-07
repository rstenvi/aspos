#ifndef __MACROS_H
#define __MACROS_H

#include <stddef.h>
#include <stdint.h>

#include "types.h"
#include "arch.h"


/*
* Guidelines for shared variables
* - Code should prefer local CPU cache when feasible. This will make it easier
*   for HW to cache data and allows speedier access. The exception (access by
*   other CPU) may then follow appropriate memory barrier instructions to get a
*   fresh variable.
*   - One example of this is collection of statistics, it's better to write
*     stats for each CPU and then combine when needed.
* - If lock is used, normal loads can be used
* - If lock is used for write, but allows concurrent reads, READ_ONCE and
*   WRITE_ONCE should be used
* - Access to thread-variables which are only accessible during that threads
*   interrupt can be accessed using normal loads / stores.
*
* Methods for avoiding a spinlock
* - Gain exclusive access to value by using `atomic_inc_fetchX()`
*   - This can, for instance, be used to get exclusive access to an index
*   - If more maintenance need to be done, the same address could be used as a
*     mutex where the holds the mutex until all operations are finished.
* - 
*/


/*
* Different type of volatile access. These have been taken from "Is Parallel
* Programming Hard, And, If So, What Can You Do About It?"
* 
* All of this provide protection against the compiler doing "weird" thing. These
* do not provide protection against the HW.
*
* (READ|WRITE)_ONCE will prevent the compiler from optimizing the access out.
* barrier() - prevent the compiler from reordering operations
*/
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#define READ_ONCE(x) ({ typeof(x) ___x = ACCESS_ONCE(x); ___x; })
#define WRITE_ONCE(x, val) do { ACCESS_ONCE(x) = (val); } while (0)
#define barrier() __asm__ __volatile__("": : :"memory")


__force_inline static inline void smp_mb(void)	{
	barrier();
	arch_smp_mb();
}
__force_inline static inline void smp_mbr(void)	{
	barrier();
	arch_smp_mbr();
}
__force_inline static inline void smp_mbw(void)	{
	barrier();
	arch_smp_mbw();
}

#define ATOMIC_MOD_MEMORDER __ATOMIC_SEQ_CST

#define ATOMIC_FETCH_INC(size) \
static inline uint##size atomic_inc_fetch##size(uint##size * addr)	{\
	barrier();\
	return __atomic_add_fetch(addr, 1, ATOMIC_MOD_MEMORDER);\
}

ATOMIC_FETCH_INC(8)
ATOMIC_FETCH_INC(16)
ATOMIC_FETCH_INC(32)
ATOMIC_FETCH_INC(64)

#endif
