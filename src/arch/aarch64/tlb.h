#ifndef __TLB_H
#define __TLB_H

#include "aarch64.h"

#define _tlbi(op,arg) asm volatile(\
	"tlbi " #op ", %0\n"\
	"dsb ish\n"\
	"isb\n"\
	: : "r"(arg)\
	)

#define _tlbi0(op) asm volatile(\
	"tlbi " #op "\n"\
	"dsb ish\n"\
	"isb\n"\
	)

static inline void tlbflush_vaddr(ptr_t vaddr)	{
	_tlbi(vaae1is, vaddr);
}
static inline void tlbflush_asid(ptr_t _asid)	{
	_tlbi(aside1, _asid);
}
// static inline void tlbflush_vaddr_asid(ptr_t vaddr, ptr_t asid)	{
// 	_tlbi(vae1, asid);
// }
static inline void tlbflush(void)	{
	_tlbi0(alle1);
}
static inline void tlbflush_is(void)	{
	_tlbi0(alle1is);
}
static inline void tlbflush_os(void)	{
	_tlbi0(alle1os);
}

#endif
