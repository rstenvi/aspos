#include "arch.h"
#include "kernel.h"

// see p 2325 in manual
#define SPSR_M_SPSEL_EL0 (0b0)
#define SPSR_M_SPSEL_ELx (0b1)

#define SPSR_M_STATE_EL0 (0b00 << 2)
#define SPSR_M_STATE_EL1 (0b01 << 2)
#define SPSR_M_STATE_EL2 (0b10 << 2)
#define SPSR_M_STATE_EL3 (0b11 << 2)

#define SPSR_M_AARCH32 (0b1 << 4)
#define SPSR_M_AARCH64 (0b0 << 4)
#define SPSR_MASK_DEBUG  (0b1 << 9)
#define SPSR_MASK_SERROR (0b1 << 8)
#define SPSR_MASK_IRQ    (0b1 << 7)
#define SPSR_MASK_FIQ    (0b1 << 6)


void arch_dump_regs(void)	{
	kwrite("Aarch64 register dump\n");
}


ptr_t arch_prepare_thread_stack(void* stacktop, ptr_t entry, ptr_t ustack, bool user)	{
	// Stack pointer must always be aligned on 16 bytes
	ptr_t nstack = (ptr_t)(stacktop) - sizeof(struct exception);
	ALIGN_DOWN_POW2(nstack, 16);

	struct exception* e = (struct exception*)nstack;

	// Zero out 
	memset(e, 0x00, sizeof(struct exception));

	// Set what we know
	e->elr = entry;
	e->spsr = SPSR_M_AARCH64 | SPSR_MASK_DEBUG | SPSR_MASK_SERROR | SPSR_MASK_FIQ;
	if(user)	{
		e->spsr |= SPSR_M_SPSEL_EL0 | SPSR_M_STATE_EL0;
	}
	else	{
		e->spsr |= SPSR_M_SPSEL_ELx | SPSR_M_STATE_EL1;
	}
		
//	e->spsr = SPSR_M_SPSEL_EL0 | SPSR_M_STATE_EL0 | SPSR_M_AARCH64 |
//		SPSR_MASK_DEBUG | SPSR_MASK_SERROR | /*SPSR_MASK_IRQ |*/ SPSR_MASK_FIQ;
	e->saved_sp = ustack;
	return nstack;
}

int arch_thread_set_arg(void* sp, ptr_t arg, int num)	{
	struct exception* e = (struct exception*)sp;

	// No sanity checking here, we assume caller has control
	e->regs[num] = arg;
	return 0;
}

int arch_thread_set_return(void* sp, ptr_t arg)	{
	struct exception* e = (struct exception*)sp;
	e->regs[0] = arg;
	return 0;
}

int arch_thread_set_exit(void* sp, ptr_t addr)	{
	struct exception* e = (struct exception*)sp;
	e->regs[30] = addr;
	return 0;
}


void* copy_to_user(void* dest, const void* src, size_t n)	{
	return memcpy(dest, src, n);
}
void* copy_from_user(void* dest, const void* src, size_t n)	{
	return memcpy(dest, src, n);
}

