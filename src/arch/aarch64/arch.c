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

/*
* TODO: Need to check length before copying
*/
ptr_t arch_thread_strcpy_stack(struct exception* e, char* str)	{
	int len, rlen;
	ptr_t user_sp;

	user_sp = e->saved_sp;

	// Get real length of string
	rlen = strlen(str);
	len = rlen;
	ALIGN_UP_POW2(len, 16);
	user_sp -= len;
	memcpy_to_user((void*)user_sp, str, rlen);

	e->saved_sp = user_sp;

	return user_sp;
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


size_t strlen_user(const char* src)	{
	size_t res = 0;
#if PAN_ENABLED
	pan_disable();
#endif
	res = strlen(src);
#if PAN_ENABLED
	pan_enable();
#endif
	return res;
}

char* strdup_user(const char* src)	{
	char* ret;
	size_t len;

	len = strlen_user(src);
	ret = (char*)malloc(len + 1);
	ASSERT_VALID_PTR(ret);
	memcpy_from_user(ret, src, len+1);
	return ret;
}

void* memdup_user(const void* src, size_t sz)	{
	void* ret = malloc(sz);
	ASSERT_VALID_PTR(ret);
	memcpy_from_user(ret, src, sz);
	return ret;
}

/**
* We use separate routine for allocating and free-ing data which has been copied
* from user mode. That allows us to optimize these memory allocations. Since
* these allocations will typically be small and also last for a short amount of
* time, we could implement a faster allocation mechanism with malloc as a backup
* if the other method is not feasible.
*/
void free_user(char* src)	{
	free(src);
}
