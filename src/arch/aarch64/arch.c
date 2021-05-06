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

#define IMM26_OFFSET  (26)
#define IMM26_MASK    ((1 << 26) - 1)
#define BRANCH_LINK (0b100101 << 26)

extern void arch_intercept_func(void);
static uint32_t aarch64_gen_branch_imm(ptr_t pc, ptr_t label)	{
	uint32_t ret = 0;
	long offset = ((long)label - (long)pc);
	offset >>= 2;

	ret = BRANCH_LINK;
	ret &= ~(IMM26_MASK);
	if(offset < 0)	{
		ret |= (1 << IMM26_OFFSET);
		offset = -offset;
	}
	ret |= offset;
	return ret;
}

void arch_hijack_function(ptr_t pc, ptr_t exec)	{
	uint32_t insn;
	uint32_t* mod = (uint32_t*)pc;
	ptr_t arch_hj = (ptr_t)arch_intercept_func;

	insn = aarch64_gen_branch_imm(pc, arch_hj);

	*mod = insn;
}
struct argregs {
	ptr_t regs[8];
};
void arch_intercepted(struct argregs* args)	{

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

int arch_update_after_copy(ptr_t* pgd, ptr_t kstack, ptr_t ustack, ptr_t _kstack, ptr_t _ustack, ptr_t stackptr, ptr_t _stackptr)	{
	struct exception* e = (struct exception*)stackptr;
	struct exception* _e = (struct exception*)_stackptr;
	ptr_t diff = _ustack - _e->saved_sp;
	e->saved_sp = ustack - diff;
	//e->saved_sp += 16;
	logi("saved_sp = %x - %x\n", e->saved_sp, _e->saved_sp);
	return 0;
}

ptr_t arch_thread_memcpy_stack(ptr_t* pgd, struct exception* e, void* data, int size)	{
	ptr_t sp = e->saved_sp;
	sp -= size;
	// SP must be aligned on 16-byte boundary
	ALIGN_DOWN_POW2(sp, 16)

	mmu_memcpy(pgd, (void*)sp, data, size);

	e->saved_sp = sp;
	return sp;
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
uint8_t get_user_u8(uint8_t* addr)	{
	uint8_t val;
	if(!ADDR_USER(addr))	{
		PANIC("expected kernel mode address\n");
	}
#if PAN_ENABLED
	pan_disable();
#endif
	val = *addr;
#if PAN_ENABLED
	pan_enable();
#endif
	return val;
}
uint16_t get_user_u16(uint16_t* addr)	{
	uint16_t val;
	if(!ADDR_USER(addr))	{
		PANIC("expected kernel mode address\n");
	}
#if PAN_ENABLED
	pan_disable();
#endif
	val = *addr;
#if PAN_ENABLED
	pan_enable();
#endif
	return val;
}
uint32_t get_user_u32(uint32_t* addr)	{
	uint32_t val;
	if(!ADDR_USER(addr))	{
		PANIC("expected kernel mode address\n");
	}
#if PAN_ENABLED
	pan_disable();
#endif
	val = *addr;
#if PAN_ENABLED
	pan_enable();
#endif
	return val;
}
uint64_t get_user_u64(uint64_t* addr)	{
	uint64_t val;
	if(!ADDR_USER(addr))	{
		PANIC("expected kernel mode address\n");
	}
#if PAN_ENABLED
	pan_disable();
#endif
	val = *addr;
#if PAN_ENABLED
	pan_enable();
#endif
	return val;
}

void mutex_acquire_user(mutex_t* lock)	{
	if(!ADDR_USER(lock))	{
		PANIC("expected kernel mode address\n");
	}
#if PAN_ENABLED
	pan_disable();
#endif
	mutex_acquire(lock);
#if PAN_ENABLED
	pan_enable();
#endif
}
void mutex_release_user(mutex_t* lock)	{
	if(!ADDR_USER(lock))	{
		PANIC("expected kernel mode address\n");
	}
#if PAN_ENABLED
	pan_disable();
#endif
	mutex_release(lock);
#if PAN_ENABLED
	pan_enable();
#endif
}

void put_user_u8(unsigned char* addr, unsigned char val)	{
	if(!ADDR_USER(addr))	{
		PANIC("expected kernel mode address\n");
	}
#if PAN_ENABLED
	pan_disable();
#endif
	*addr = val;
#if PAN_ENABLED
	pan_enable();
#endif
}
void put_user_u16(uint16_t* addr, uint16_t val)	{
	if(!ADDR_USER(addr))	{
		PANIC("expected kernel mode address\n");
	}
#if PAN_ENABLED
	pan_disable();
#endif
	*addr = val;
#if PAN_ENABLED
	pan_enable();
#endif
}
void put_user_u32(uint32_t* addr, uint32_t val)	{
	if(!ADDR_USER(addr))	{
		PANIC("expected kernel mode address\n");
	}
#if PAN_ENABLED
	pan_disable();
#endif
	*addr = val;
#if PAN_ENABLED
	pan_enable();
#endif
}
void put_user_u64(uint64_t* addr, uint64_t val)	{
	if(!ADDR_USER(addr))	{
		PANIC("expected kernel mode address\n");
	}
#if PAN_ENABLED
	pan_disable();
#endif
	*addr = val;
#if PAN_ENABLED
	pan_enable();
#endif
}

char* strdup_user(const char* src)	{
	if(!ADDR_USER(src))	return NULL;
	char* ret;
	size_t len;

	len = strlen_user(src);
	if(!ADDR_USER((ptr_t)src + len))	return NULL;

	ret = (char*)kmalloc(len + 1);
	ASSERT_VALID_PTR(ret);
	memcpy_from_user(ret, src, len+1);
	return ret;
}

void* memdup_user(const void* src, size_t sz)	{
	ASSERT_USER_MEM(src, sz);
	void* ret = kmalloc(sz);
	if(PTR_IS_ERR(src))	return NULL;
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
	kfree(src);
}
