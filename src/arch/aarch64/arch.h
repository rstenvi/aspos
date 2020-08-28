/*
* All architectures must implement a file like this
*/
#ifndef __ARCH_H
#define __ARCH_H

#include <stdint.h>

#include "aarch64.h"
#include "aarch64-config.h"
#include "types.h"

#define ARCH_LITTLE_ENDIAN 1
#define ARCH_CPUBITS 64

struct exception {
	uint64_t type;
	uint64_t esr;
	uint64_t saved_sp;
	uint64_t elr;
	uint64_t spsr;
	uint64_t regs[31];
};

struct altinstr_repl {
	uint64_t addr;
	uint32_t instruction;
	uint32_t id;
} __attribute__((packed));

enum MEMPROT {
	PROT_NONE = 0,
	PROT_RO,
	PROT_RW,
	PROT_RX,
	PROT_RWX
};

/* todo: Currently we only support args in registers */
static int arch_max_supported_args(void) { return 8; }

static inline bool prot_writable(enum MEMPROT prot)	{
	return (prot == PROT_RW) || (prot == PROT_RWX);
}

static inline void isb() { asm("isb"); }
static inline void dsb() { asm("dsb SY"); }



int mmu_init_user_memory();
int mmu_second_init(void);
int mmu_map_dma(ptr_t paddr, ptr_t stop);
int mmu_map_pages(ptr_t vaddr, int pages, enum MEMPROT prot);
int mmu_map_page(ptr_t vaddr, enum MEMPROT prot);
void mmu_unmap_pages(ptr_t vaddr, int pages);
void mmu_unmap_page(ptr_t vaddr);
ptr_t mmu_va_to_pa(ptr_t vaddr);


void arch_dump_regs(void);

ptr_t arch_prepare_thread_stack(void* stacktop, ptr_t entry, ptr_t ustack, bool user);
int arch_thread_set_arg(void* sp, ptr_t arg, int num);
int arch_thread_set_return(void* sp, ptr_t arg);
int arch_thread_set_exit(void* sp, ptr_t addr);
void arch_schedule(void* sp);

void set_stack(uint64_t, void (*cb_t)(void));

#define PAGE_SIZE ARM64_PAGE_SIZE

#define CNTV_CTL_ENABLE   (1 << 0)

uint64_t read_cntv_ctl_el0();
void write_cntv_ctl_el0(uint64_t);
void write_mair_el1(uint64_t);
uint64_t read_cntfrq_el0();
uint64_t read_cntvct_el0();
uint64_t read_mpidr_el1();
void write_cntv_cval_el0(uint64_t);
void enable_irq(void);
void arch_busyloop(void);
void _uthread_exit(void);
void* copy_from_user(void* dest, const void* src, size_t n);
void* copy_to_user(void* dest, const void* src, size_t n);
char* strdup_user(const char* src);
void* memcopy_user(const void* src, size_t sz);
size_t strlen_user(const char* src);
void free_user(char* src);
void cpu_reset(void);

bool pan_enable(void);
bool pan_disable(void);
bool pan_supported(void);

static inline int cpu_id(void)	{ return (int)(read_mpidr_el1() & 0xff); }

static inline void halt() { asm volatile("wfi"); }

static inline void arm64_disable_cntv()	{
	uint64_t ctl;
	ctl = read_cntv_ctl_el0();
	ctl &= ~(CNTV_CTL_ENABLE);
	write_cntv_ctl_el0(ctl);
}

static inline void arm64_enable_cntv()	{
	uint64_t ctl;
	ctl = read_cntv_ctl_el0();
	ctl |= CNTV_CTL_ENABLE;
	write_cntv_ctl_el0(ctl);
}

#endif
