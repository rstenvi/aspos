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
//__force_inline static inline ptr_t arch_return_pc(void) { asm("mov x0, lr"); }

#define CHK_CLONE_FLAG_USER   (1 << 0)
#define CHK_CLONE_FLAG_INSTR  (1 << 1)
#define CHK_CLONE_FLAG_WRITE  (1 << 2)
#define CHK_CLONE_FLAG_COPY   (1 << 3)
#define CHK_CLONE_FLAG_NOPERM (1 << 4)

ptr_t mmu_find_available_space(ptr_t* pgd, int pages, enum MEMPROT prot, bool mapin);
int mmu_copy_cloned_pages(ptr_t vaddr, int pages, ptr_t* pgd1, ptr_t* pgd2);
void mmu_unmap_pages_pgd(ptr_t* pgd, ptr_t vaddr, int pages);
bool mmu_page_mapped(ptr_t addr);
bool mmu_check_page_cloned_pgd(ptr_t* pgd, ptr_t vaddr, uint32_t flags /*bool user, bool instr, bool write*/);
int mmu_map_page_pgd_oa_entry(ptr_t* pgd, ptr_t vaddr, ptr_t oa, ptr_t entry);
int mmu_map_page_pgd(ptr_t* pgd, ptr_t vaddr, enum MEMPROT prot);
ptr_t mmu_find_free_pages(ptr_t* pgd, int startpage, int pages);
int mmu_double_unmap_pages(ptr_t* pgdfrom, ptr_t* pgdto, ptr_t, ptr_t, int pages);
int mmu_double_map_pages(ptr_t* pgdfrom, ptr_t* pgdto, ptr_t, ptr_t, int pages);
void* mmu_memset(ptr_t* pgd, void* _s, int c, size_t n);
void* mmu_memcpy(ptr_t* pgd, void* _dest, const void* src, size_t n);
void* mmu_strcpy(ptr_t* pgd, void* _dest, const void* src);
int mmu_put_u64(ptr_t* pgd, ptr_t* _dest, ptr_t val);
int mmu_init_user_memory(ptr_t*);
int mmu_second_init(void);
int mmu_map_dma(ptr_t paddr, ptr_t stop);
int mmu_map_pages(ptr_t vaddr, int pages, enum MEMPROT prot);
int mmu_map_page(ptr_t vaddr, enum MEMPROT prot);
void mmu_unmap_pages(ptr_t vaddr, int pages);
void mmu_unmap_page(ptr_t vaddr);
ptr_t mmu_va_to_pa(ptr_t vaddr);
void mmu_unmap_user(ptr_t*);
int mmu_clone_fork(ptr_t* pgdto);
int mmu_map_pages_pgd(ptr_t* pgd, ptr_t vaddr, int pages, enum MEMPROT prot);
ptr_t mmu_va_to_pa_pgd(ptr_t* pgd, ptr_t vaddr, ptr_t* entry);
ptr_t mmu_create_user_stack(ptr_t* pgd, int pages);

void mutex_acquire_user(mutex_t* lock);
void mutex_release_user(mutex_t* lock);
void put_user_u8(unsigned char* addr, unsigned char val);
void put_user_u16(uint16_t* addr, uint16_t val);
void put_user_u32(uint32_t* addr, uint32_t val);
void put_user_u64(uint64_t* addr, uint64_t val);
uint8_t get_user_u8(uint8_t* addr);
uint16_t get_user_u16(uint16_t* addr);
uint32_t get_user_u32(uint32_t* addr);
uint64_t get_user_u64(uint64_t* addr);

void arch_dump_regs(void);

ptr_t arch_prepare_thread_stack(void* stacktop, ptr_t entry, ptr_t ustack, bool user);
int arch_thread_set_arg(void* sp, ptr_t arg, int num);
int arch_thread_set_return(void* sp, ptr_t arg);
int arch_thread_set_exit(void* sp, ptr_t addr);
ptr_t arch_thread_strcpy_stack(struct exception* e, char* str);
void arch_schedule(void* sp, ptr_t ttbr0);
ptr_t arch_thread_memcpy_stack(ptr_t* pgd, struct exception* e, void* data, int size);

int arch_update_after_copy(ptr_t* pgd, ptr_t kstack, ptr_t ustack, ptr_t _kstack, ptr_t _ustack, ptr_t stackptr, ptr_t _stackptr);
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
void* memcpy_from_user(void* dest, const void* src, size_t n);
void* memcpy_to_user(void* dest, const void* src, size_t n);
char* strdup_user(const char* src);
void* memdup_user(const void* src, size_t sz);
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

#define MMU_ALL_MAPPED   1
#define MMU_ALL_UNMAPPED 2
bool mmu_addr_mapped(ptr_t addr, size_t len, int type);


static inline void arch_set_upgd(ptr_t pgd)	{
	write_sysreg_ttbr0(pgd);
}

void flush_tlb(void);

#endif
