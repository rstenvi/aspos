#include "aarch64.h"
#include "kernel.h"
#include "mmu.h"

extern uint64_t REAL_LOAD;
extern uint64_t kernel_pgd;
extern uint64_t kernel_pud;
extern uint64_t kernel_pmd;
extern uint64_t kernel_ptd;
extern uint64_t KERNEL_START;
extern uint64_t IMAGE_END;
extern uint64_t USER_START;
extern uint64_t USER_END;
extern uint64_t user_pgd;

// All kernel segments
extern uint64_t KERNEL_TEXT_START;
extern uint64_t KERNEL_TEXT_STOP;

extern uint64_t KERNEL_DATA_START;
extern uint64_t KERNEL_DATA_STOP;

extern uint64_t KERNEL_BSS_START;
extern uint64_t KERNEL_BSS_STOP;

extern uint64_t KERNEL_RODATA_START;
extern uint64_t KERNEL_RODATA_STOP;

static inline uint64_t* find_pgd(ptr_t vaddr)	{
	if(ADDR_USER(vaddr))	{
		return (uint64_t*)(cpu_get_user_pgd());
	}
	else	{
		return (uint64_t*)(cpu_get_pgd());
	}
}

int __attribute__((__section__(".init.text"))) mmu_init_kernel(ptr_t vaddr, ptr_t paddr)	{
	ALIGN_DOWN_POW2(paddr, (PAGE_SIZE * ARM64_MMU_ENTRIES_PER_PAGE));
	ALIGN_DOWN_POW2(vaddr, (PAGE_SIZE * ARM64_MMU_ENTRIES_PER_PAGE));
	int i;
#if ARM64_VA_BITS > 39
	uint64_t* kpgd = &kernel_pgd;
#endif
	uint64_t* kpud = &kernel_pud;
	uint64_t* kpmd = &kernel_pmd;
	uint64_t* kptd = &kernel_ptd;
	vaddr -= ARM64_VA_KERNEL_FIRST_ADDR;

#if ARM64_VA_BITS > 39
	int l0idx = ((vaddr & ((ARM64_MMU_ENTRIES_PER_PAGE-1) << 39)) >> 39 );
#endif
	int l1idx = ((vaddr & ((ARM64_MMU_ENTRIES_PER_PAGE-1) << 30)) >> 30 );
	int l2idx = ((vaddr & ((ARM64_MMU_ENTRIES_PER_PAGE-1) << 21)) >> 21 );
	
//	int l3idx = vaddr2ptd(vaddr);

#if ARM64_VA_BITS > 39
	kpgd[l0idx] = (ptr_t)kpud | ARM64_MMU_ENTRY_NEXT_TBL;
#endif

	kpud[l1idx] = (ptr_t)kpmd | ARM64_MMU_ENTRY_NEXT_TBL;
	kpmd[l2idx] = (ptr_t)kptd | ARM64_MMU_ENTRY_NEXT_TBL;

	for(i = 0; i < ARM64_MMU_ENTRIES_PER_PAGE; i++)	{	
		ptr_t tmp = (ptr_t)paddr;
		tmp += (i * PAGE_SIZE);
		tmp &= ARM64_MMU_OA_MASK;
		kptd[i] = tmp;
		kptd[i] |= ARM64_MMU_ENTRY_NEXT_PAGE;
		kptd[i] |= ARM64_MMU_ENTRY_KERNEL_RWX;
	}
	return 0;
}

void __attribute__((__section__(".init.text"))) mmu_early_init(ptr_t real_load, ptr_t kernfirst)	{
	uint64_t* ttbr0;
	uint64_t* ttbr1;

	ttbr0 = &user_pgd;
#if ARM64_VA_BITS > 39
	ttbr1 = &kernel_pgd;
#else
	ttbr1 = &kernel_pud;
#endif

	ptr_t i;
	ALIGN_DOWN_POW2(real_load, PAGE_SIZE);

	// First set up TTBR0 as identity map
	// We fill in the entire pud, which will map in 512GB of memory
	// That much memory probably doesn't exist, but it doesn't matter
	for(i = 0; i < ARM64_MMU_ENTRIES_PER_PAGE; i++)	{
		ttbr0[i] = (i << 30) | ARM64_MMU_ENTRY_KERNEL_RWX | ARM64_MMU_ENTRY_NEXT_BLK;
	}

	// Set ttbr0
	write_sysreg_ttbr0(ttbr0);


	// Early init ttbr0 is 39-bits while ttbr1 is real
	write_sysreg_tcr(
		ARM64_REG_TCR_T0SZ_INIT |
		ARM64_REG_TCR_T1SZ | 
		ARM64_REG_TCR_TG0 | 
		ARM64_REG_TCR_IPS
	);

	mmu_init_kernel(kernfirst + real_load, real_load);
	// Write ttbr1
	write_sysreg_ttbr1(ttbr1);
}


/**
* Create a new table and initialize it to 0.
*/
static ptr_t mmu_create_table()	{
	ptr_t pt = pmm_alloc(1);
	ASSERT_TRUE(pt != 0, "Unable to allocate page table");
	memset((void*)(pt + cpu_linear_offset()), 0x00, PAGE_SIZE);
	return pt;
}

static uint64_t* mmu_check_entry(uint64_t* pt, int idx, bool create)	{
	ptr_t ret;
	if(! entry_valid(pt, idx))	{
		if(create)	{
			ret = mmu_create_table();
			pt[idx] = ret | ARM64_MMU_ENTRY_NEXT_TBL;
		}
		else	{
			return NULL;
		}
	}
	else	{
		ret = pt[idx] & ARM64_MMU_OA_MASK;
	}
	return (uint64_t*)(ret + cpu_linear_offset());
}

static int mmu_create_entry(ptr_t addr, ptr_t oa, uint64_t* pgd, ptr_t flag)	{
#if ARM64_VA_BITS > 39
	int l0idx = vaddr2pgd(addr);
#endif
	int l1idx = vaddr2pud(addr);
	int l2idx = vaddr2pmd(addr);
	int l3idx = vaddr2ptd(addr);

	uint64_t* pud, *pmd, *ptd;

#if ARM64_VA_BITS > 39
	pud = mmu_check_entry(pgd, l0idx, true);
#else
	pud = pgd;
#endif

	pmd = mmu_check_entry(pud, l1idx, true);
	ptd = mmu_check_entry(pmd, l2idx, true);

	ptd[l3idx] = oa | ARM64_MMU_ENTRY_NEXT_PAGE | flag;

	return 0;
}


static void _mmu_unmap_page(ptr_t addr, uint64_t* pgd)	{
#if ARM64_VA_BITS > 39
	int l0idx = vaddr2pgd(addr);
#endif
	int l1idx = vaddr2pud(addr);
	int l2idx = vaddr2pmd(addr);
	int l3idx = vaddr2ptd(addr);

	uint64_t* pud, *pmd, *ptd;

#if ARM64_VA_BITS > 39
	pud = mmu_check_entry(pgd, l0idx, false);
	if(pud == NULL)	return;
#else
	pud = pgd;
#endif

	pmd = mmu_check_entry(pud, l1idx, false);
	if(pmd == NULL)	return;
	
	ptd = mmu_check_entry(pmd, l2idx, false);
	if(ptd == NULL)	return;

	ptr_t oa = ptd[l3idx] & ARM64_MMU_OA_MASK;
	pmm_free(oa);
	ptd[l3idx] = 0;

	isb(); dsb();
}


/**
* Create the linear mapping covering all physical memory.
*/
int mmu_create_linear(ptr_t start, ptr_t end)	{
	ptr_t linstart = phys_to_linear(start);
	ptr_t linstop = phys_to_linear(end);
	ALIGN_DOWN_POW2(linstart, PAGE_SIZE);
	ALIGN_UP_POW2(linstop, PAGE_SIZE);
	uint64_t* pgd = (uint64_t*)(cpu_get_pgd());;

	ptr_t i;

	/*
	* We need to map as RWX below because, the linear region includes the
	* kernel .text segment. This will be automatically patched up when we map in
	* the kernel image. 
	*/
	for(i = 0; i < (linstop - linstart); i += PAGE_SIZE)	{
		mmu_create_entry(linstart + i, start + i, pgd, ARM64_MMU_ENTRY_KERNEL_RWX);
	}

	isb();
}

int mmu_init_user_memory()	{
	uint64_t* pgd = (uint64_t*)(cpu_get_user_pgd());
	int i;
	memset(pgd, 0x00, PAGE_SIZE);

	// VA_BITS for EL0 might be wrong on initial config
	// must write it again
	write_sysreg_tcr(
		ARM64_REG_TCR_T0SZ |
		ARM64_REG_TCR_T1SZ | 
		ARM64_REG_TCR_TG0 | 
		ARM64_REG_TCR_IPS
	);
	isb();
	return 0;
}

int __mmu_map_pages(ptr_t vaddr, ptr_t paddr, int pages, uint64_t* pgd, ptr_t flags)	{
	int i, res = 0;
	ptr_t add;
	for(i = 0; i < pages; i++)	{
		add = i * PAGE_SIZE;
		res = mmu_create_entry(vaddr + add, paddr + add, pgd, flags);
		if(res != 0)	{
			PANIC("Unable to map vaddr");
		}
	}
	isb();
	return res;
}

int mmu_map_dma(ptr_t paddr, ptr_t stop)	{
	int ret = 0;
	uint64_t* pgd = (uint64_t*)(cpu_get_pgd());
	ALIGN_DOWN_POW2(paddr, PAGE_SIZE);
	ALIGN_UP_POW2(stop, PAGE_SIZE);

	ptr_t vaddr = (ARM64_VA_LINEAR_START + paddr);
	ret = __mmu_map_pages(
		vaddr, paddr, (stop - paddr) / PAGE_SIZE , pgd, ARM64_MMU_ENTRY_KERNEL_RW | ARM64_MMU_ENTRY_ATTR_DMA);

	isb();
	return ret;
}

static int _mmu_map_pages(ptr_t vaddr, int pages, ptr_t flags, uint64_t* pgd)	{
	int ret = 0;
	ptr_t paddr = pmm_alloc(pages);
	ret = __mmu_map_pages(vaddr, paddr, pages, pgd, flags);
	isb();
	return ret;
}

static ptr_t _mmu_prot_to_flags(bool user, enum MEMPROT prot)	{
	ptr_t ret = 0;
	switch(prot)	{
		case PROT_NONE:
			ret = 0;
			break;
		case PROT_RO:
			ret = (user) ? ARM64_MMU_ENTRY_USER_RO : ARM64_MMU_ENTRY_KERNEL_RO;
			break;
		case PROT_RW:
			ret = (user) ? ARM64_MMU_ENTRY_USER_RW : ARM64_MMU_ENTRY_KERNEL_RW;
			break;
		case PROT_RX:
			ret = (user) ? ARM64_MMU_ENTRY_USER_RX : ARM64_MMU_ENTRY_KERNEL_RX;
			break;
		case PROT_RWX:
			ret = (user) ? ARM64_MMU_ENTRY_USER_RWX : ARM64_MMU_ENTRY_KERNEL_RWX;
			break;
		default:
			logw("Unsupported value: %i\n", prot);
			break;
	}
	return ret;
}


static int map_kernel_image(void)	{
	uint64_t* pgd = (uint64_t*)(cpu_get_pgd());
	ptr_t start, stop;

	// Map text segment as executable
	start = (ptr_t)(&(KERNEL_TEXT_START));	ALIGN_DOWN_POW2(start, PAGE_SIZE);
	stop = (ptr_t)(&(KERNEL_TEXT_STOP));	ALIGN_UP_POW2(stop, PAGE_SIZE);
	__mmu_map_pages(start, start - ARM64_VA_KERNEL_FIRST_ADDR, (stop - start) / PAGE_SIZE, pgd, ARM64_MMU_ENTRY_KERNEL_RX);


	// Map .data and .bss as RW
	start = (ptr_t)(&(KERNEL_DATA_START));	ALIGN_DOWN_POW2(start, PAGE_SIZE);
	stop = (ptr_t)(&(KERNEL_BSS_STOP));		ALIGN_UP_POW2(stop, PAGE_SIZE);
	__mmu_map_pages(start, start - ARM64_VA_KERNEL_FIRST_ADDR, (stop - start) / PAGE_SIZE, pgd, ARM64_MMU_ENTRY_KERNEL_RW);

	// Map .rodata and RO
	start = (ptr_t)(&(KERNEL_RODATA_START));	ALIGN_DOWN_POW2(start, PAGE_SIZE);
	stop = (ptr_t)(&(KERNEL_RODATA_STOP));		ALIGN_UP_POW2(stop, PAGE_SIZE);
	__mmu_map_pages(start, start - ARM64_VA_KERNEL_FIRST_ADDR, (stop - start) / PAGE_SIZE, pgd, ARM64_MMU_ENTRY_KERNEL_RO);

	return 0;
}




// ------------------------------ API ------------------------------------ //


int mmu_second_init(void)	{
	map_kernel_image();

	// [0] = normal memory pointing to attr
	// [1] = strong device memory (nGnRnE)
	write_mair_el1(0b0000000001000100UL);

	isb();
	dsb();
	return 0;
}


/**
* Parse page tables to find a physical address associated with any virtual address.
*/
ptr_t mmu_va_to_pa(ptr_t vaddr)	{
	uint64_t* pgd = find_pgd(vaddr);


#if ARM64_VA_BITS > 39
	int l0idx = vaddr2pgd(vaddr);
#endif
	int l1idx = vaddr2pud(vaddr);
	int l2idx = vaddr2pmd(vaddr);
	int l3idx = vaddr2ptd(vaddr);

	uint64_t* pud, *pmd, *ptd;

#if ARM64_VA_BITS > 39
	pud = mmu_check_entry(pgd, l0idx, false);
	if(pud == NULL)	return 0;
#else
	pud = pgd;
#endif

	pmd = mmu_check_entry(pud, l1idx, false);
	if(pmd == NULL)	return 0;

	ptd = mmu_check_entry(pmd, l2idx, false);
	if(ptd == NULL)	return 0;

	return (ptd[l3idx] & ARM64_MMU_OA_MASK) | (vaddr & ARM64_MMU_OFFSET_MASK);
}

bool mmu_addr_mapped(ptr_t addr, size_t len, int type)	{
	ptr_t res;
	size_t off;
	int invalid = 0;

	ALIGN_DOWN_POW2(addr, PAGE_SIZE);
	ALIGN_UP_POW2(len, PAGE_SIZE);
	for(off = 0; off < len; off += PAGE_SIZE)	{
		res = mmu_va_to_pa((ptr_t)addr + off);
		if(res == 0)	{
			if(type == MMU_ALL_MAPPED)	{
				return false;
			}
		}
		else	{
			if(type == MMU_ALL_UNMAPPED)	{
				return false;
			}
		}
	}
	return true;
}

int mmu_map_pages(ptr_t vaddr, int pages, enum MEMPROT prot)	{
	uint64_t* pgd = find_pgd(vaddr);
	return _mmu_map_pages(vaddr, pages, _mmu_prot_to_flags(ADDR_USER(vaddr), prot), pgd);
}

int mmu_map_page(ptr_t vaddr, enum MEMPROT prot) {
	return mmu_map_pages(vaddr, 1, prot);
}

void mmu_unmap_pages(ptr_t vaddr, int pages)	{
	uint64_t* pgd = find_pgd(vaddr);
	int i;
	for(i = 0; i < pages; i++)	{
		_mmu_unmap_page(vaddr + (i * PAGE_SIZE), pgd);
	}
}

void mmu_unmap_page(ptr_t vaddr) { return mmu_unmap_pages(vaddr, 1); }

