
#include "aarch64.h"
#include "arch.h"
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

#define PGD_ASSERT(pgd) \
	BUG_ASSERT(ADDR_KERNEL((ptr_t)pgd)); \
	BUG_ASSERT(ALIGNED_ON_POW2((ptr_t)pgd,PAGE_SIZE))


//int _mmu_clone_table(ptr_t* pgdfrom, ptr_t* pgdto, int last);

static inline uint64_t* find_pgd(ptr_t vaddr)	{
	if(ADDR_USER(vaddr))	{
		return (uint64_t*)(cpu_get_user_pgd());
	}
	else	{
		return (uint64_t*)(cpu_get_pgd());
	}
}

int __no_ubsan __attribute__((__section__(".init.text"))) mmu_init_kernel(ptr_t vaddr, ptr_t paddr)	{
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

void __no_ubsan __attribute__((__section__(".init.text"))) mmu_early_init(ptr_t real_load, ptr_t kernfirst)	{
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

static ptr_t mmu_copy_page(ptr_t* page)	{
	ptr_t pt = pmm_alloc(1);
	ASSERT_TRUE(pt != 0, "Unable to allocate page table");
	memcpy((void*)(pt + cpu_linear_offset()), page, PAGE_SIZE);
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
	//logd("mmu %lx -> %lx\n", addr, oa);

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

	if(ptd[l3idx] & ARM64_MMU_ENTRY_NEXT_PAGE)	{
		ptr_t oa = ptd[l3idx] & ARM64_MMU_OA_MASK;
		logd("mmu free %lx -> %lx\n", addr, oa);
		pmm_free(oa);
		ptd[l3idx] = 0;
	}

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

int mmu_init_user_memory(ptr_t* pgd)	{
//	uint64_t* pgd = (uint64_t*)(cpu_get_user_pgd());
	int i;
//	memset(pgd, 0x00, PAGE_SIZE);

	write_sysreg_ttbr0(mmu_va_to_pa((ptr_t)pgd));

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
	isb(); dsb();
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

#if defined(CONFIG_KASAN)
	kasan_mark_valid(vaddr, (stop - paddr));
#endif
	isb(); dsb();
	return ret;
}

static int _mmu_map_pages(ptr_t vaddr, int pages, ptr_t flags, uint64_t* pgd)	{
	int ret = 0;
	ptr_t paddr = pmm_alloc(pages);
	//logd("mmu %lx -> %lx\n", vaddr, paddr);
	ret = __mmu_map_pages(vaddr, paddr, pages, pgd, flags);
	isb(); dsb();
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

ptr_t mmu_va_to_pa_pgd(ptr_t* pgd, ptr_t vaddr, ptr_t* entry)	{

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

	if(entry != NULL)	*entry = ptd[l3idx] & ~(ARM64_MMU_OA_MASK);
	return (ptd[l3idx] & ARM64_MMU_OA_MASK) | (vaddr & ARM64_MMU_OFFSET_MASK);
}


/**
* Parse page tables to find a physical address associated with any virtual address.
*/
ptr_t mmu_va_to_pa(ptr_t vaddr)	{
	uint64_t* pgd = find_pgd(vaddr);

	return mmu_va_to_pa_pgd(pgd, vaddr, NULL);
}

bool mmu_page_mapped(ptr_t addr)	{
	return mmu_va_to_pa(addr) != 0;
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
int mmu_map_pages_pgd(ptr_t* pgd, ptr_t vaddr, int pages, enum MEMPROT prot)	{
	return _mmu_map_pages(vaddr, pages, _mmu_prot_to_flags(ADDR_USER(vaddr), prot), pgd);
}
int mmu_map_page_pgd(ptr_t* pgd, ptr_t vaddr, enum MEMPROT prot)	{
	return _mmu_map_pages(vaddr, 1, _mmu_prot_to_flags(ADDR_USER(vaddr), prot), pgd);
}
int mmu_map_page_pgd_oa_entry(ptr_t* pgd, ptr_t vaddr, ptr_t oa, ptr_t entry)	{
	return __mmu_map_pages(vaddr, oa, 1, pgd, entry);
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
void mmu_unmap_pages_pgd(ptr_t* pgd, ptr_t vaddr, int pages)	{
	int i;
	for(i = 0; i < pages; i++)	{
		_mmu_unmap_page(vaddr + (i * PAGE_SIZE), pgd);
	}
}

ptr_t* _mmu_fix_table(ptr_t* pxd, int idx, ptr_t entry)	{
	PGD_ASSERT(pxd);
	ptr_t oa = (ptr_t)pxd - cpu_linear_offset(), noa;
	int pmmref;
	pmmref = pmm_ref(oa);
	if(pmmref > 1)	{
		noa = mmu_copy_page(pxd);
		pmm_free(oa);
		pxd = (ptr_t*)(noa + cpu_linear_offset());
//		ARM64_MMU_SET_OA(entry, noa);
	}
	pxd[idx] = entry;
	return pxd;
}

static bool access_valid(int ap, bool user, bool write)	{
	switch(ap)	{
	case ARM64_MMU_ENTRY_AP_EL1_RW_EL0_NONE:
		return !user;
	case ARM64_MMU_ENTRY_AP_EL1_RW_EL0_RW:
		return true;
	case ARM64_MMU_ENTRY_AP_EL1_RO_EL0_NONE:
		return (!user && !write);
	case ARM64_MMU_ENTRY_AP_EL1_RO_EL0_RO:
		return (!write);
	default:
		return false;
	}
}
bool mmu_check_page_cloned_pgd(ptr_t* pgd, ptr_t vaddr, uint32_t flags)	{
	PGD_ASSERT(pgd);
	int res, pmmref;
	ptr_t _p, * pud, * pmd, * ptd, * page, e, val, oa, noa;
	ASSERT(pgd);
	bool user = FLAG_SET(flags, CHK_CLONE_FLAG_USER);
	bool instr = FLAG_SET(flags, CHK_CLONE_FLAG_INSTR);
	bool write = FLAG_SET(flags, CHK_CLONE_FLAG_WRITE);
	bool copy = FLAG_SET(flags, CHK_CLONE_FLAG_COPY);
	bool noperm = FLAG_SET(flags, CHK_CLONE_FLAG_NOPERM);

#if ARM64_VA_BITS > 39
	int l0idx = vaddr2pgd(vaddr);
	pud = mmu_check_entry(pgd, l0idx, false);
	if(PTR_IS_ERR(pud))	return false;
#endif

	int l1idx = vaddr2pud(vaddr);
	pmd = mmu_check_entry(pud, l1idx, false);
	if(PTR_IS_ERR(pmd))	return false;

	int l2idx = vaddr2pmd(vaddr);
	ptd = mmu_check_entry(pmd, l2idx, false);
	if(PTR_IS_ERR(ptd))	return false;

	int l3idx = vaddr2ptd(vaddr);
	page = mmu_check_entry(ptd, l3idx, false);
	if(PTR_IS_ERR(page))	return false;

	e = ptd[l3idx];
	if(ARM64_MMU_ENTRY_IS_VALID(e))	{
		if(!ARM64_MMU_CLONED(e))	return false;
		if(!noperm && !write)		return false;

		// Get real AP value and check if access is valid
		val = ARM64_MMU_CLONE_AP_VAL(e);
		if(!noperm && !access_valid(val, user, write))	return false;
//		if(user && ((val == ARM64_MMU_ENTRY_AP_EL1_RO_EL0_RO) || (val == ARM64_MMU_ENTRY_AP_EL1_RO_EL0_NONE) || (val == ARM64_MMU_ENTRY_AP_EL1_RW_EL0_NONE)))
//			return false;
//		if(!user && ((val == ARM64_MMU_ENTRY_AP_EL1_RO_EL0_NONE) || (val == ARM64_MMU_ENTRY_AP_EL1_RO_EL0_RO)))
//			return false;

		
		// Access is valid, we must fix ptd
		oa = (e & ARM64_MMU_OA_MASK);
		pmmref = pmm_ref(oa);
		if(pmmref > 0)	{
			if(copy && pmmref > 1)	{
				// If there are multiple references to this page table, we must
				// allocate a new one and copy the old one
				noa = mmu_copy_page(page);
				ARM64_MMU_SET_OA(e, noa);
				pmm_free(oa);
			}
			// Restore original permission bits and set clone off
			ARM64_AP_SET(e, val);
			ARM64_MMU_CLONE_AP_CLEAR(e);
			ARM64_MMU_CLONE_CLEAR(e);
		}
		else	{
			PANIC("pmmref <= 0");
		}

		// We must now propogate the fix throughout the upper page tables

		ptr_t* pxd;
		pxd = _mmu_fix_table(ptd, l3idx, e);
		if(pxd != ptd)	{
			e = pmd[l2idx];
			ARM64_MMU_SET_OA(e, (ptr_t)pxd - cpu_linear_offset());
			pxd = _mmu_fix_table(pmd, l2idx, e);
			if(pxd != pmd)	{
				e = pud[l1idx];
				ARM64_MMU_SET_OA(e, (ptr_t)pxd - cpu_linear_offset());
#if ARM64_VA_BITS <= 39
				pud[l1idx] = e;
#else
				pxd = _mmu_fix_table(pud, l1idx, e);
				if(pxd != pud)	{
					e = pgd[l0idx];
					ARM64_MMU_SET_OA(e, (ptr_t)pxd - cpu_linear_offset());
					pgd[l0idx] = e;
				}
#endif
			}
		}
	}
	else	{
		return false;
	}


	// TLB will never hold an invalid entry, so it should not be necessary to
	// any TLB maintenance

//	flush_tlb();
	isb(); dsb();
	return true;
}

bool mmu_check_page_cloned(ptr_t vaddr, bool user, bool instr, bool write)	{
	ptr_t* pgd = find_pgd(vaddr);
	uint32_t flags = 0;
	flags |= (user) ? CHK_CLONE_FLAG_USER : 0;
	flags |= (instr) ? CHK_CLONE_FLAG_INSTR : 0;
	flags |= (write) ? CHK_CLONE_FLAG_WRITE : 0;
	flags |= CHK_CLONE_FLAG_COPY;
	return mmu_check_page_cloned_pgd(pgd, vaddr, flags/*user, instr, write*/);
}
int mmu_copy_cloned_pages(ptr_t vaddr, int pages, ptr_t* pgd1, ptr_t* pgd2)	{
	int i;
	uint32_t flags = CHK_CLONE_FLAG_NOPERM;
	for(i = 0; i < pages; i++)	{
		mmu_check_page_cloned_pgd(pgd1, vaddr + (i * PAGE_SIZE), flags);
		mmu_check_page_cloned_pgd(pgd2, vaddr + (i * PAGE_SIZE), flags);
	}
	return OK;
}

int _mmu_clone_fork(ptr_t* from, int max, int table)	{
	ptr_t* n = NULL, tmp, oa, e;
	int res, i;
	for(i = 0; i < max; i++)	{
		n = mmu_check_entry(from, i, false);
		if(!n)	continue;

		oa = (from[i] & ARM64_MMU_OA_MASK);
		pmm_add_ref(oa);

		if(table > 0)	{
			_mmu_clone_fork(n, ARM64_MMU_ENTRIES_PER_PAGE, table-1);
		}
		else	{
			e = from[i];
			e |= ARM64_MMU_CLONE_BIT;
			if(ARM64_MMU_ENTRY_WRITABLE(e))	{
				tmp = ARM64_AP_GET(e);
				e &= ~(ARM64_AP_MASK);
				e |= (tmp << ARM64_MMU_CLONE_AP_OFFSET);

				// Need to change AP-bits to readable by appropriate EL
				// entry is writable, so only two valid entries
				ptr_t apbits = (tmp == ARM64_MMU_ENTRY_AP_EL1_RW_EL0_RW) ?
					ARM64_MMU_ENTRY_AP_EL1_RO_EL0_RO :
					ARM64_MMU_ENTRY_AP_EL1_RO_EL0_NONE;

				ARM64_AP_SET(e, apbits);
			}
			from[i] = e;
		}
	}
	return 0;
}
int mmu_clone_fork(ptr_t* pgdto)	{
	PGD_ASSERT(pgdto);
	int max = 512, i;
	int table = 2;
	ptr_t* pgd = (ptr_t*)cpu_get_user_pgd();

#if ARM64_VA_BITS > 39
	table = 3;
	max = (1 << (ARM64_VA_BITS - 39));
#endif

	_mmu_clone_fork(pgd, max, table);

	memcpy(pgdto, pgd, PAGE_SIZE);
	flush_tlb();
	isb(); dsb();
	return OK;
}

// Free up all user-space memory
void mmu_unmap_user(ptr_t* pgd)	{
	PGD_ASSERT(pgd);
	int i, j, k, l, max1 = 0;
	uint64_t* pud, *pmd, *ptd;
//	uint64_t* pgd = (uint64_t*)(cpu_get_user_pgd());
	ptr_t oa;
#if ARM64_VA_BITS > 39
	max1 = (1 << (ARM64_VA_BITS - 39));
	for(i = 0; i < max1; i++)	{
		pud = mmu_check_entry(pgd, i, false);
		if(!pud)	continue;
#else
		pud = pgd
#endif
		for(j = 0; j < ARM64_MMU_ENTRIES_PER_PAGE; j++)	{
			pmd = mmu_check_entry(pud, j, false);
			if(!pmd)	continue;
			for(k = 0; k < ARM64_MMU_ENTRIES_PER_PAGE; k++)	{
				ptd = mmu_check_entry(pmd, k, false);
				if(!ptd)	continue;
				for(l = 0; l < ARM64_MMU_ENTRIES_PER_PAGE; l++)	{
					if(ptd[l] & ARM64_MMU_ENTRY_NEXT_PAGE)	{
						oa = ptd[l] & ARM64_MMU_OA_MASK;
						pmm_free(oa);
						ptd[l] = 0;
					}
				}
				oa = pmd[k] & ARM64_MMU_OA_MASK;
				pmm_free(oa);
				pmd[k] = 0;
			}
			oa = pud[j] & ARM64_MMU_OA_MASK;
			pmm_free(oa);
			pud[j] = 0;
		}
#if ARM64_VA_BITS > 39
		oa = pgd[i] & ARM64_MMU_OA_MASK;
		pmm_free(oa);
		pgd[i] = 0;
	}
#endif
	flush_tlb();
}

void mmu_unmap_page(ptr_t vaddr) { return mmu_unmap_pages(vaddr, 1); }


int mmu_double_map_pages(ptr_t* pgdfrom, ptr_t* pgdto, ptr_t _vaddr_from, ptr_t _vaddr_to, int pages)	{
	PGD_ASSERT(pgdfrom);
	PGD_ASSERT(pgdto);
	int i;
	ptr_t oa, entry, vaddr_from, vaddr_to;
	for(i = 0; i < pages; i++)	{
		vaddr_from = _vaddr_from + (i * PAGE_SIZE);
		vaddr_to = _vaddr_to + (i * PAGE_SIZE);
		oa = mmu_va_to_pa_pgd(pgdfrom, vaddr_from, &entry);
		pmm_add_ref(oa);
		// The entries we've copied might have been cloned
		mmu_create_entry(vaddr_to, oa, pgdto, entry);
	}
	return OK;
}
int mmu_double_unmap_pages(ptr_t* pgdfrom, ptr_t* pgdto, ptr_t _vaddr_from, ptr_t _vaddr_to, int pages)	{
	PGD_ASSERT(pgdfrom);
	PGD_ASSERT(pgdto);
	int i;
	ptr_t ooa, noa, oentry, nentry, vaddr_from, vaddr_to;
	for(i = 0; i < pages; i++)	{
		vaddr_from = _vaddr_from + (i * PAGE_SIZE);
		vaddr_to = _vaddr_to + (i * PAGE_SIZE);
		ooa = mmu_va_to_pa_pgd(pgdfrom, vaddr_from, &oentry);
		noa = mmu_va_to_pa_pgd(pgdto, vaddr_to, &nentry);

		// The page we originally mapped might have been cloned, so we might
		// need to fix up the original pgd
		// This will also increase pmm-ref, so that the next free
		// will be correct
		if(ooa != noa || oentry != nentry)	{
			mmu_create_entry(vaddr_from, noa, pgdfrom, nentry);
		}
		_mmu_unmap_page(vaddr_to, pgdto);
	}
	flush_tlb();
	return OK;
}

ptr_t mmu_find_free_pages(ptr_t* pgd, int startpage, int pages)	{
	PGD_ASSERT(pgd);
	logi("TODO: Checking page all the way until stack region\n");
	ptr_t i, lastpage = (ARM64_VA_USER_STOP / PAGE_SIZE) - 1, count = 0;
	for(i = startpage; i < lastpage; i++)	{
		if(mmu_va_to_pa_pgd(pgd, ((ptr_t)i * PAGE_SIZE), NULL))	{
			count = 0;
		}
		else	{
			count++;
			if(count == pages)	{
				return (ptr_t)(i - count + 1) * PAGE_SIZE;
			}
		}
	}
	logw("Unable to find free pages\n");
	return 0;
}

ptr_t mmu_find_available_space(ptr_t* pgd, int pages, enum MEMPROT prot, bool mapin)	{
	PGD_ASSERT(pgd);
	ptr_t try = (1 * MB), oa, rtry;
	int i;
	bool found = false;

	while(found == false && try < (ADDR_USER_LAST - (PAGE_SIZE * pages)))	{
		for(i = 0; i < pages; i++)	{
			rtry = try + (i * PAGE_SIZE);
			if(mmu_va_to_pa_pgd(pgd, rtry, NULL))	{
				try = rtry + PAGE_SIZE;
				break;
			}
		}
		if(i >= pages)	{
			if(mapin)	{
				_mmu_map_pages(try, pages, _mmu_prot_to_flags(true, prot), pgd);
			}
			return try;
		}
	}
	return 0;
}

/**
* Search for a user-stack. This should be a simple process in most instances,
* but the user-mode process may have mapped in some uncommon areas.
*/
ptr_t mmu_create_user_stack(ptr_t* pgd, int pages)	{
	PGD_ASSERT(pgd);

	// First possible stack size we try
	ptr_t try = ADDR_USER_LAST - (PAGE_SIZE * (CONFIG_THREAD_STACK_BLOCKS + 1));
	// We must allow some padding between each stack so that it can grow
	ptr_t padding = (PAGE_SIZE * CONFIG_THREAD_STACK_BLOCKS * 16);
	ptr_t oa;
	int i;
again:
	while((oa = mmu_va_to_pa_pgd(pgd, try, NULL)) != 0)	{
		try -= padding;
	}
	for(i = 0; i < pages; i++)	{
		if(mmu_va_to_pa_pgd(pgd, try + (i * PAGE_SIZE), NULL))	{
			try -= padding;
			goto again;
		}
	}

	// Map in all the pages
	_mmu_map_pages(try, pages, _mmu_prot_to_flags(true, PROT_RW), pgd);

	flush_tlb();
	isb(); dsb();
	return try;
}

void* mmu_memset(ptr_t* pgd, void* _s, int c, size_t n)	{
	PGD_ASSERT(pgd);
	ASSERT_USER_MEM(_s, n);
	ptr_t oa = mmu_va_to_pa_pgd(pgd, (ptr_t)_s, NULL);
	if(!oa)	return NULL;
	void* s = (void*)(oa + cpu_linear_offset());
	return memset(s, c, n);
}
void* mmu_memcpy(ptr_t* pgd, void* _dest, const void* src, size_t n)	{
	PGD_ASSERT(pgd);
	ASSERT_KERNEL_MEM(src, n);
	ASSERT_USER_MEM(_dest, n);
	ptr_t oa = mmu_va_to_pa_pgd(pgd, (ptr_t)_dest, NULL);
	if(!oa)	return NULL;
	void* dest = (void*)(oa + cpu_linear_offset());
	return memcpy(dest, src, n);
}
void* mmu_strcpy(ptr_t* pgd, void* _dest, const void* src)	{
	PGD_ASSERT(pgd);
	ASSERT_KERNEL(src);
	ASSERT_USER(_dest);
	ptr_t oa = mmu_va_to_pa_pgd(pgd, (ptr_t)_dest, NULL);
	if(!oa)	return NULL;
	void* dest = (void*)(oa + cpu_linear_offset());
	return strcpy(dest, src);
}
int mmu_put_u64(ptr_t* pgd, ptr_t* _dest, ptr_t val)	{
	PGD_ASSERT(pgd);
	ASSERT_USER(_dest)
	ptr_t oa = mmu_va_to_pa_pgd(pgd, (ptr_t)_dest, NULL);
	if(!oa)	return -1;
	ptr_t* dest = (ptr_t*)(oa + cpu_linear_offset());
	*dest = val;
	return OK;
}
/*
ptr_t* _mmu_clone_fork_table(ptr_t* from, ptr_t* to, int start, bool page)	{
	int i;
	ptr_t* 
	for(i = start; i < ARM64_MMU_ENTRIES_PER_PAGE; i++)	{
		pmd = mmu_check_entry(from, i, false);
		if(!pmd)	continue;
		tmp = mmu_create_table()
		n_pud[j] = pud[j] & ~(ARM64_MMU_OA_MASK) | tmp;
		n_pmd = (ptr_t*)(tmp + cpu_linear_offset());
	}
}
*/
/*
ptr_t _mmu_check_page_cloned(ptr_t* pgd, ptr_t vaddr, int level, int maxbits, bool user, bool write, bool* fixed)	{
	int offset = (level * 9) + 12;
	ptr_t mask = (((1UL<<maxbits)-1) << offset);
	int idx = (vaddr & mask) >> offset, pmmref;
	ptr_t* pxd, e, val, res, *pp, noa, *npgd, oa;
	if(!entry_valid(pgd, idx))	return 0;
	e = pgd[idx];
	oa = (e & ARM64_MMU_OA_MASK);

	if(level > 0)	{
		res = _mmu_check_page_cloned((ptr_t*)(oa + cpu_linear_offset()), vaddr, level-1, 9, user, write, fixed);
		if(res > 0)	{
			noa = 0;
			pmmref = pmm_ref(oa);
			if(pmmref > 0)	{
				noa = mmu_copy_page((ptr_t*)(oa + cpu_linear_offset()));
				npgd = (ptr_t*)(noa + cpu_linear_offset());
				pmm_free(oa);
			}
			else	{
				npgd = pgd;
			}
			ARM64_MMU_SET_OA(npgd[idx], res);
			return noa;
		}
	}
	else	{
		if(write && ARM64_MMU_ENTRY_IS_VALID(e))	{
			val = ARM64_MMU_CLONE_AP_VAL(e);
			if((user && val == ARM64_MMU_ENTRY_AP_EL1_RW_EL0_RW) ||
				(!user && (val == ARM64_MMU_ENTRY_AP_EL1_RW_EL0_NONE) ||
				(val == ARM64_MMU_ENTRY_AP_EL1_RW_EL0_RW)))	{

				pmmref = pmm_ref(oa);
				if(pmmref > 0)	{
					if(pmmref > 1)	{
						// Copy full page
						noa = mmu_copy_page((ptr_t*)(oa + cpu_linear_offset()));
						ARM64_MMU_SET_OA(e, noa);
						pmm_free(oa);
					}
					// Restore original permission bits and set clone off
					ARM64_AP_SET(e, val);
					ARM64_MMU_CLONE_AP_CLEAR(e);
					ARM64_MMU_CLONE_CLEAR(e);
//					pgd[idx] = e;
					*fixed = true;
					return noa;

				}
				else	{ PANIC("pmmref was negative"); }
			}
		}
	}
	return 0;
}
*/


/*
static ptr_t* _mmu_check_pxd(ptr_t* pxd, int i, bool ptd, bool user, bool write)	{
	int val, pmmref;
	ptr_t oa, noa, vnoa, entry;
	
	entry = pxd[i];
	oa = (entry & ARM64_MMU_OA_MASK);
	if(write && ARM64_MMU_ENTRY_IS_VALID(entry))	{
		val = ARM64_MMU_CLONE_AP_VAL(entry);
		if((user && val == ARM64_MMU_ENTRY_AP_EL1_RW_EL0_RW) ||
			(!user && (val == ARM64_MMU_ENTRY_AP_EL1_RW_EL0_NONE) ||
			(val == ARM64_MMU_ENTRY_AP_EL1_RW_EL0_RW)))	{
			pmmref = pmm_ref(oa);
			if(pmmref > 0)	{
				if(pmmref > 1)	{
					// Copy full page
					noa = mmu_copy_page((ptr_t*)(oa + cpu_linear_offset()));
					ARM64_MMU_SET_OA(entry, noa);
					pmm_free(oa);
				}
				// Restore original permission bits and set clone off
				ARM64_AP_SET(entry, val);
				ARM64_MMU_CLONE_AP_CLEAR(entry);
				ARM64_MMU_CLONE_CLEAR(entry);
				pxd[i] = entry;
				goto finished;
			}
			else	{ PANIC("pmmref was negative"); }
		}
	}
	return (ptr_t*)(-1);
finished:
	isb(); dsb();
	return (ptr_t*)((pxd[i] & ARM64_MMU_OA_MASK) + cpu_linear_offset());
}

int mmu_check_page_cloned(ptr_t vaddr, bool user, bool write)	{
	int res;
	ptr_t _p;
	read_sysreg_ttbr0(_p);
	ptr_t* pgd = (ptr_t*)(_p + cpu_linear_offset());
	//ptr_t* pgd = find_pgd(vaddr);
	ptr_t* pud, * pmd, * ptd, * page;
	ASSERT(pgd);

#if ARM64_VA_BITS > 39
	int l0idx = vaddr2pgd(vaddr);
	pud = mmu_check_entry(pgd, l0idx, false);
	if(PTR_IS_ERR(pud))	return -1;
#endif

	int l1idx = vaddr2pud(vaddr);
	pmd = mmu_check_entry(pud, l1idx, false);
	if(PTR_IS_ERR(pmd))	return -1;

	int l2idx = vaddr2pmd(vaddr);
	ptd = mmu_check_entry(pmd, l2idx, false);
	if(PTR_IS_ERR(ptd))	return -1;

	int l3idx = vaddr2ptd(vaddr);
	page = _mmu_check_pxd(ptd, l3idx, true, user, write);
	if(PTR_IS_ERR(page))	return -1;

	// TLB will never hold an invalid entry, so it should not be necessary to
	// any TLB maintenance

	flush_tlb();
	isb(); dsb();
	return 0;
}


int _mmu_clone_table(ptr_t* pgdfrom, ptr_t* pgdto, int last)	{
	// We simply copy pgd on first clone
	// Actual real copy is handled on page faults
	int i;
	ptr_t val, oa, entry;
	for(i = 0; i < last; i++)	{
		entry = pgdfrom[i];
		if(ARM64_MMU_ENTRY_IS_VALID(entry) || ARM64_MMU_CLONED(entry))	{
			oa = entry & ARM64_MMU_OA_MASK;
			if(pmm_add_ref(oa) < 0)	{
				PANIC("Unable to increase pmm reference");
			}
			if(ARM64_MMU_ENTRY_IS_VALID(entry))	{
				entry |= ARM64_MMU_CLONE_BIT;
				entry &= ~(ARM64_MMU_ENTRY_VALID);
				pgdfrom[i] = entry;
			}
		}
		pgdto[i] = pgdfrom[i];
	}
	//for(i = last; i < ARM64_MMU_ENTRIES_PER_PAGE; i++)	pgdto[i] = 0;
	return 0;
}
*/
/*
int mmu_clone_fork(ptr_t* pgdto)	{
	int i, j, k, l, max1 = 0;
	uint64_t* pud, *pmd, *ptd;
	ptr_t* pgd = (ptr_t*)cpu_get_user_pgd();
	ptr_t tmp, entry, oa;
	ptr_t* n_pud, * n_pmd, * n_ptd;
#if ARM64_VA_BITS > 39
	max1 = (1 << (ARM64_VA_BITS - 39));
//	max1 -= 1;	// TODO: we reserve the last one for stack
	for(i = 0; i < max1; i++)	{
		pud = mmu_check_entry(pgd, i, false);
		if(!pud)	continue;
		tmp = mmu_create_table();
		pgdto[i] = pgd[i] & ~(ARM64_MMU_OA_MASK) | tmp;
		n_pud = (ptr_t*)(tmp + cpu_linear_offset());

#else
		pud = pgd
#endif
		for(j = 0; j < ARM64_MMU_ENTRIES_PER_PAGE; j++)	{
			pmd = mmu_check_entry(pud, j, false);
			if(!pmd)	continue;
			tmp = mmu_create_table();
			n_pud[j] = pud[j] & ~(ARM64_MMU_OA_MASK) | tmp;
			n_pmd = (ptr_t*)(tmp + cpu_linear_offset());

			for(k = 0; k < ARM64_MMU_ENTRIES_PER_PAGE; k++)	{
				ptd = mmu_check_entry(pmd, k, false);
				if(!ptd)	continue;
				tmp = mmu_create_table();
				n_pmd[k] = pmd[k] & ~(ARM64_MMU_OA_MASK) | tmp;
				n_ptd = (ptr_t*)(tmp + cpu_linear_offset());

				for(l = 0; l < ARM64_MMU_ENTRIES_PER_PAGE; l++)	{
					if(ptd[l] & ARM64_MMU_ENTRY_NEXT_PAGE)	{
						oa = ptd[l] & ARM64_MMU_OA_MASK;
						entry = ptd[l];
						if(ARM64_MMU_ENTRY_WRITABLE(entry))	{
							// Store real AP bits in some of the available bits and set cloned flag
							tmp = (entry & ARM64_AP_MASK) >> ARM64_AP_OFFSET;
							entry &= ~(ARM64_AP_MASK);
							entry |= (tmp << ARM64_MMU_CLONE_AP_OFFSET);
							entry |= ARM64_MMU_CLONE_BIT;

							// Need to change AP-bits to readable by appropriate EL
							// entry is writable, so only two valid entries
							ptr_t apbits = (tmp == ARM64_MMU_ENTRY_AP_EL1_RW_EL0_RW) ?
								ARM64_MMU_ENTRY_AP_EL1_RO_EL0_RO :
								ARM64_MMU_ENTRY_AP_EL1_RO_EL0_NONE;

							ARM64_AP_SET(entry, apbits);
						}
						// We always need to add ref count because we might change
						// the permission in the future
						pmm_add_ref(oa);

						// Both new and old entry is the same
						n_ptd[l] = ptd[l] = entry;
					}
				}
			}
		}
#if ARM64_VA_BITS > 39
	}
#endif
	flush_tlb();
	return OK;
}
*/
/*
int mmu_clone_fork(ptr_t* pgdto)	{
	ptr_t* pgd = (ptr_t*)cpu_get_user_pgd();
	// TODO:
	// - Currently stack is at the last entry, so we use this as a quick hack
	//   to avoid copying cloning stack of other procs
	// - This hack can be avoided by:
	//   - Using the same stack as previous thread
	//   - We must then remove the current assumptions about where ustack is
	return _mmu_clone_table(pgd, pgdto, ARM64_MMU_ENTRIES_PER_PAGE-1);
}
*/
