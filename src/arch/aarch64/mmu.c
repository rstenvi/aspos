#include "aarch64.h"
#include "arch.h"
#include "kernel.h"
#include "mmu.h"
#include "tlb.h"

ptr_t offset_dma = 0;

#define SHIFT(lvl)  (12+((3-(lvl))*9))
#define VADDR_TO_IDX(vaddr,lvl)    (((vaddr) & (511UL << SHIFT(lvl))) >> SHIFT(lvl));
//#define VADDR_TO_IDX(vaddr, level) ((vaddr >> (12+((3-level)*9))) & 511)

#define PGD_ASSERT(pgd) \
	BUG_ASSERT(ADDR_KERNEL((ptr_t)pgd)); \
	BUG_ASSERT(ALIGNED_ON_POW2((ptr_t)pgd,PAGE_SIZE))


#define MMU_MAX_LEVEL (3)
//extern uint64_t kernel_pgd;
extern uint64_t kernel_pud;
extern uint64_t kernel_pmd;
extern uint64_t kernel_ptd;
extern uint64_t user_pgd;

static ptr_t mmu_copy_page(ptr_t page);

void __no_ubsan __attribute__((__section__(".init.text"))) mmu_early_init(ptr_t real_load, ptr_t kernfirst)	{
	int i;
	//uint64_t* l1 = &user_pgd;
	uint64_t* l1 = (uint64_t*)&user_pgd;
	real_load = GET_ALIGNED_DOWN_POW2(real_load, PAGE_SIZE);
	uint64_t start_load = GET_ALIGNED_DOWN_POW2(real_load, GB * MMU_ENTRIES_PER_PAGE);
	for(i = 0; i < MMU_ENTRIES_PER_PAGE; i++) {
		// Each entry maps in 1GB of memory
		WRITE_ONCE(l1[i], (start_load + ((uint64_t)i * GB)) | PTE_ENTRY_KERNEL_RWX | MMU_ENTRY_NEXT_BLK);
	}

	smp_mb();

	write_sysreg_ttbr0((uint64_t)l1);

	isb();

	write_sysreg_tcr(
		ARM64_REG_TCR_T0SZ_INIT |
		ARM64_REG_TCR_T1SZ |
		ARM64_REG_TCR_TG0 |
		ARM64_REG_TCR_TG1 |
		ARM64_REG_TCR_IPS |
		ARM64_REG_TCR_A1_EL0
	);


	ptr_t kernreal = kernfirst + IMAGE_LOAD;
	kernreal = GET_ALIGNED_DOWN_POW2(kernreal, 2*MB);

	int l1idx, l2idx, l1idx2;
	l1 = &kernel_pud;
	uint64_t* l2 = &kernel_pmd;
//	uint64_t* l3 = &kernel_ptd;



	l1idx = VADDR_TO_IDX(kernreal, 1);
	l2idx = VADDR_TO_IDX(kernreal, 2);
	int l2idxlast = VADDR_TO_IDX(kernreal + (32 * MB), 2);

	WRITE_ONCE(l1[l1idx], (uint64_t)l2 | MMU_ENTRY_NEXT_TBL);

//	kernfirst += IMAGE_LOAD;

	ptr_t rload = GET_ALIGNED_DOWN_POW2(real_load, 2*MB);
	for(i = l2idx; i < l2idxlast; i++)	{
		ptr_t addr = (rload + ((i-l2idx) * 2 * MB));
		WRITE_ONCE(l2[i], addr | MMU_ENTRY_NEXT_BLK | MMU_ENTRY_ATTR_NORMAL | MMU_SHAREABLE_INNER | MMU_ENTRY_KERNEL_RWX);
	}

	l1idx2 = VADDR_TO_IDX(ARM64_VA_LINEAR_START, 1);
	//ASSERT(l1idx2 != l1idx);

	// Map in a few GB of linear region
	for(i = l1idx2; i < l1idx2 + 4; i++)	{
		ptr_t addr = ((uint64_t)(i-l1idx2) * GB);
		WRITE_ONCE(l1[i], addr | MMU_ENTRY_NEXT_BLK | MMU_ENTRY_KERNEL_RW | MMU_ENTRY_ATTR_NOCACHE | MMU_SHAREABLE_INNER);

	}
	// Invalid for now
	write_sysreg_ttbr1(l1);
	isb();

	uint64_t mair = 0xff00ffUL;
	asm volatile("msr mair_el1, %0" : : "r"(mair));

	smp_mb();
	isb();
}

static inline ptr_t find_pgd(ptr_t vaddr)   {
	if(ADDR_USER(vaddr))    {
		return cpu_get_user_pgd();
	}
	else    {
		return cpu_get_pgd();
	}
}

static ptr_t _mmu_prot_to_flags(bool user, enum MEMPROT prot)   {
	ptr_t ret = MMU_ENTRY_ATTR_NORMAL | MMU_SHAREABLE_INNER;

	ret |= (user) ? get_asid() | MMU_ENTRY_NG : 0;
	switch(prot)	{
		case PROT_NONE:
			break;
		case PROT_RO:
			ret |= (user) ? MMU_ENTRY_USER_RO : MMU_ENTRY_KERNEL_RO;
			break;
		case PROT_RW:
			ret |= (user) ? MMU_ENTRY_USER_RW : MMU_ENTRY_KERNEL_RW;
			break;
		case PROT_RX:
			ret |= (user) ? MMU_ENTRY_USER_RX : MMU_ENTRY_KERNEL_RX;
			break;
		case PROT_RWX:
			ret |= (user) ? MMU_ENTRY_USER_RWX : MMU_ENTRY_KERNEL_RWX;
			break;
		default:
			logw("Unsupported value: %i\n", prot);
			break;
	}
	return ret;
}
static ptr_t mmu_create_table() {
	ptr_t pt = pmm_alloc(1);
	ASSERT_TRUE(pt != 0, "Unable to allocate page table");
	memset((void*)(pt + cpu_linear_offset()), 0x00, PAGE_SIZE);
	return pt;
}
static ptr_t mmu_check_entry(ptr_t _pt, int idx, bool create)	{
	ptr_t ret, *pt = (ptr_t*)_pt;
	if(! entry_valid(pt, idx))  {
		if(create)  {
			ret = mmu_create_table();
			WRITE_ONCE(pt[idx], ret | MMU_ENTRY_NEXT_TBL);
		}
		else	{
			return 0;
		}
	}
	else	{
		if(entry_block(pt, idx)) {
			ASSERT(false);
		}
		ret = READ_ONCE(pt[idx]) & MMU_OA_MASK;
	}
	return ret + cpu_linear_offset();
}
static int mmu_create_entry(ptr_t pgd, ptr_t addr, ptr_t oa, ptr_t flag)	{
	int l1idx = VADDR_TO_IDX(addr, 1);
	int l2idx = VADDR_TO_IDX(addr, 2);
	int l3idx = VADDR_TO_IDX(addr, 3);

	ptr_t pmd, ptd;


	pmd = mmu_check_entry(pgd, l1idx, true);
	ptd = mmu_check_entry(pmd, l2idx, true);


	ptr_t* tbl = (ptr_t*)ptd;
	WRITE_ONCE(tbl[l3idx], oa | MMU_ENTRY_NEXT_PAGE | flag);
	return 0;
}

int _mmu_map_pages(ptr_t pgd, ptr_t vaddr, ptr_t flags, int pages)	{
	int i, res;
	ptr_t add = 0, paddr;
	for(i = 0; i < pages; i++)	{
		paddr = pmm_alloc(1);

		add = (uint64_t)i * PAGE_SIZE;
		res = mmu_create_entry(pgd, vaddr + add, paddr, flags);
		ASSERT(res == 0);
	}
	return 0;
}
int mmu_map_pages(ptr_t vaddr, int pages, enum MEMPROT prot)	{
	ptr_t pgd = find_pgd(vaddr);
	ptr_t flag = _mmu_prot_to_flags(ADDR_USER(vaddr), prot);
	return _mmu_map_pages(pgd, vaddr, flag, pages);
}
int mmu_map_page(ptr_t vaddr, enum MEMPROT prot) {
	return mmu_map_pages(vaddr, 1, prot);
}

int mmu_map_pages_pgd(ptr_t pgd, ptr_t vaddr, int pages, enum MEMPROT prot)	{
	ptr_t flag = _mmu_prot_to_flags(ADDR_USER(vaddr), prot);
	return _mmu_map_pages(pgd, vaddr, flag, pages);
}
int mmu_map_page_pgd(ptr_t pgd, ptr_t vaddr, enum MEMPROT prot)	{
	return mmu_map_pages_pgd(pgd, vaddr, 1, prot);
}

int _mmu_map_pages_fixed(ptr_t vaddr, ptr_t paddr, int pages, ptr_t flags)	{
	ptr_t pgd = (ptr_t)cpu_get_pgd(), add;
	int i, res;
	for(i = 0; i < pages; i++)	{
		add = (uint64_t)i * PAGE_SIZE;
		res = mmu_create_entry(pgd, vaddr + add, paddr + add, flags);
		ASSERT(res == 0);
	}
	return 0;
}

ptr_t mmu_map_dma(ptr_t paddr, ptr_t stop)	{
	paddr = GET_ALIGNED_DOWN_POW2(paddr, PAGE_SIZE);
	stop = GET_ALIGNED_UP_POW2(stop, PAGE_SIZE);
	int pages = (stop - paddr) / PAGE_SIZE;

	ptr_t vaddr = ARM64_VA_KERNEL_DMA_START + offset_dma;
	offset_dma += (stop - paddr);

#if defined(CONFIG_KASAN)
	kasan_mark_valid(vaddr, pages * PAGE_SIZE);
#endif

	//ptr_t vaddr = cpu_linear_offset() + paddr;

	ASSERT(_mmu_map_pages_fixed(vaddr, paddr, pages, MMU_ENTRY_ATTR_DMA | MMU_ENTRY_KERNEL_RW) == 0);
	return vaddr;
}

ptr_t mmu_map_shared(size_t pages, enum MEMPROT prot, bool mapin)	{
	ptr_t vaddr = ARM64_VA_KERNEL_DMA_START + offset_dma;
	offset_dma += (pages * PAGE_SIZE);

	if(mapin)	{
		ptr_t flags = _mmu_prot_to_flags(true, prot);
		ptr_t paddr = pmm_alloc(pages);
		ASSERT(_mmu_map_pages_fixed(vaddr, paddr, pages, flags) == 0);
	}
	return vaddr;
}




















/*
* Slow when unmapping several pages, should at least be inlined.
*/
/*
static void _mmu_unmap_page(ptr_t addr, ptr_t pgd)	{
	int l1idx = VADDR_TO_IDX(addr, 1);
	int l2idx = VADDR_TO_IDX(addr, 2);
	int l3idx = VADDR_TO_IDX(addr, 3);
	ptr_t pmd, ptd;

	pmd = mmu_check_entry(pgd, l1idx, false);
	if(pmd == 0)	return;

	ptd = mmu_check_entry((ptr_t)pmd, l2idx, false);
	if(ptd == 0)	return;

	ptr_t* tbl = (ptr_t*)ptd;
	ptr_t e = READ_ONCE(tbl[l3idx]);
	ptr_t oa = e & MMU_OA_MASK;
	if(oa != 0)	{
		WRITE_ONCE(tbl[l3idx], 0);
		tlbflush_vaddr(addr);
		pmm_free(oa);
	}
}*/
static void _mmu_free_page(ptr_t _tbl, int idx, ptr_t addr)	{
	ptr_t* tbl = (ptr_t*)_tbl;
	ptr_t e = READ_ONCE(tbl[idx]);
	ptr_t oa = e & MMU_OA_MASK;
	if(oa != 0)	{
		WRITE_ONCE(tbl[idx], 0);
		tlbflush_vaddr(addr);
		pmm_free(oa);
	}
}


void mmu_unmap_pages_pgd(ptr_t pgd, ptr_t vaddr, size_t pages) {
	size_t i, j, k, l1i, l2i, l3i, nl1i, nl2i, nl3i;
	ptr_t pmd, ptd;

	ptr_t lastvaddr = vaddr + ((ptr_t)pages * PAGE_SIZE);
	l1i = VADDR_TO_IDX(vaddr, 1);
	l2i = VADDR_TO_IDX(vaddr, 2);
	l3i = VADDR_TO_IDX(vaddr, 3);

	nl1i = VADDR_TO_IDX(lastvaddr, 1);
	nl2i = VADDR_TO_IDX(lastvaddr, 2);
	nl3i = VADDR_TO_IDX(lastvaddr, 3);

	ptr_t faddr = 0;
	for(i = l1i; i <= nl1i; i++)	{
		pmd = mmu_check_entry(pgd, i, false);
		if(pmd == 0)	continue;

		for(j = l2i; j < nl2i; j++)	{
			ptd = mmu_check_entry(pmd, j, false);
			if(ptd == 0)	continue;

			for(k = l3i; k < nl3i; k++)	{
				faddr = ((ptr_t)i << 30) | ((ptr_t)j << 21) | ((ptr_t)k << 12);
				_mmu_free_page(ptd, k, faddr);
			}
		}
	}
}




// ------------------------------ API ------------------------------------ //



ptr_t mmu_va_to_pa_pgd(ptr_t pgd, ptr_t vaddr, ptr_t* entry)	{
	int l1idx = VADDR_TO_IDX(vaddr, 1);
	int l2idx = VADDR_TO_IDX(vaddr, 2);
	int l3idx = VADDR_TO_IDX(vaddr, 3);
	uint64_t pmd, ptd;

	pmd = mmu_check_entry(pgd, l1idx, false);
	if(pmd == 0)	return 0;

	ptd = mmu_check_entry(pmd, l2idx, false);
	if(ptd == 0)	return 0;

	ptr_t* tbl = (ptr_t*)ptd;
	ptr_t e = READ_ONCE(tbl[l3idx]);
	if(entry != NULL)	*entry = e & ~(MMU_OA_MASK);

	// We want to include offset VA
	return (e & MMU_OA_MASK) | (vaddr & MMU_OFFSET_MASK);
}


ptr_t mmu_va_to_pa(ptr_t vaddr)	{
	ptr_t pgd = (ptr_t)find_pgd(vaddr);
	return mmu_va_to_pa_pgd(pgd, vaddr, NULL);
}

bool mmu_page_mapped(ptr_t addr)	{
	return mmu_va_to_pa(addr) != 0;
}
bool mmu_addr_mapped(ptr_t addr, size_t len, int type)	{
	ptr_t res, end, start, i;

	start = addr;
	end = start + len;

	ALIGN_DOWN_POW2(start, PAGE_SIZE);
	ALIGN_UP_POW2(end, PAGE_SIZE);
	for(i = addr; i < end; i += PAGE_SIZE)	{
		res = mmu_va_to_pa(i);
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

/*
static bool access_valid(int ap, bool user, bool write)	{
	switch(ap)	{
	case MMU_ENTRY_AP_EL1_RW_EL0_NONE:
		return !user;
	case MMU_ENTRY_AP_EL1_RW_EL0_RW:
		return true;
	case MMU_ENTRY_AP_EL1_RO_EL0_NONE:
		return (!user && !write);
	case MMU_ENTRY_AP_EL1_RO_EL0_RO:
		return (!write);
	default:
		return false;
	}
}
*/
ptr_t _mmu_fix_table(ptr_t pxd, int idx, ptr_t entry) {
    PGD_ASSERT(pxd);
    ptr_t oa = pxd - cpu_linear_offset(), noa;
    int pmmref;
    pmmref = pmm_ref(oa);
    if(pmmref > 1)  {
        noa = mmu_copy_page(pxd);
        pmm_free(oa);
        pxd = noa + cpu_linear_offset();
    }
	ptr_t* _p = (ptr_t*)pxd;
    WRITE_ONCE(_p[idx], entry);
    return pxd;
}
// Free up all user-space memory
/*
void mmu_unmap_user(ptr_t pgd)	{
	logi("TODO: Ensure that user region is cleaned up\n");
	write_sysreg_ttbr0(0);
	isb();
}
*/


void mmu_unmap_page(ptr_t vaddr) {
	ptr_t pgd = cpu_get_pgd();
	return mmu_unmap_pages_pgd(pgd, vaddr, 1);
}


void* mmu_memset(ptr_t pgd, void* _s, int c, size_t n)	{
	PGD_ASSERT(pgd);
	ASSERT_USER_MEM(_s, n);
	ptr_t oa;
	size_t copied = 0;
	ptr_t vafrom = (ptr_t)_s;
	while(copied < n)	{
		oa = mmu_va_to_pa_pgd(pgd, vafrom + copied, NULL);
		if(!oa)	return NULL;

		// Find number of bytes we can copy
		size_t tocopy = PAGE_SIZE;
		if(!ALIGNED_PAGE(oa))	{
			tocopy = GET_ALIGNED_UP_POW2(oa, PAGE_SIZE) - oa;
		}

		void* s = (void*)(oa + cpu_linear_offset());
		memset(s, c, tocopy);
		copied += tocopy;
	}
	return (void*)(_s + copied);
}
void* mmu_memcpy(ptr_t pgd, void* _dest, const void* src, size_t n)	{
	PGD_ASSERT(pgd);
	//ASSERT_KERNEL_MEM(src, n);
	ASSERT_USER_MEM(_dest, n);
	ptr_t oa, vato = (ptr_t)_dest;
	size_t copied = 0;
	while(copied < n)	{
		oa = mmu_va_to_pa_pgd(pgd, vato + copied, NULL);
		if(!oa)	return NULL;

		// Find number of bytes we can copy
		size_t tocopy = PAGE_SIZE;
		if(!ALIGNED_PAGE(oa))	{
			tocopy = GET_ALIGNED_UP_POW2(oa, PAGE_SIZE) - oa;
		}
		if(tocopy > n) {
			tocopy = n;
		}
		void* dest = (void*)(oa + cpu_linear_offset());
		memcpy(dest, (src + copied), tocopy);
		copied += tocopy;
	}
	return (void*)(_dest + copied);
}
void* mmu_memcpy_user(ptr_t pgd, void* _dest, const void* _src, size_t n)	{
	PGD_ASSERT(pgd);
	ASSERT_USER_MEM(_src, n);
	ASSERT_USER_MEM(_dest, n);

	ptr_t oa1 = mmu_va_to_pa_pgd(pgd, (ptr_t)_dest, NULL);
	if(!oa1)	return NULL;
	void* dest = (void*)(oa1 + cpu_linear_offset());

	ptr_t oa2 = mmu_va_to_pa_pgd(pgd, (ptr_t)_src, NULL);
	if(!oa2)	return NULL;
	void* src = (void*)(oa2 + cpu_linear_offset());

	return memcpy(dest, src, n);

}
void* mmu_strcpy(ptr_t pgd, void* dest, const void* src)	{
	PGD_ASSERT(pgd);
	ASSERT_KERNEL(src);
	ASSERT_USER(dest);
	int len = strlen(src);
	return mmu_memcpy(pgd, dest, src, len+1);
}
int mmu_put_u64(ptr_t pgd, ptr_t* dest, ptr_t val)	{
	PGD_ASSERT(pgd);
	ASSERT_USER(dest)
	mmu_memcpy(pgd, dest, &val, 8);
	return OK;
}

static int _mmu_clone_table(ptr_t _tbl, int level);

static ptr_t _fix_cloned_tbl(ptr_t _tbl, ptr_t vaddr, int level, bool write, bool* fixed)	{
	ptr_t* tbl = (ptr_t*)_tbl, entry, oa, roa;
	int idx = VADDR_TO_IDX(vaddr, level);
	*fixed = false;

	entry = READ_ONCE(tbl[idx]);
	oa = entry & MMU_OA_MASK;
	if(oa == 0)	return 0;

	roa = oa;

	if(FLAG_SET(entry, MMU_CLONE_BIT))	{
		if(FLAG_SET(entry, MMU_ENTRY_VALID))	{
			// Should only trigger a page fault on
			if(write)	{
				ASSERT(level == MMU_MAX_LEVEL);
				AP_SET(entry, MMU_ENTRY_AP_EL1_RW_EL0_RW);
				entry &= ~(MMU_CLONE_BIT);
				*fixed = true;
			}
		} else {
			entry &= ~(MMU_CLONE_BIT);
			entry |= MMU_ENTRY_VALID;
			*fixed = true;
		}

		if(*fixed)	{
			// If physical address has multiple references to it
			// we must allocate new page, but only if it references a
			// table or it's a write operation
			if((level < MMU_MAX_LEVEL || write) && pmm_ref(oa) > 1)	{
				ptr_t ntbl = pmm_allocz(1);
				ptr_t* vntbl = (ptr_t*)(ntbl + cpu_linear_offset());
				ptr_t voa = oa + cpu_linear_offset();
				if(level < MMU_MAX_LEVEL)	{
					_mmu_clone_table(voa, level + 1);
				}
				// If this is the last level we simply copy the page
				memcpy((void*)vntbl, (void*)voa, PAGE_SIZE);

				// Need to change OA on entry
				entry = entry & ~(MMU_OA_MASK);
				entry |= ntbl;
				roa = ntbl;		// Used in return value

				// Will decrement the reference
				pmm_free(oa);
			}

			// Write new entry to table
			WRITE_ONCE(tbl[idx], entry);
		}
// 		else {
// 			logd("Not fixed\n");
// 		}
	}
	return roa + cpu_linear_offset();
}

bool mmu_fix_addr_pgd(ptr_t pgd, ptr_t vaddr, bool write)	{
	int i;
	bool fixed, rfixed = false;
	ptr_t tbl = pgd;

	// TODO: Start at 4 if VA > 39
	for(i = 1; i <= MMU_MAX_LEVEL; i++)	{
		tbl = _fix_cloned_tbl(tbl, vaddr, i, write, &fixed);
		if(tbl == 0)	return false;
		if(fixed)	rfixed = true;
	}
	return rfixed;
}

bool mmu_fix_translation_fault(ptr_t _vaddr, bool write)	{
	ptr_t vaddr = GET_ALIGNED_DOWN_POW2(_vaddr, PAGE_SIZE);
	ptr_t tbl = cpu_get_user_pgd();
	return mmu_fix_addr_pgd(tbl, vaddr, write);
}


// TODO: Need to implement these
int mmu_copy_cloned_pages(ptr_t vaddr, int pages, ptr_t* pgd1, ptr_t* pgd2)	{
	PANIC("");
	return OK;
}
static int _mmu_clone_table(ptr_t _tbl, int level)	{
	ptr_t oa, entry, *tbl = (ptr_t*)_tbl;
	int i;
	bool valid;
	for(i = 0; i < MMU_ENTRIES_PER_PAGE; i++)	{
		entry = READ_ONCE(tbl[i]);
		if(entry)	{
			valid = false;
			oa = entry & MMU_OA_MASK;

			// If it's not valid, we simply add the reference
			// on the physical page
			if(FLAG_SET(entry, MMU_CLONE_BIT))	{
				// Has already been cloned, just need to increment ref
				valid = true;
			} else if(FLAG_SET(entry, MMU_ENTRY_VALID)) {
				if(level != MMU_MAX_LEVEL && FLAG_SET(entry, MMU_ENTRY_TABLE)) {
					entry |= MMU_CLONE_BIT;
					entry &= ~(MMU_ENTRY_VALID);
					valid = true;
				} else if(level == MMU_MAX_LEVEL && FLAG_SET(entry, MMU_ENTRY_PAGE)) {
					// Last level pages always remains valid as readable pages
					if(AP_GET(entry) == MMU_ENTRY_AP_EL1_RW_EL0_RW)	{
						AP_SET(entry, MMU_ENTRY_AP_EL1_RO_EL0_RO);
						entry |= MMU_CLONE_BIT;
					}
					// If it's RO we simply increase the ref
					valid = true;
				} else {
					// Block entries are not supported
					PANIC("Unhandled");
				}
			}

			// If we handled a clone, we must increase ref on physical page
			if(valid)	{
				pmm_add_ref(oa);
				WRITE_ONCE(tbl[i], entry);
			}
		}
	}
	return OK;
}
int mmu_clone_fork(ptr_t pgdto)	{
	PGD_ASSERT(pgdto);
	ptr_t pgdfrom = cpu_get_user_pgd();
	// TODO: Adjust level if > 39b
	int level = 1;

	// Clone PGD only
	_mmu_clone_table(pgdfrom, level);
	memcpy((void*)pgdto, (void*)pgdfrom, PAGE_SIZE);
	return OK;
}
int mmu_unmap_pgd(ptr_t pgd)	{
	//PANIC("");

	// Re-use the existing functionality meant for unmapping mmaped data
	// Regardless of user- or kernel-mode we unmap from 0 - 1 << VA_BITS
	// This works because we include the PGD
	mmu_unmap_pages_pgd(pgd, 0, (1UL << ARM64_VA_BITS) / PAGE_SIZE);
	smp_mb();
	//write_sysreg_ttbr0(0);
	isb();

	return 0;
}
static ptr_t mmu_copy_page(ptr_t page)	{
	// So that we don't accidentally pass a physical page to this function
	ASSERT(page >= cpu_linear_offset());
	ptr_t pa = pmm_alloc(1);
	memcpy((void*)(pa + cpu_linear_offset()), (void*)page, PAGE_SIZE);
	return pa;
//	PANIC("");
}


/*
void mmu_unmap_pages(ptr_t vaddr, int pages) {
	PANIC("");
}
ptr_t mmu_find_available_space(ptr_t* pgd, int pages, enum MEMPROT prot, bool mapin)	{
	PANIC("");
}
ptr_t mmu_create_user_stack(ptr_t* pgd, int pages)	{
	PANIC("");
}
int _mmu_clone_fork(ptr_t* from, int max, int table)	{
	PANIC("");
	return 0;
}
int mmu_map_page_pgd_oa_entry(ptr_t pgd, ptr_t vaddr, ptr_t oa, ptr_t entry) {
	PANIC("");
	return 0;
}
int mmu_double_map_pages(ptr_t pgdfrom, ptr_t pgdto, ptr_t _vaddr_from, ptr_t _vaddr_to, int pages)	{
	PANIC("");
}
int mmu_double_unmap_pages(ptr_t pgdfrom, ptr_t pgdto, ptr_t _vaddr_from, ptr_t _vaddr_to, int pages)	{
	PANIC("");
}
ptr_t mmu_find_free_pages(ptr_t pgd, int startpage, int pages)	{
	PANIC("");
}
bool mmu_check_page_cloned_pgd(ptr_t pgd, ptr_t vaddr, uint32_t flags)	{
	PGD_ASSERT(pgd);
	int pmmref;
	ptr_t pmd, ptd, page, e, val, oa, noa;
	ASSERT(pgd);
	bool user = FLAG_SET(flags, CHK_CLONE_FLAG_USER);
	//bool instr = FLAG_SET(flags, CHK_CLONE_FLAG_INSTR);
	bool write = FLAG_SET(flags, CHK_CLONE_FLAG_WRITE);
	bool copy = FLAG_SET(flags, CHK_CLONE_FLAG_COPY);
	bool noperm = FLAG_SET(flags, CHK_CLONE_FLAG_NOPERM);

// #if ARM64_VA_BITS > 39
// 	int l0idx = vaddr2pgd(vaddr);
// 	pud = mmu_check_entry(pgd, l0idx, false);
// 	if(PTR_IS_ERR(pud))	return false;
// #endif

	int l1idx = VADDR_TO_IDX(vaddr, 1);
	int l2idx = VADDR_TO_IDX(vaddr, 2);
	int l3idx = VADDR_TO_IDX(vaddr, 3);

	pmd = mmu_check_entry(pgd, l1idx, false);
	if(!pmd)	return false;

	ptd = mmu_check_entry(pmd, l2idx, false);
	if(!ptd)	return false;

	page = mmu_check_entry(ptd, l3idx, false);
	if(!page)	return false;

	ptr_t* tbl = (ptr_t*)ptd;
	e = READ_ONCE(tbl[l3idx]);
	if(MMU_ENTRY_IS_VALID(e))	{
		if(!MMU_CLONED(e))	{
			return false;
		}
		if(!noperm && !write)		return false;

		// Get real AP value and check if access is valid
		val = MMU_CLONE_AP_VAL(e);
		if(!noperm && !access_valid(val, user, write))	return false;

		// Access is valid, we must fix ptd
		oa = (e & MMU_OA_MASK);
		pmmref = pmm_ref(oa);
		if(pmmref > 0)	{
			if(copy && pmmref > 1)	{
				// If there are multiple references to this page table, we must
				// allocate a new one and copy the old one
				noa = mmu_copy_page(page);
				MMU_SET_OA(e, noa);
				pmm_free(oa);
			}
			// Restore original permission bits and set clone off
			MMU_CLONE_AP_CLEAR(e);
			MMU_CLONE_CLEAR(e);
			AP_SET(e, val);
		}
		else	{
			PANIC("pmmref <= 0");
		}

		// We must now propogate the fix throughout the upper page tables

		ptr_t pxd;
		pxd = _mmu_fix_table(ptd, l3idx, e);
		if(pxd != ptd)	{
			e = READ_ONCE(((ptr_t*)pmd)[l2idx]);
			//e = pmd[l2idx];
			MMU_SET_OA(e, (ptr_t)pxd - cpu_linear_offset());
			pxd = _mmu_fix_table(pmd, l2idx, e);
			if(pxd != pmd)	{
				//e = pud[l1idx];
				e = READ_ONCE(((ptr_t*)pud)[l1idx]);
				MMU_SET_OA(e, (ptr_t)pxd - cpu_linear_offset());
//#if ARM64_VA_BITS <= 39
				//pud[l1idx] = e;
				WRITE_ONCE(((ptr_t*)pud)[l1idx], e);
//#else
//				pxd = _mmu_fix_table(pud, l1idx, e);
//				if(pxd != pud)	{
//					e = pgd[l0idx];
//					MMU_SET_OA(e, (ptr_t)pxd - cpu_linear_offset());
//					pgd[l0idx] = e;
//				}
//#endif

			}
		}
	}
	else	{
		return false;
	}
	// TLB will never hold an invalid entry, so it should not be necessary to
	// any TLB maintenance
	return true;
}

bool mmu_check_page_cloned(ptr_t vaddr, bool user, bool instr, bool write)	{
	ptr_t pgd = find_pgd(vaddr);
	uint32_t flags = 0;
	flags |= (user) ? CHK_CLONE_FLAG_USER : 0;
	flags |= (instr) ? CHK_CLONE_FLAG_INSTR : 0;
	flags |= (write) ? CHK_CLONE_FLAG_WRITE : 0;
	flags |= CHK_CLONE_FLAG_COPY;
	return mmu_check_page_cloned_pgd(pgd, vaddr, flags);
}
*/
