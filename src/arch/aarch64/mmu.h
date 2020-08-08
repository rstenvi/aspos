#ifndef __MMU_H
#define __MMU_H

static inline int vaddr2pgd(ptr_t vaddr)	{
	return (int)( ((vaddr & ((ARM64_MMU_ENTRIES_PER_PAGE-1) << 39)) >> 39 ) );
}
static inline int vaddr2pud(ptr_t vaddr)	{
	return (int)( ((vaddr & ((ARM64_MMU_ENTRIES_PER_PAGE-1) << 30)) >> 30 ) );
}

static inline int vaddr2pmd(ptr_t vaddr)	{
	return (int)( ((vaddr & ((ARM64_MMU_ENTRIES_PER_PAGE-1) << 21)) >> 21 ) );
}
static inline int vaddr2ptd(ptr_t vaddr)	{
	return (int)( ((vaddr & ((ARM64_MMU_ENTRIES_PER_PAGE-1) << 12)) >> 12 ) );
}
static inline int vaddr2offset(ptr_t vaddr) {
	return (int)( (vaddr & ((1<<ARM64_PTE_OFFSET_BITS)-1)) );
}
static inline bool entry_valid(uint64_t* pt, int idx)	{
	return (pt[idx] & ARM64_MMU_ENTRY_VALID) == ARM64_MMU_ENTRY_VALID;
}
static inline bool entry_block(uint64_t* pt, int idx)	{
	return (pt[idx] & 2) == 0;
}
static inline ptr_t phys_to_linear(ptr_t addr) { return (addr + ARM64_VA_LINEAR_START); }
static inline ptr_t linear_to_phys(ptr_t addr) { return (addr - ARM64_VA_LINEAR_START); }

#endif
