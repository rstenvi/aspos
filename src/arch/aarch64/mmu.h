#ifndef __MMU_H
#define __MMU_H

#include "kernel.h"
#include "aarch64.h"

#define TTBR_ASID_OFFSET (48)
#define TTBR_ASID_MASK (0xffffUL << TTBR_ASID_OFFSET)
static inline ptr_t get_asid(void) {
	ptr_t asid = current_pid();
	if(asid == (ptr_t)-1)	return 0;

	ASSERT(asid < 0x100);
	asid <<= TTBR_ASID_OFFSET;
	return asid;
}

#define MMU_SHAREABLE_INNER (0b11UL << 8)
#define MMU_SHAREABLE_OUTER (0b10UL << 8)
#define MMU_SHAREABLE_NON   (0b00UL << 8)

#define MMU_CLONE_BIT_OFFSET  (48)
#define MMU_CLONE_MASK        (0b1UL << MMU_CLONE_BIT_OFFSET)
#define MMU_CLONE_AP_OFFSET   (49)
#define MMU_CLONE_AP_MASK     (0b11UL << MMU_CLONE_AP_OFFSET)
#define MMU_CLONE_AP_VAL(n)   ((n >> MMU_CLONE_AP_OFFSET) & 0b11)
#define MMU_CLONE_AP_CLEAR(n) (n &= ~(MMU_CLONE_AP_MASK))
#define MMU_CLONE_CLEAR(n)    (n &= ~(MMU_CLONE_MASK))

#define MMU_CLONE_BIT        (1UL << MMU_CLONE_BIT_OFFSET)
#define MMU_CLONED(entry)    (entry & MMU_CLONE_BIT)
#define MMU_CLONE_OFF(entry) (entry &= ~(MMU_CLONE_BIT))

#define MMU_ENTRY_VALID           (1UL)
#define MMU_ENTRY_INVALID         (0UL)
#define MMU_ENTRY_IS_VALID(entry) FLAG_SET(entry, MMU_ENTRY_VALID)
#define MMU_ENTRY_TABLE           (1UL << 1)
#define MMU_ENTRY_PAGE            (1UL << 1)


#define AP_OFFSET (6)
#define AP_MASK (0b11 << AP_OFFSET)
#define AP_GET(n) ((n & AP_MASK) >> AP_OFFSET)
#define AP_SET(n,v) \
    n &= ~(AP_MASK); \
    n |= (v << AP_OFFSET) & AP_MASK

#define MMU_ENTRY_AP_EL1_RW_EL0_NONE (0UL)
#define MMU_ENTRY_AP_EL1_RW_EL0_RW   (1UL)
#define MMU_ENTRY_AP_EL1_RO_EL0_NONE (2UL)
#define MMU_ENTRY_AP_EL1_RO_EL0_RO   (3UL)

// Hierarchical lookup of tables, limit early
#define MMU_ENTRY_TBL_NS (1UL << 63)
#define MMU_ENTRY_TBL_AP_KERNEL_RW (MMU_ENTRY_AP_EL1_RW_EL0_NONE << 61)
#define MMU_ENTRY_TBL_AP_KERNEL_RO (MMU_ENTRY_AP_EL1_RO_EL0_NONE << 61)
#define MMU_ENTRY_TBL_UXN (1UL << 60)
#define MMU_ENTRY_TBL_PXN (1UL << 59)


// For table and block entries
#define MMU_ENTRY_UXN (1UL << 54)
#define MMU_ENTRY_PXN (1UL << 53)
#define MMU_ENTRY_AF  (1UL << 10)
#define MMU_ENTRY_NG  (1UL << 11)
#define MMU_ENTRY_AP_KERN_RW  (MMU_ENTRY_AP_EL1_RW_EL0_NONE << 6)
#define MMU_ENTRY_AP_KERN_RO  (MMU_ENTRY_AP_EL1_RO_EL0_NONE << 6)
#define MMU_ENTRY_AP_USER_RW  (MMU_ENTRY_AP_EL1_RW_EL0_RW << 6)
#define MMU_ENTRY_AP_USER_RO  (MMU_ENTRY_AP_EL1_RO_EL0_RO << 6)

#define MMU_ENTRY_AP_UK_RW      (MMU_ENTRY_AP_EL1_RW_EL0_RW << 6)
#define MMU_ENTRY_AP_UK_RO      (MMU_ENTRY_AP_EL1_RO_EL0_RO << 6)


#define MMU_ENTRY_NEXT_TBL  (MMU_ENTRY_VALID | MMU_ENTRY_TABLE)
#define MMU_ENTRY_NEXT_BLK  (MMU_ENTRY_VALID | MMU_ENTRY_AF)
#define MMU_ENTRY_NEXT_PAGE (MMU_ENTRY_VALID | MMU_ENTRY_PAGE | MMU_ENTRY_AF)

#define MMU_ENTRY_WRITABLE(entry) \
    (entry & MMU_ENTRY_NEXT_PAGE) && \
    ((entry & AP_MASK) == MMU_ENTRY_AP_USER_RW)


#define MMU_ENTRY_ATTR_NOCACHE  (0x2UL << 2)
#define MMU_ENTRY_ATTR_DMA      (0x1UL << 2)
#define MMU_ENTRY_ATTR_NORMAL   (0x0UL << 2)

// Valid kernel mappings
#define MMU_ENTRY_KERNEL_RWX (MMU_ENTRY_AP_KERN_RW)
#define MMU_ENTRY_KERNEL_RO  (MMU_ENTRY_AP_KERN_RO | MMU_ENTRY_PXN | MMU_ENTRY_UXN)
#define MMU_ENTRY_KERNEL_RX  (MMU_ENTRY_AP_KERN_RO | MMU_ENTRY_UXN)
#define MMU_ENTRY_KERNEL_RW  (MMU_ENTRY_AP_KERN_RW | MMU_ENTRY_UXN | MMU_ENTRY_PXN)

// Valid for user+kernel
#define MMU_ENTRY_UK_RWX (MMU_ENTRY_AP_UK_RW)
#define MMU_ENTRY_UK_RX  (MMU_ENTRY_AP_UK_RO)
#define MMU_ENTRY_UK_RO  (MMU_ENTRY_AP_UK_RO | MMU_ENTRY_UXN | MMU_ENTRY_PXN)
#define MMU_ENTRY_UK_RW  (MMU_ENTRY_AP_UK_RW | MMU_ENTRY_UXN | MMU_ENTRY_PXN)

// Valid user mappings
#define MMU_ENTRY_USER_RWX (MMU_ENTRY_AP_USER_RW)
#define MMU_ENTRY_USER_RO  (MMU_ENTRY_AP_USER_RO | MMU_ENTRY_PXN | MMU_ENTRY_UXN)
#define MMU_ENTRY_USER_RX  (MMU_ENTRY_AP_USER_RO | MMU_ENTRY_PXN)
#define MMU_ENTRY_USER_RW  (MMU_ENTRY_AP_USER_RW | MMU_ENTRY_UXN | MMU_ENTRY_PXN)

#define MMU_ENTRIES_PER_PAGE (ARM64_PAGE_SIZE / 8)


// TODO: Should be configured based on page size chosen as well
#define MMU_OA_MASK (((1UL<<(ARM64_VA_BITS-12))-1)<<12)

#define MMU_OA_MASK_PTD MMU_OA_MASK
#define MMU_OA_MASK_PMD (((1UL<<(ARM64_VA_BITS-21))-1)<<21)
#define MMU_OA_MASK_PUD (((1UL<<(ARM64_VA_BITS-30))-1)<<30)

#define MMU_OFFSET_MASK ((1UL<<ARM64_PTE_OFFSET_BITS)-1)

#define PTE_ENTRY_KERNEL_RO  (MMU_ENTRY_KERNEL_RO)
#define PTE_ENTRY_KERNEL_RW  (MMU_ENTRY_KERNEL_RW)
#define PTE_ENTRY_KERNEL_RX  (MMU_ENTRY_KERNEL_RX)
#define PTE_ENTRY_KERNEL_RWX (MMU_ENTRY_KERNEL_RWX)
#define PTE_ENTRY_KERNEL_DMA (MMU_ENTRY_KERNEL_RW | MMU_ENTRY_ATTR_DMA)

#define MMU_SET_OA(entry, oa) \
    entry &= ~(MMU_OA_MASK); \
    entry |= ((oa) & MMU_OA_MASK)

#define MMU_SET_TBL(entry, tbl) \
    entry &=  ~(MMU_OA_MASK); \
    entry |= tbl

bool mmu_check_page_cloned(ptr_t vaddr, bool user, bool instr, bool write);

static inline int vaddr2pgd(ptr_t vaddr)	{
	if(ADDR_KERNEL(vaddr))	{
		vaddr -= ARM64_VA_KERNEL_FIRST_ADDR;
	}
	return (int)( ((vaddr & (((uint64_t)MMU_ENTRIES_PER_PAGE-1) << 39)) >> 39 ) );
}
static inline int vaddr2pud(ptr_t vaddr)	{
	return (int)( ((vaddr & (((uint64_t)MMU_ENTRIES_PER_PAGE-1) << 30)) >> 30 ) );
}

static inline int vaddr2pmd(ptr_t vaddr)	{
	return (int)( ((vaddr & ((MMU_ENTRIES_PER_PAGE-1) << 21)) >> 21 ) );
}
static inline int vaddr2ptd(ptr_t vaddr)	{
	return (int)( ((vaddr & ((MMU_ENTRIES_PER_PAGE-1) << 12)) >> 12 ) );
}
static inline int vaddr2offset(ptr_t vaddr) {
	return (int)( (vaddr & ((1<<ARM64_PTE_OFFSET_BITS)-1)) );
}
static inline bool entry_valid(uint64_t* pt, int idx)	{
	return (pt[idx] & MMU_ENTRY_VALID) == MMU_ENTRY_VALID;
}
static inline bool entry_block(uint64_t* pt, int idx)	{
	return (pt[idx] & 2) == 0;
}
static inline ptr_t phys_to_linear(ptr_t addr) { return (addr + ARM64_VA_LINEAR_START); }
static inline ptr_t linear_to_phys(ptr_t addr) { return (addr - ARM64_VA_LINEAR_START); }

#endif
