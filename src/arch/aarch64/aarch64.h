/*
* This file should contain constants related to aarch64
*/
#ifndef __ARCH64_H
#define __ARCH64_H

#include "aarch64-config.h"

#define ADDR_USER(vaddr)   (((ptr_t)vaddr & (1UL<<63)) == 0)
#define ADDR_KERNEL(vaddr) (((ptr_t)vaddr & (1UL<<63)) != 0)


#define PAN_CC_SUPPORT (ARMV_MAJOR >= 8 && ARMV_MINOR >= 1)
#define PAN_ENABLED (PAN_CC_SUPPORT && CONFIG_AARCH64_PAN == 1)

#define DAIF_IRQ_BIT 0x02

#define CPACR_EL1_FPEN (0b11 << 20)


#define AARCH64_EXC_SYNC_SP0      0x1
#define AARCH64_EXC_IRQ_SP0       0x2
#define AARCH64_EXC_FIQ_SP0       0x3
#define AARCH64_EXC_SERR_SP0      0x4
#define AARCH64_EXC_SYNC_SPX      0x11
#define AARCH64_EXC_IRQ_SPX       0x12
#define AARCH64_EXC_FIQ_SPX       0x13
#define AARCH64_EXC_SERR_SPX      0x14
#define AARCH64_EXC_SYNC_AARCH64  0x21
#define AARCH64_EXC_IRQ_AARCH64   0x22
#define AARCH64_EXC_FIQ_AARCH64   0x23
#define AARCH64_EXC_SERR_AARCH64  0x24
#define AARCH64_EXC_SYNC_AARCH32  0x31
#define AARCH64_EXC_IRQ_AARCH32   0x32
#define AARCH64_EXC_FIQ_AARCH32   0x33
#define AARCH64_EXC_SERR_AARCH32  0x34


#define EXC_EXC_SP_OFFSET 16

/*
* The least-significant 11 bits of VBAR must be zero
*/
#define ALIGN_VECTORTABLE 2048

// Alignment between different data in same section
#define ALIGN_SAME_SECTION 8

#define ALIGN_DIFF_SECTION ARM64_PAGE_SIZE



// ------------------- MMU ------------------------------------ //


// EL1&0 stage 1 address translation enabled
#define ARM64_REG_SCTLR_M 1UL

// Big-endian of data access when set for EL1 and EL0 respectively
#define ARM64_REG_SCTLR_EE  (1UL << 25)
#define ARM64_REG_SCTLR_EOE (1UL << 24)


// We use same number of VA bits for EL0 and EL1
#define ARM64_REG_TCR_T0SZ_INIT (64 - 39)
#define ARM64_REG_TCR_T0SZ (64 - ARM64_VA_BITS)
#define ARM64_REG_TCR_T1SZ ((64 - ARM64_VA_BITS) << 16)

// Configure TG0 and TG1 according to PAGE_SIZE chosen
#if ARM64_PAGE_SIZE == (4*1024)
# define ARM64_REG_TCR_TG0 (0b00UL << 14)
# define ARM64_REG_TCR_TG1 (0b10UL << 30)
# define ARM64_PTE_OFFSET_BITS 12
#elif ARM64_PAGE_SIZE == (16*1024)
# define ARM64_REG_TCR_TG0 (0b10UL << 14)
# define ARM64_REG_TCR_TG1 (0b01UL << 30)
# define ARM64_PTE_OFFSET_BITS 14
#elif ARM64_PAGE_SIZE == (64*1024)
# define ARM64_REG_TCR_TG0 (0b01UL << 14)
# define ARM64_REG_TCR_TG1 (0b11UL << 30)
# define ARM64_PTE_OFFSET_BITS 16
#else
# error "Invalid PAGE_SIZE was used"
#endif



#if ARM64_PAGE_SIZE != 4096
# error "Only 4KB page size currently supported"
#endif


#if ARM64_VA_BITS == 32
# define ARM64_REG_TCR_IPS (0x000UL << 32)
# define ARM64_VA_KERNEL_FIRST_ADDR 0xffffffff00000000
#elif ARM64_VA_BITS == 36
# define ARM64_REG_TCR_IPS (0x001UL << 32)
# define ARM64_VA_KERNEL_FIRST_ADDR 0xfffffff000000000
#elif ARM64_VA_BITS == 40
# define ARM64_REG_TCR_IPS (0x010UL << 32)
# define ARM64_VA_KERNEL_FIRST_ADDR 0xffffff0000000000
#elif ARM64_VA_BITS == 42
# define ARM64_REG_TCR_IPS (0x011UL << 32)
# define ARM64_VA_KERNEL_FIRST_ADDR 0xfffffc0000000000
#elif ARM64_VA_BITS == 44
# define ARM64_REG_TCR_IPS (0x100UL << 32)
# define ARM64_VA_KERNEL_FIRST_ADDR 0xfffff00000000000
#elif ARM64_VA_BITS == 48
# define ARM64_REG_TCR_IPS (0x101UL << 32)
# define ARM64_VA_KERNEL_FIRST_ADDR 0xffff000000000000
#else
# error "Invalid VA_BITS size"
#endif



#define ARM64_REG_TCR_INIT (ARM64_REG_TCR_T0SZ | ARM64_REG_TCR_T1SZ | ARM64_REG_TCR_TG0 | ARM64_REG_TCR_TG1 | ARM64_REG_TCR_IPS)


#define linker_kernel_start(out) asm("adr %0, KERNEL_START" : "=r"(out));
#define linker_kernel_end(out) asm("adr %0, IMAGE_END" : "=r"(out));

#define write_sysreg_tcr(val) asm("msr TCR_EL1, %0" : : "r"(val));
#define write_sysreg_ttbr1(val) asm("msr TTBR1_EL1, %0" : : "r"(val));
#define write_sysreg_ttbr0(val) asm("msr TTBR0_EL1, %0" : : "r"(val));
#define write_sysreg_sctlr(val) asm("msr SCTLR_EL1, %0" : : "r"(val));


#define ARM64_MMU_ENTRY_VALID (1UL)
#define ARM64_MMU_ENTRY_INVALID (0UL)

#define ARM64_MMU_ENTRY_TABLE (1UL << 1)

#define ARM64_MMU_ENTRY_AP_EL1_RW_EL0_NONE (0UL)
#define ARM64_MMU_ENTRY_AP_EL1_RW_EL0_RW   (1UL)
#define ARM64_MMU_ENTRY_AP_EL1_RO_EL0_NONE (2UL)
#define ARM64_MMU_ENTRY_AP_EL1_RO_EL0_RO   (3UL)

// Hierarchical lookup of tables, limit early
#define ARM64_MMU_ENTRY_TBL_NS (1UL << 63)
#define ARM64_MMU_ENTRY_TBL_AP_KERNEL_RW (ARM64_MMU_ENTRY_AP_EL1_RW_EL0_NONE << 61)
#define ARM64_MMU_ENTRY_TBL_AP_KERNEL_RO (ARM64_MMU_ENTRY_AP_EL1_RO_EL0_NONE << 61)
#define ARM64_MMU_ENTRY_TBL_UXN (1UL << 60)
#define ARM64_MMU_ENTRY_TBL_PXN (1UL << 59)


// For table and block entries
#define ARM64_MMU_ENTRY_UXN (1UL << 54)
#define ARM64_MMU_ENTRY_PXN (1UL << 53)
#define ARM64_MMU_ENTRY_AF  (1UL << 10)
#define ARM64_MMU_ENTRY_AP_KERNEL_RW  (ARM64_MMU_ENTRY_AP_EL1_RW_EL0_NONE << 6)
#define ARM64_MMU_ENTRY_AP_KERNEL_RO  (ARM64_MMU_ENTRY_AP_EL1_RO_EL0_NONE << 6)
#define ARM64_MMU_ENTRY_AP_USER_RW    (ARM64_MMU_ENTRY_AP_EL1_RW_EL0_RW << 6)
#define ARM64_MMU_ENTRY_AP_USER_RO    (ARM64_MMU_ENTRY_AP_EL1_RO_EL0_RO << 6)

#define ARM64_MMU_ENTRY_AP_UK_RW      (ARM64_MMU_ENTRY_AP_EL1_RW_EL0_RW << 6)
#define ARM64_MMU_ENTRY_AP_UK_RO      (ARM64_MMU_ENTRY_AP_EL1_RO_EL0_RO << 6)




#define ARM64_MMU_ENTRY_NEXT_TBL (ARM64_MMU_ENTRY_VALID | ARM64_MMU_ENTRY_TABLE)
#define ARM64_MMU_ENTRY_NEXT_BLK (ARM64_MMU_ENTRY_VALID)
#define ARM64_MMU_ENTRY_NEXT_PAGE ARM64_MMU_ENTRY_NEXT_TBL

#define ARM64_MMU_ENTRY_ATTR_DMA    (0x1 << 2)
#define ARM64_MMU_ENTRY_ATTR_NORMAL (0x0 << 2)

// Valid kernel mappings
#define ARM64_MMU_ENTRY_KERNEL_RWX (ARM64_MMU_ENTRY_AF | ARM64_MMU_ENTRY_AP_KERNEL_RW)
#define ARM64_MMU_ENTRY_KERNEL_RO  (ARM64_MMU_ENTRY_AF | ARM64_MMU_ENTRY_AP_KERNEL_RO | ARM64_MMU_ENTRY_PXN | ARM64_MMU_ENTRY_UXN)
#define ARM64_MMU_ENTRY_KERNEL_RX  (ARM64_MMU_ENTRY_AF | ARM64_MMU_ENTRY_AP_KERNEL_RO | ARM64_MMU_ENTRY_UXN)
#define ARM64_MMU_ENTRY_KERNEL_RW  (ARM64_MMU_ENTRY_AF | ARM64_MMU_ENTRY_AP_KERNEL_RW | ARM64_MMU_ENTRY_UXN | ARM64_MMU_ENTRY_PXN)

// Valid for user+kernel
#define ARM64_MMU_ENTRY_UK_RWX (ARM64_MMU_ENTRY_AF | ARM64_MMU_ENTRY_AP_UK_RW)
#define ARM64_MMU_ENTRY_UK_RX  (ARM64_MMU_ENTRY_AF | ARM64_MMU_ENTRY_AP_UK_RO)
#define ARM64_MMU_ENTRY_UK_RO  (ARM64_MMU_ENTRY_AF | ARM64_MMU_ENTRY_AP_UK_RO | ARM64_MMU_ENTRY_UXN | ARM64_MMU_ENTRY_PXN)
#define ARM64_MMU_ENTRY_UK_RW  (ARM64_MMU_ENTRY_AF | ARM64_MMU_ENTRY_AP_UK_RW | ARM64_MMU_ENTRY_UXN | ARM64_MMU_ENTRY_PXN)

// Valid user mappings
#define ARM64_MMU_ENTRY_USER_RWX   (ARM64_MMU_ENTRY_AF | ARM64_MMU_ENTRY_AP_USER_RW)
#define ARM64_MMU_ENTRY_USER_RO  (ARM64_MMU_ENTRY_AF | ARM64_MMU_ENTRY_AP_USER_RO | ARM64_MMU_ENTRY_PXN | ARM64_MMU_ENTRY_UXN)
#define ARM64_MMU_ENTRY_USER_RX  (ARM64_MMU_ENTRY_AF | ARM64_MMU_ENTRY_AP_USER_RO | ARM64_MMU_ENTRY_PXN)
#define ARM64_MMU_ENTRY_USER_RW  (ARM64_MMU_ENTRY_AF | ARM64_MMU_ENTRY_AP_USER_RW | ARM64_MMU_ENTRY_UXN | ARM64_MMU_ENTRY_PXN)




#define ARM64_MMU_ENTRIES_PER_PAGE (uint64_t)(ARM64_PAGE_SIZE / 8)

// TODO: Should be configured based on page size chosen as well
#define ARM64_MMU_OA_MASK (((1UL<<(ARM64_VA_BITS-12))-1)<<12)

#define ARM64_MMU_OA_MASK_PTD ARM64_MMU_OA_MASK
#define ARM64_MMU_OA_MASK_PMD (((1UL<<(ARM64_VA_BITS-21))-1)<<21)
#define ARM64_MMU_OA_MASK_PUD (((1UL<<(ARM64_VA_BITS-30))-1)<<30)

#define ARM64_MMU_OFFSET_MASK ((1<<ARM64_PTE_OFFSET_BITS)-1)


// ------------------- Define virtual memory layout ----------------- //



//#define ARM64_VA_KERNEL_FIRST_ADDR  (~((1UL<<ARM64_VA_BITS)-1))
//#define ARM64_VA_KERNEL_IMAGE_START ARM64_VA_KERNEL_FIRST_ADDR


#define ARM64_VA_LINEAR_START  (ARM64_VA_KERNEL_FIRST_ADDR)
#define ARM64_VA_LINEAR_SIZE   (CONFIG_LINEAR_SIZE_MB * MB)
#define ARM64_VA_LINEAR_STOP   (ARM64_VA_LINEAR_START + ARM64_VA_LINEAR_SIZE)


#define ARM64_VA_KERNEL_VMMAP_START  ARM64_VA_LINEAR_STOP
#define ARM64_VA_KERNEL_VMMAP_SIZE   (CONFIG_MAX_VMMAP_SIZE_MB * MB)
#define ARM64_VA_KERNEL_VMMAP_STOP   (ARM64_VA_KERNEL_VMMAP_START + ARM64_VA_KERNEL_VMMAP_SIZE)



#define ARM64_VA_KERNEL_STACK_START ARM64_VA_KERNEL_VMMAP_STOP
#define ARM64_VA_KERNEL_STACK_SIZE  (PAGE_SIZE * CONFIG_EXCEPTION_STACK_BLOCKS)
#define ARM64_VA_KERNEL_STACK_STOP (ARM64_VA_KERNEL_STACK_START + ARM64_VA_KERNEL_STACK_SIZE)

// This should rarely be problem on 48b VA, but can easily be a problem on 32b VA
#if ARM64_VA_KERNEL_STACK_STOP < ARM64_VA_KERNEL_FIRST_ADDR
# error "Error in virtual memory layout, the virtual regions allocated are larger than the VA space"
#endif

#define VMMAP_START ARM64_VA_KERNEL_VMMAP_START
#define VMMAP_STOP ARM64_VA_KERNEL_VMMAP_STOP



#define ARM64_VA_USER_START (PAGE_SIZE)
#define ARM64_VA_USER_STOP  ((1UL<<ARM64_VA_BITS)-1)

#define ARM64_VA_THREAD_STACKS_SIZE  (PAGE_SIZE * (CONFIG_MAX_THREADS * CONFIG_THREAD_STACK_BLOCKS))
#define ARM64_VA_THREAD_STACKS_START (ARM64_VA_USER_STOP + 1 - ARM64_VA_THREAD_STACKS_SIZE)
#define ARM64_VA_THREAD_STACKS_STOP (ARM64_VA_THREAD_STACKS_START + ARM64_VA_THREAD_STACKS_SIZE)


#endif
