#include "aarch64.h"

.global _start

.extern kstart
.extern secondary_cpu_start

.section .init
/*
* Not yet working with proper header
* Must either this using values from linker-script or post-process and add it to
* the Image file afterwards.
* For EFI, use 'add x13, x18, #0x16'  as first opcode
*/
_head:
	add x13, x18, #0x16
	b _start

	/* 
	* Load offset and kernel size set to 0 for now
	* Should set a proper value, but it will now be interpreted as an old Linux
	* kernel.
	*/
	.quad 0x80000		// Load offset
	.quad 0x0			// Kernel size

	/*
	* LE | 4K page size | 2MB aligned anywhere
	*/
	.quad 0b1010		// Kernel flags

	.quad 0		// reserved
	.quad 0		// reserved
	.quad 0		// reserved
	.ascii "ARM\x64"
	.long _efiheader - _head		// Offset to PE header

_efiheader:
	.long 0x00004550	/* PE_MAGIC */
	.short 0xaa64		/* AArch64 */
	.short 2			/* Number of sections */
	.long 0		/* TS */
	.long 0		/* Ptr symbol tbl */
	.long 0		/* Number of symbol tbl */
	.short 0		/* Optional header size */
	.short 0x0002 | 0x0004 | 0x0200	/* Characteristics */

_section_tbl:
	.ascii ".text\0\0\0"
	.long 0		/* VirtualSize */
	.long 0		/* VirtualAddress */
	.long 0		/* SizeOfRawData */
	.long 0		/* PointerToRawData */
	.long 0		/* PointerToRelocations */
	.long 0		/* PointerToLineNumbers */
	.short 0	/* NumberOfRelocations */
	.short 0	/* NumberOfLineNumbers */
	.long 0x00000020 | 0x20000000 | 0x40000000		/* Characteristics */
	.ascii ".data\0\0\0"
	.long 0		/* VirtualSize */
	.long 0		/* VirtualAddress */
	.long 0		/* SizeOfRawData */
	.long 0		/* PointerToRawData */
	.long 0		/* PointerToRelocations */
	.long 0		/* PointerToLineNumbers */
	.short 0	/* NumberOfRelocations */
	.short 0	/* NumberOfLineNumbers */
	.long 0x00000040|0x40000000|0x80000000	/* Characteristics */

_start:
	/* Store DTB */
	mov x10, x0

	/* 
	* Store PC so we know where we have been loaded
	* This value should be aligned downwards to get the real start
	* This is only used as an output address in early memory initialization
	* so the least significant bits will always be masked to 0.
	*/
	adr x9, .

	/*
	* Disable FP and SIMD traps
	* Unsure how to support floating point numbers and if it's necessary
	* Will remain disabled until I find a use for it
	*/
	mov x0, #CPACR_EL1_FPEN
	msr cpacr_el1, x0


	/* 
	* Set up vectortable, comes directly after .init section
	*/
	adr x1, start_vectortables;
	mov x2, ARM64_VA_KERNEL_FIRST_ADDR
	add x1, x1, x2
	msr vbar_el1, x1


	/* Set up a reasonable stack */
	adr x1, KSTACK_INIT_HIGH
	mov sp, x1

	/* Init MMU, but don't initialize it */
	mov x0, x9
	mov x1, ARM64_VA_KERNEL_FIRST_ADDR

	bl mmu_early_init

	/* Enable MMU */
	dsb ish
	isb
/*	mrs x0, sctlr_el1 */
	eor x0, x0, x0
	orr x0, x0, 1			    /* MMU enable */
	orr x0, x0, #(1 << 2)	    /* cache enable */
	/*orr x0, x0, #(1 << 12)*/	/* Instruction access cacheability */
	/*orr x0, x0, #(1 << 23)*/	    /* SPAN */
	msr sctlr_el1, x0
	isb

	clrex
/*
	mov x0, #0x72000000
	orr x0, x0, #0x2000
	mov x1, #10
	mov x2, #5
	smc #0
*/

	/*
	* Call main
	* kstart(text_load, dtbptr, kernpgd, userpgd, cpu_reset_func)
	*/
	mov x0, x9		/* .text load */
	mov x1, x10
#if ARM64_VA_BITS > 39
	adr x2, kernel_pgd
#else
	adr x2, kernel_pud
#endif
	adr x3, user_pgd
	adr x4, cpu_reset

	ldr x8, =kstart
	blr x8
	
	/* Is valid to return here, but should not happen */
1:
	b 1b
