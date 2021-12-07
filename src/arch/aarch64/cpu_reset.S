#include "aarch64.h"

.section .cpureset
.extern secondary_cpu_start
.global cpu_reset

/*
* CPU reset leaves system in the following state
* - All PSTATE interrupts are masked
* - PSTATE.SS/IL is set to 0
* - All GP regs and SIMD regs are unknown
* - ELR and SPSR are unknown
* - SP is unknown
*/
cpu_reset:
	/*
	* Stack for new CPU is stored in cpustackptr
	* Can't load the value yet, because it's in virtual memory
	*/
	ldr x19, =cpustackptr

	mov x0, #CPACR_EL1_FPEN
	msr cpacr_el1, x0

	mov x0, xzr
	ldr x10, =ARM64_REG_TCR_T0SZ_INIT
	orr x0, x0, x10

	ldr x10, =ARM64_REG_TCR_T1SZ
	orr x0, x0, x10

	ldr x10, =ARM64_REG_TCR_TG0
	orr x0, x0, x10

	orr x0, x0, #ARM64_REG_TCR_TG1

	ldr x10, =ARM64_REG_TCR_IPS
	orr x0, x0, x10

	ldr x10, =ARM64_REG_TCR_A1_EL0
	orr x0, x0, x10

	msr tcr_el1, x0
/*	mov x0, #0x10180190019 */

	/* mair */
	ldr x0, =MAIR_VALUE
	msr mair_el1, x0

	adr x1, IMAGE_INIT_END;
	mov x2, ARM64_VA_KERNEL_FIRST_ADDR
	add x1, x1, x2
	msr vbar_el1, x1

#if ARM64_VA_BITS > 39
	adr x0, kernel_pgd
#else
	adr x0, kernel_pud
#endif
	msr ttbr1_el1, x0

	adr x0, user_pgd
	msr ttbr0_el1, x0

	isb
	eor x0, x0, x0
	orr x0, x0, #1
	orr x0, x0, #4
	msr sctlr_el1, x0
	dsb ish
	isb

	/* MMU is on, we can now load stack pointer */
	ldr x19, [x19]
	mov sp, x19

	ldr x8, =secondary_cpu_start
	blr x8

/* Endless loop we should never return to */
1:
	b 1b

.section .data
.global cpustackptr
.align 8
cpustackptr:
	.quad 0x0
