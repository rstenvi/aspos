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
	/* Stack is sent to us as an argument */
	mov sp, x0

	mov x0, #CPACR_EL1_FPEN
	msr cpacr_el1, x0

	adr x1, IMAGE_INIT_END;
	mov x2, ARM64_VA_KERNEL_IMAGE_START
	add x1, x1, x2
	msr vbar_el1, x1

	adr x0, kernel_pgd
	msr ttbr1_el1, x0

	adr x0, user_pgd
	msr ttbr0_el1, x0

	isb
	mrs x0, sctlr_el1
	orr x0, x0, 1
	msr sctlr_el1, x0
	isb

	ldr x8, =secondary_cpu_start
	blr x8

/* Endless loop we should never return to */
1:
	b 1b

