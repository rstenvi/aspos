#include "aarch64.h"

.extern exception_handler

.global vectortable
.global exception_return

.section .text
_save_fpregs:
	stp q0, q1, [sp, #-32]!
	stp q2, q3, [sp, #-32]!
	stp q4, q5, [sp, #-32]!
	stp q6, q7, [sp, #-32]!
	stp q8, q9, [sp, #-32]!
	stp q10, q11, [sp, #-32]!
	stp q12, q13, [sp, #-32]!
	stp q14, q15, [sp, #-32]!
	stp q16, q17, [sp, #-32]!
	stp q18, q19, [sp, #-32]!
	stp q20, q21, [sp, #-32]!
	stp q22, q23, [sp, #-32]!
	stp q24, q25, [sp, #-32]!
	stp q26, q27, [sp, #-32]!
	stp q28, q29, [sp, #-32]!
	stp q30, q31, [sp, #-32]!
	ret


exception_return:
	/* Restore SP */
	ldr	x21, [sp, EXC_EXC_SP_OFFSET]
	msr	sp_el0, x21

	/* Point to saved sp value */
	add	sp, sp, #16
	
	/* Restore elr */
	ldp	x21, x22, [sp], #16	
	msr	elr_el1, x22

	ldp q0, q1, [sp], #32
	ldp q2, q3, [sp], #32
	ldp q4, q5, [sp], #32
	ldp q6, q7, [sp], #32
	ldp q8, q9, [sp], #32
	ldp q10, q11, [sp], #32
	ldp q12, q13, [sp], #32
	ldp q14, q15, [sp], #32
	ldp q16, q17, [sp], #32
	ldp q18, q19, [sp], #32
	ldp q20, q21, [sp], #32
	ldp q22, q23, [sp], #32
	ldp q24, q25, [sp], #32
	ldp q26, q27, [sp], #32
	ldp q28, q29, [sp], #32
	ldp q30, q31, [sp], #32

	/* Restore spsr and x0 */
	ldp	x21, x0, [sp], #16
	msr	spsr_el1, x21

	/* Restore remaining */
	ldp	x1, x2, [sp], #16
	ldp	x3, x4, [sp], #16
	ldp	x5, x6, [sp], #16
	ldp	x7, x8, [sp], #16
	ldp	x9, x10, [sp], #16
	ldp	x11, x12, [sp], #16
	ldp	x13, x14, [sp], #16
	ldp	x15, x16, [sp], #16
	ldp	x17, x18, [sp], #16
	ldp	x19, x20, [sp], #16
	ldp	x21, x22, [sp], #16
	ldp	x23, x24, [sp], #16
	ldp	x25, x26, [sp], #16
	isb
	ldp	x27, x28, [sp], #16
	isb
	ldp	x29, x30, [sp], #16
	isb

	eret

.section .vectortable

.macro vector_entry exceptiontype
	stp	x29, x30, [sp, #-16]!
	stp	x27, x28, [sp, #-16]!
	stp	x25, x26, [sp, #-16]!
	stp	x23, x24, [sp, #-16]!
	stp	x21, x22, [sp, #-16]!
	stp	x19, x20, [sp, #-16]!
	stp	x17, x18, [sp, #-16]!
	stp	x15, x16, [sp, #-16]!
	stp	x13, x14, [sp, #-16]!
	stp	x11, x12, [sp, #-16]!
	stp	x9, x10, [sp, #-16]!
	stp	x7, x8, [sp, #-16]!
	stp	x5, x6, [sp, #-16]!
	stp	x3, x4, [sp, #-16]!
	stp	x1, x2, [sp, #-16]!
	
	/* Get spsr value */
	mrs	x21, spsr_el1
	stp	x21, x0, [sp, #-16]!

	/* Store all floating point registers */
	bl _save_fpregs
	
	mrs	x21, elr_el1
	stp	xzr, x21, [sp, #-16]!

	/* Store exception type and esr */
	mov	x21, #(\exceptiontype)
	mrs	x22, esr_el1
	stp	x21, x22, [sp, #-16]!


	/* Store SP at appropriate offset */
	mrs	x21, sp_el0
	str	x21, [sp, EXC_EXC_SP_OFFSET]
	
	/*
	* Data monitors for exclusive memory access is undefined after certain
	* exceptions. We clear it here to avoid undefined behaviour.
	*/
	clrex

	mov x0, sp
	bl #exception_handler

	b exception_return
.endm

.macro ALIGNED_BRANCH bxvalue
	.align 7
	b \bxvalue
.endm

.macro ALIGNED_ENTRY bxvalue num
.align 7
\bxvalue:
	vector_entry \num
.endm

.align 11
vectortable:
// Generate all the code
ALIGNED_ENTRY _curr_el_sp0_sync, AARCH64_EXC_SYNC_SP0
ALIGNED_ENTRY _curr_el_sp0_irq, AARCH64_EXC_IRQ_SP0
ALIGNED_ENTRY _curr_el_sp0_fiq, AARCH64_EXC_FIQ_SP0
ALIGNED_ENTRY _curr_el_sp0_serror, AARCH64_EXC_SERR_SP0
ALIGNED_ENTRY _curr_el_spx_sync, AARCH64_EXC_SYNC_SPX
ALIGNED_ENTRY _curr_el_spx_irq, AARCH64_EXC_IRQ_SPX
ALIGNED_ENTRY _curr_el_spx_fiq, AARCH64_EXC_FIQ_SPX
ALIGNED_ENTRY _curr_el_spx_serror, AARCH64_EXC_SERR_SPX
ALIGNED_ENTRY _lower_el_aarch64_sync, AARCH64_EXC_SYNC_AARCH64
ALIGNED_ENTRY _lower_el_aarch64_irq, AARCH64_EXC_IRQ_AARCH64
ALIGNED_ENTRY _lower_el_aarch64_fiq, AARCH64_EXC_FIQ_AARCH64
ALIGNED_ENTRY _lower_el_aarch64_serror, AARCH64_EXC_SERR_AARCH64
ALIGNED_ENTRY _lower_el_aarch32_sync, AARCH64_EXC_SYNC_AARCH32
ALIGNED_ENTRY _lower_el_aarch32_irq, AARCH64_EXC_IRQ_AARCH32
ALIGNED_ENTRY _lower_el_aarch32_fiq, AARCH64_EXC_FIQ_AARCH32
ALIGNED_ENTRY _lower_el_aarch32_serror, AARCH64_EXC_SERR_AARCH32

// Ensure we reserve enough bytes for last entry
.align 7

