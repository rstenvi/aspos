#include "aarch64.h"

.macro ALT_INSTR ins id
.altinstr_\id\()_\ins:
.pushsection .data.altinstr
.quad .altinstr_\id\()_\ins
.word \ins
.word \id
.popsection
nop
.endm

.global set_stack
.global arch_schedule
.global new_thread_prep_args

set_stack:
	mov sp, x0
	isb
	mov lr, x1
	br x1


#if CONFIG_AARCH64_PAN
.global pan_enabled
pan_enabled:
	mov x0, xzr
	/* mrs x0, pan */
	ALT_INSTR 0xd5384260, CPU_FEATURE_PAN

	ret

.global pan_disable
pan_disable:
	mov x0, xzr
	/* msr pan, #0 */
	ALT_INSTR 0xd500409f, CPU_FEATURE_PAN
	ret

.global pan_enable
pan_enable:
	mov x0, xzr
	/* msr pan, #1 */
	ALT_INSTR 0xd500419f, CPU_FEATURE_PAN
	ret
#endif

arch_schedule:
	mov sp, x0
	isb
	mov lr, 0x00
	b exception_return

new_thread_prep_args:
	/* We don't use stack, but must save lr */
	stp x29, x30, [sp, #-16]!
	mov x29, sp

	mov x9, x0
	ldp x0, x1, [x9], #16

	/* Pointer to remaining arguments */
	mov x2, x9

.done:
	bl thread_new_syscall

	ldp x29, x30, [sp], #16
	ret

.global arch_busyloop
arch_busyloop:
	eor x0, x0, x0
	wfi
	b arch_busyloop



.macro MSRFUNC reg, val
.global write_\reg
write_\reg:
	msr \reg, \val
	ret
.endm

.macro MSRFUNCC name, reg, val
.global \name
\name:
	msr \reg, \val
	ret
.endm

/*
* Helper-macro to create wrapper for accessing user-memory using through the
* usual C string function.
*/
.macro COPY_USER_HELPER dir, func
.global \func\()_\dir\()_user
\func\()_\dir\()_user:
	stp x29, x30, [sp, #-16]!
	mov x29, sp

	mov x19, x0
	mov x20, x1
	mov x21, x2

#if CONFIG_AARCH64_PAN
	bl pan_disable
#endif

	mov x0, x19
	mov x1, x20
	mov x2, x21
	bl \func
	mov x19, x0

#if CONFIG_AARCH64_PAN
	bl pan_enable
#endif

	ldp x29, x30, [sp], #16
	mov x0, x19
	ret
.endm


COPY_USER_HELPER to, strncpy
COPY_USER_HELPER to, strncat
COPY_USER_HELPER to, memcpy
COPY_USER_HELPER from, memcpy


/**
* Macro to define various mrs-functions which are used exensively in
* the architecture.
*/
.macro MRSFUNC reg
.global read_\reg
read_\reg:
	mrs x0, \reg
	ret
.endm


MSRFUNCC enable_irq daifclr, #DAIF_IRQ_BIT

#if ARMV_MAJOR >= 8 && ARMV_MINOR >= 2
MSRFUNCC disable_pan pan, #0
MSRFUNCC enable_pan pan, #1
#endif

#if ARMV_MAJOR >= 8 && ARMV_MINOR >= 3
MSRFUNCC disable_uao uao, #0
MSRFUNCC enable_uao uao, #1
#endif

MRSFUNC spsr_el1
MSRFUNC spsr_el1, x0

MSRFUNC cntv_ctl_el0, x0
MRSFUNC cntv_ctl_el0

MRSFUNC cntv_cval_el0
MSRFUNC cntv_cval_el0, x0

MRSFUNC vbar_el1

MRSFUNC cntfrq_el0

MRSFUNC cntvct_el0

MRSFUNC ttbr0_el1
MSRFUNC ttbr0_el1, x0

MRSFUNC ttbr1_el1
MSRFUNC ttbr1_el1, x0

MRSFUNC tcr_el1
MSRFUNC tcr_el1, x0

MRSFUNC sctlr_el1
MSRFUNC sctlr_el1, x0

MSRFUNC mair_el1, x0


MRSFUNC mpidr_el1

.global hvc
hvc:
	hvc #0
	ret
.global smc
smc:
	smc #0
	ret

