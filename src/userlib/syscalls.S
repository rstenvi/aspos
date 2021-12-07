#include "syscalls.h"

.macro SYSCALL name num
.global \name
\name:
	mov x8, \num
	svc #0
	ret
.endm

.global svc
svc:
	mov x8, x0
	mov x9, x1
	ldp x0, x1, [x9], #16
	ldp x2, x3, [x9], #16
	ldp x4, x5, [x9], #16
	ldp x6, x7, [x9], #16
	svc #0
	ret

SYSCALL _isatty SYS_ISATTY
SYSCALL _exit SYS_EXIT
SYSCALL _sbrk SYS_SBRK
SYSCALL _write SYS_WRITE
SYSCALL _read SYS_READ
SYSCALL _lseek SYS_LSEEK
SYSCALL _fstat SYS_FSTAT
SYSCALL _close SYS_CLOSE
SYSCALL tsleep SYS_SLEEP_TICK
/* SYSCALL new_thread SYS_NEW_THREAD*/
SYSCALL exit_thread SYS_EXIT_THREAD
SYSCALL poweroff    SYS_POWEROFF
SYSCALL conf_thread SYS_CONF_THREAD
SYSCALL msleep SYS_SLEEP_MS
SYSCALL yield SYS_YIELD
SYSCALL _open SYS_OPEN
SYSCALL dup SYS_DUP
SYSCALL get_char SYS_GET_CHAR
SYSCALL put_char SYS_PUT_CHAR
SYSCALL wait_tid SYS_WAIT_TID
SYSCALL get_tid SYS_GET_TID
SYSCALL fcntl   SYS_FCNTL
SYSCALL fork    SYS_FORK

SYSCALL is_mapped SYS_IS_MAPPED

/* SYSCALL proc_keepalive SYS_PROC_KEEPALIVE */
SYSCALL conf_process   SYS_CONF_PROCESS

SYSCALL _mmap    SYS_MMAP
SYSCALL _munmap  SYS_MUNMAP

SYSCALL wait_pid  SYS_WAITPID
SYSCALL getpid    SYS_GET_PID

.global __trunctfdf2
__trunctfdf2:
	b __trunctfdf2


.global new_thread
new_thread:
#ifdef KASAN_ENABLE
/*
	TODO: With this hack, we cannot have more than 5 arguments
	cmp x1, #5
*/
	mov x7, x0
	adr x0, new_thread_trampoline
#endif
	mov x8, #SYS_NEW_THREAD
	svc #0

	ret


.global new_thread_trampoline
new_thread_trampoline:
#ifdef KASAN_ENABLE
	stp	x29, x30, [sp, #-16]!
	stp x0, x1, [sp, #-16]!
	stp x2, x3, [sp, #-16]!
	stp x4, x5, [sp, #-16]!
	stp x6, x7, [sp, #-16]!
	mov x0, sp
	and x0, x0, #~(4096-1)
	add x0, x0, #(4096)
	sub x0, x0, #(4096 * CONFIG_THREAD_STACK_BLOCKS * 2)
	mov x1, #(4096 * CONFIG_THREAD_STACK_BLOCKS * 2)
	bl kasan_mark_valid
	ldp x6, x7, [sp], #16
	ldp x4, x5, [sp], #16
	ldp x2, x3, [sp], #16
	ldp x0, x1, [sp], #16
	ldp	x29, x30, [sp], #16
#endif
	br x5

