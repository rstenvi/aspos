#include "syscalls.h"

.macro SYSCALL name num
.global \name
\name:
	mov x8, \num
	svc #0
	ret
.endm


SYSCALL _isatty SYS_ISATTY
SYSCALL _exit SYS_EXIT
SYSCALL _sbrk SYS_SBRK
SYSCALL _write SYS_WRITE
SYSCALL _read SYS_READ
SYSCALL _lseek SYS_LSEEK
SYSCALL _fstat SYS_FSTAT
SYSCALL _close SYS_CLOSE
SYSCALL tsleep SYS_SLEEP_TICK
SYSCALL new_thread SYS_NEW_THREAD
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

.global __trunctfdf2
__trunctfdf2:
	b __trunctfdf2
