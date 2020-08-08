/*
* All this code will be placed in user-executable memory.
*/

#include "syscalls.h"

.section .user.text

.global _uthread_exit
_uthread_exit:
	/* x0 should already contain any potential return value */
	mov x8, #SYS_EXIT_THREAD
	svc #0

