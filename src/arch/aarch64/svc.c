#include "aarch64.h"
#include "mmu.h"
#include "kernel.h"
#include "vfs.h"
#include "syscalls.h"

int new_thread_prep_args(ptr_t*);
int handle_svc(struct exception* exc)	{
	int64_t ret = 0;
	ptr_t sysnum = exc->regs[8];
#if defined(CONFIG_SUPPORT_SYSCALL_FILTER)
	if(!thread_access_valid(sysnum))	{
		ret = -NO_ACCESS;
		goto done;
	}
#endif
	switch(sysnum)	{
		case SYS_ISATTY:
			ret = _isatty(exc->regs[0]);
			break;
		case SYS_FSTAT:
			ret = thread_fstat(exc->regs[0], (struct stat*)exc->regs[1]);
			break;
		case SYS_WRITE:
			ret = thread_write(exc->regs[0], (const void*)exc->regs[1], exc->regs[2]);
			break;
		case SYS_SBRK:
			ret = (int64_t)_usbrk(exc->regs[0]);
			break;

		// Poweroff and exit leads to poweroff
		case SYS_EXIT:
#if CONFIG_EXIT_AS_POWEROFF
			kern_poweroff(false);
#else
			ret = thread_exit(exc->regs[0]);
#endif
		break;
		case SYS_POWEROFF:
			kern_poweroff(false);
			break;
		case SYS_SLEEP_TICK:
			ret = thread_tick_sleep(exc->regs[0]);
			break;
		case SYS_NEW_THREAD:
			ret = new_thread_prep_args(exc->regs);
			break;
		case SYS_EXIT_THREAD:
			ret = thread_exit(exc->regs[0]);
			break;
		case SYS_CONF_THREAD:
			ret = thread_configure(exc->regs[0], exc->regs[1]);
			break;
		case SYS_CONF_PROCESS:
			ret = process_configure(exc->regs[0], exc->regs[1]);
			break;
		case SYS_SLEEP_MS:
			ret = thread_ms_sleep(exc->regs[0]);
			break;
		case SYS_YIELD:
			ret = thread_yield();
			break;
		case SYS_READ:
			ret = thread_read(exc->regs[0], (void*)exc->regs[1], exc->regs[2]);
			break;
		case SYS_OPEN:
			ret = thread_open((const char*)exc->regs[0], exc->regs[1], exc->regs[2]);
			break;
		case SYS_CLOSE:
			ret = thread_close(exc->regs[0]);
			break;
		case SYS_LSEEK:
			ret = thread_lseek(exc->regs[0], exc->regs[1], exc->regs[2]);
			break;
		case SYS_DUP:
			ret = thread_dup(exc->regs[0]);
			break;
		case SYS_GET_CHAR:
			ret = thread_getchar(exc->regs[0]);
			break;
		case SYS_PUT_CHAR:
			ret = thread_putchar(exc->regs[0], exc->regs[1]);
			break;
		case SYS_WAIT_TID:
			ret = thread_wait_tid(exc->regs[0], true, false);
			break;
		case SYS_GET_TID:
			ret = thread_get_tid();
			break;
		case SYS_GET_PID:
			ret = thread_get_pid();
			break;
		case SYS_FCNTL:
			ret = thread_fcntl(exc->regs[0], exc->regs[1], exc->regs[2]);
			break;
		case SYS_FORK:
			ret = thread_fork();
			break;
		case SYS_SET_USER:
			ret = thread_setuser((struct user_id*)exc->regs[0]);
			break;
		case SYS_GET_USER:
			ret = thread_getuser((struct user_id*)exc->regs[0]);
			break;
		case SYS_SET_FILTER:
			ret = thread_set_filter((sysfilter_t)exc->regs[0]);
			break;
		case SYS_GET_FILTER:
			ret = thread_get_filter();
			break;
		case SYS_MMAP:
			ret = thread_mmap((void*)exc->regs[0], (size_t)exc->regs[1],
				exc->regs[2], exc->regs[3], exc->regs[4]);
			break;
		case SYS_MUNMAP:
			ret = thread_munmap((void*)exc->regs[0]);
			break;
		case SYS_WAITPID:
			ret = thread_wait_pid((int)exc->regs[0]);
			break;
		default:
			logw("Unknown syscall %i\n", sysnum);
			ret = -1;
			break;
	}
done:
	exc->regs[0] = ret;
	return 0;
}
