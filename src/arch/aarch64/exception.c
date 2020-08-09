#include "aarch64.h"
#include "kernel.h"
#include "syscalls.h"

typedef int (*handle_exc)(struct exception*);

static void check_wakeup_cpus(void)	{
	/**
	* First check if there are more threads to run, if there are:
	* - Check if any of the CPUs are in busyloop
	* - We ignore CPU 0 since that's what we're running at
	* - If a different CPU is in busyloop, we send SGI to wake it up
	* - The SGI will interrupt the CPU and run schedule()
	*
	* todo: There might be more threads ready to run and multiple cores
	* waiting. In the current implementation, this will not be caught until
	* the next interrupt on this core.
	*
	* todo: It also makes sense to run this on svc calls, especially if new
	* thread has been created. Currently we don't send IRQ ACK correctly as we
	* don't include cpuid on SGI, so we can't send SGI from anything other than
	* CPU 0.
	*/
	if(thread_ready() > 0)	{
		int id = cpu_find_busyloop();
		if(id > 0)	{
			gic_send_sgi_cpu(SGI_IRQ_SCHEDULE, id);
		}
	}
}

static int handle_irq(struct exception* exc)	{
	int irq = gic_find_pending();
	if(irq > 0)	{
		gic_disable_intr(irq);
		gic_clear_intr(irq);
		logi("irq = %i on CPU %i\n", irq, cpu_id());

		/**
		* We enable interrupts before we are actually finished executing.
		* This shouldn't be a problem because IRQ is still globally disabled
		* until we return with eret.
		*/
		gic_intr_processed(irq);
		gic_enable_intr(irq);


		/**
		* Any IRQ is considered an opportunity to wake up more CPU cores if
		* there is any additional work.
		*/
		check_wakeup_cpus();

		/*
		* Call any registered callbacks
		* This is where this core might schedule a different thread.
		*/
		gic_perform_cb(irq);

		return 0;
	}
	while(1);
}

int new_thread_prep_args(ptr_t*);

static int handle_svc(struct exception* exc)	{
	int64_t ret = 0;
	ptr_t sysnum = exc->regs[8];
	switch(sysnum)	{
		case SYS_ISATTY:
			ret = _isatty(exc->regs[0]);
			break;
		case SYS_FSTAT:
			ret = _fstat(exc->regs[0], (struct stat*)exc->regs[1]);
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
			poweroff();
#else
			ret = thread_exit(exc->regs[0]);
#endif
		break;
		case SYS_POWEROFF:
			poweroff();
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
		default:
			logw("Unknown syscall %i\n", sysnum);
			PANIC("");
	}
	exc->regs[0] = ret;
	return 0;
}


static int exc_unknown(struct exception* exc)	{
	uart_early_putc('Y');
	while(1);
}

void exception_handler(struct exception* exc)	{
	int ret;
	handle_exc func = exc_unknown;
	switch(exc->type)	{
		case AARCH64_EXC_IRQ_AARCH64:
		case AARCH64_EXC_IRQ_SPX:
			func = handle_irq;
			break;
		case AARCH64_EXC_SYNC_AARCH64:
			func = handle_svc;
			break;
		case AARCH64_EXC_SYNC_SP0:
		case AARCH64_EXC_IRQ_SP0:
		case AARCH64_EXC_FIQ_SP0:
		case AARCH64_EXC_SERR_SP0:
		case AARCH64_EXC_SYNC_SPX:
		case AARCH64_EXC_FIQ_SPX:
		case AARCH64_EXC_SERR_SPX:
		case AARCH64_EXC_FIQ_AARCH64: 
		case AARCH64_EXC_SERR_AARCH64:
		case AARCH64_EXC_SYNC_AARCH32:
		case AARCH64_EXC_IRQ_AARCH32: 
		case AARCH64_EXC_FIQ_AARCH32: 
		case AARCH64_EXC_SERR_AARCH32:
		default:
			uart_early_putc('X');
			while(1);
			break;
	}
	ret = func(exc);
	if(ret < 0)	{
		while(1);
	}
}
