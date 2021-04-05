#include "aarch64.h"
#include "kernel.h"
#include "vfs.h"
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
		logd("irq = %i on CPU %i\n", irq, cpu_id());

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

#define ESR_EC_OFFSET (26)
#define ESR_EC_BITS   (6)
#define ESR_EC_MASK   (((1<<ESR_EC_BITS)-1)<<ESR_EC_OFFSET)
#define GET_ESR_EC(n) ((n & ESR_EC_MASK) >> ESR_EC_OFFSET)

// https://developer.arm.com/documentation/ddi0601/2020-12/AArch64-Registers/ESR-EL1--Exception-Syndrome-Register--EL1-
#define ESR_EC_UNKNOWN        0b000000
#define ESR_EC_TRAP_WF        0b000001
#define ESR_EC_TRAP_MRC       0b000011
#define ESR_EC_TRAP_MRRC      0b000100
#define ESR_EC_TRAP_MRC2      0b000101
#define ESR_EC_TRAP_LDT       0b000110
#define ESR_EC_SVE            0b000111
#define ESR_EC_TRAP_LD        0b001010
#define ESR_EC_TRAP_MRRC2     0b001100
#define ESR_EC_BRANCH_TARGET  0b001101
#define ESR_EC_ILL_EXEC       0b001110
#define ESR_EC_SVC_32         0b010001
#define ESR_EC_SVC_64         0b010101
#define ESR_EC_TRAP_MSR       0b011000
#define ESR_EC_SVE2           0b011001
#define ESR_EC_TSTART         0b011011
#define ESR_EC_PTRAUTH        0b011100
#define ESR_EC_INSTR_ABRT_LEL 0b100000
#define ESR_EC_INSTR_ABRT_SEL 0b100001
#define ESR_EC_PC_ALIGN       0b100010
#define ESR_EC_DATA_ABRT_LEL  0b100100
#define ESR_EC_DATA_ABRT_SEL  0b100101
#define ESR_EC_SP_ALIGN       0b100110
#define ESR_EC_FLOAT_32       0b101000
#define ESR_EC_FLOAT_64       0b101100
#define ESR_EC_SERROR         0b101111
#define ESR_EC_BP_LEL         0b110000
#define ESR_EC_BP_SEL         0b110001
#define ESR_EC_SW_STEP_LEL    0b110010
#define ESR_EC_SW_STEP_SEL    0b110011
#define ESR_EC_WP_LEL         0b110100
#define ESR_EC_WP_SEL         0b110101
#define ESR_EC_BKPT_32        0b111000
#define ESR_EC_BKPT_64        0b111100

// normal syscall ESR: 0x56000000
// invalid memacc ESR: 0x9200004f
int new_thread_prep_args(ptr_t*);

static int handle_svc(struct exception* exc)	{
	int64_t ret = 0;
	ptr_t sysnum = exc->regs[8];
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
			kern_poweroff();
#else
			ret = thread_exit(exc->regs[0]);
#endif
		break;
		case SYS_POWEROFF:
			kern_poweroff();
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
			ret = thread_wait_tid(exc->regs[0]);
			break;
		case SYS_GET_TID:
			ret = thread_get_tid();
			break;
		case SYS_FCNTL:
			ret = thread_fcntl(exc->regs[0], exc->regs[1], exc->regs[2]);
			break;
		default:
			logw("Unknown syscall %i\n", sysnum);
			kern_poweroff();
	}
	exc->regs[0] = ret;
	return 0;
}
// TODO: When abort is in user-mode, we should just kill thread
static int handle_abort(struct exception* exc, bool user, bool instr)	{
	logw("abort: user=%i instr=%i addr=%x\n", user, instr, exc->elr);
	if(user)	thread_exit(42);
	else		kern_poweroff();
	return 0;
}
static int handle_align(struct exception* exc, bool pc)	{
	logw("align: pc=%i addr=%x\n", pc, exc->elr);
	kern_poweroff();
	return 0;
}
static int handle_sync(struct exception* exc)	{
	int ret;
	int esr = GET_ESR_EC(exc->esr);

	switch(esr)	{
	case ESR_EC_SVC_64:
		ret = handle_svc(exc);
		break;
	case ESR_EC_INSTR_ABRT_LEL:
		ret = handle_abort(exc, true, true);
		break;
	case ESR_EC_INSTR_ABRT_SEL:
		ret = handle_abort(exc, false, true);
		break;
	case ESR_EC_DATA_ABRT_LEL:
		ret = handle_abort(exc, true, false);
		break;
	case ESR_EC_DATA_ABRT_SEL:
		ret = handle_abort(exc, false, false);
		break;
	case ESR_EC_PC_ALIGN:
		ret = handle_align(exc, true);
		break;
	case ESR_EC_SP_ALIGN:
		ret = handle_align(exc, false);
		break;
	default:
		logw("Don't know how to handle ESR: %x\n", esr);
		PANIC("halt");
		break;
	}
	return ret;
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
			func = handle_sync;
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
		PANIC("exception handling was negative");
		while(1);
	}
}
