#include "kernel.h"

#if defined(CONFIG_DRIVER_USERID_AUTO_INCREMENT)
uint32_t last_driver_uid = USERID_LAST;
#endif
__attribute__((__section__(".bss"))) struct os_data osdata;

int logready = 0;
extern ptr_t KERNEL_START;
extern ptr_t KERNEL_END;
extern ptr_t USER_START;
extern ptr_t USER_END;
extern ptr_t DRVFUNC_START;
extern ptr_t DRVFUNC_STOP;

extern ptr_t HMEMFUNC_START;
extern ptr_t HMEMFUNC_STOP;

extern ptr_t EARLYHW_START;
extern ptr_t EARLYHW_STOP;

extern ptr_t CPUCORE_START;
extern ptr_t CPUCORE_STOP;

static void percpu_start(void);
static void kstart_stage2(void);
static void init_sbrk(void);
static void init_drivers(void);
void secondary_cpu_start(void);

#if defined(CONFIG_EARLY_UART)
int early_printf(const char* fmt, ...)	{
	return uart_early_write(fmt);
}
#endif

uint64_t smc();

/**
* Main C entry point after the initial assembly code has executed.
*
* The function will never return.
*
* Parameters:
*	image: Not sure if we need this
*	dtb: Address to where DTB data is stored
*	kpgd: Address to kernel page directory
*	upgd: Address to user page directory
*	seccpu: Not sure if we need this
*/
__noreturn void kstart(ptr_t kimage, ptr_t dtb, ptr_t kpgd, ptr_t upgd, ptr_t seccpu)	{

	struct os_data* osd = &(osdata);
	// Temporary location for DTB
	// We still use physical address, but it's been identity mapped
	osd->kernel_start = (ptr_t)&(KERNEL_START);
	osd->kernel_end = (ptr_t)&(KERNEL_END);
	//osd->linear_offset = 0;
	osd->cpu_reset_func = seccpu;

	osdata.linear_offset = ARM64_VA_LINEAR_START;

	osd->dtb = dtb + osdata.linear_offset;
	osdata.kpgd = kpgd + osdata.linear_offset;
	osdata.upgd = upgd + osdata.linear_offset;

	mutex_clear(cpu_loglock()); 

#if defined(CONFIG_EARLY_UART)
	uart_early_init();
	// We can't use printf until after we have set up dynamic memory and brk
	osd->kgetc = uart_early_getc;
	osd->kputs = uart_early_write;
	osd->kputc = uart_early_putc;
	osd->printk = early_printf;
#endif

	// Initially we use identity map
	//osd->kpgd = kpgd;
	//osd->upgd = upgd;

	ptr_t addr, length;
	if(get_memory_dtb(&addr, &length) != OK)	PANIC("Unable to get memory from dtb\n");

	osdata.pmm.start = addr;
	osdata.pmm.end = addr + length;

	pmm_init();
	pmm_mark_mem(kimage, osdata.kernel_end - ARM64_VA_KERNEL_FIRST_ADDR);

	// TODO: Should parse FDT to get true size
	pmm_mark_mem(dtb, (ptr_t)dtb + MB);

	//init_memory(kimage);

	init_vmmap();
	ptr_t stack = vmmap_alloc_pages(CONFIG_EXCEPTION_STACK_BLOCKS, PROT_RW, VMMAP_FLAG_NONE);
	stack += (PAGE_SIZE * CONFIG_EXCEPTION_STACK_BLOCKS);

	//const char* smsg = "Hello from normal world";
	//ASSERT_TRUE(smc((0x72 << 24) | 0x2000, 10, 20) == 30, "smc returned unknown value");
	
	//ASSERT_TRUE(smc(SMCC_FAST32(OPTEE_ID, 0), mmu_va_to_pa((ptr_t)smsg)) == 0, "smc returned wrong value");
	
//	smc(SMCC_FAST32(42, 0), 0, 0);

	/*
	* todo: This is only a fix for gdb-scripts.
	* It can be at the top, but it them becomes more cumbersome to debug.
	*/
//	stack -= 32;

	/* Set stack and jump to stage2 of boot process */
	set_stack(stack, kstart_stage2);

	// Will never return here
	while(1);
}

/**
* When this function is called, the identity map has been removed and we have a
* fresh stack. In other words, we we cannot access any DMA resource through its
* original mapping and we cannot return from this function.
*/
__noreturn static void kstart_stage2(void) {
	struct os_data* osd = &(osdata);

	init_sbrk();

#if defined(CONFIG_KASAN)
	kasan_init();
	kasan_mark_valid((ptr_t)osd->dtb, MB);
	kasan_mark_valid(VMMAP_START, PAGE_SIZE);
	kasan_mark_valid(ARM64_VA_KERNEL_STACK_START, ARM64_VA_KERNEL_STACK_SIZE);
#endif

/*
#if defined(CONFIG_EARLY_UART)
	osd->printk = printf;
#endif
*/

	// This should be the first message printed
#if defined(CONFIG_EARLY_UART)
	logi("Reached stage 2 with memory set up\n");
	logi("Taking second pass at DTB\n");
#endif
	struct dtb_node* root = dtb_parse_data(osd->dtb);
	dtb_second_pass(root);
	osd->dtbroot = root;

	// All code from here on can use a nicer interface to retrieve DTB data

#if defined(CONFIG_EARLY_UART)
	logi("Initializing drivers\n");
#endif

	init_drivers();


	// UART should now be defined
	logready = 1;

	logi("VA Memory regions set up\n");
	logi("First: %lx\n", ARM64_VA_KERNEL_FIRST_ADDR);
	logi("Linear: %lx -> %lx\n", ARM64_VA_LINEAR_START, ARM64_VA_LINEAR_STOP);
#if defined(CONFIG_KASAN)
	logi("KASAN: %lx -> %lx\n", ARM64_VA_SHADOW_START, ARM64_VA_SHADOW_STOP);
#endif
	logi("Vmmap: %lx -> %lx\n", ARM64_VA_KERNEL_VMMAP_START, ARM64_VA_KERNEL_VMMAP_STOP);
	logi("Stack: %lx -> %lx\n", ARM64_VA_KERNEL_STACK_START, ARM64_VA_KERNEL_STACK_STOP);
	logi("DMA: %lx\n", ARM64_VA_KERNEL_DMA_START);


	logi("Initializing threads\n");
	init_threads();


	/*
	* CPUs will be reset without MMU enabled, so we must have identity map intact
	* when we call `cpu_reset`. 
	*/
	int i;

	// Lock the boot CPU so that we can pause the secondary CPUs
	logi("Starting secondary CPUs\n");
	struct cpus* cps = &(osd->cpus);
	cps->started = 1;
	mutex_acquire( &(cps->cpus[0].readylock) );

	for(i = 1; i < cps->numcpus; i++)	{
		if(cps->cpu_on)	{
			// Acquire the lock first
			mutex_acquire( &(cps->cpus[i].readylock) );
			cps->started += 1;

			// Start the CPU
			cps->cpu_on(cps->cpus[i].cpuid, osd->cpu_reset_func);

			// The CPU has finished booting, it will release the lock
			mutex_acquire( &(cps->cpus[i].readylock) );
		}
		else	{
			logw("No driver is able to reset additional CPU with ID %i\n",
				cps->cpus[i].cpuid
			);
		}
	}

	// Init user memory and remove identity map
	logi("Removing user memory\n");
	//mmu_unmap_user_pgd((ptr_t*)osdata.upgd);
//	mmu_init_user_memory((ptr_t*)osdata.upgd);

	logi("Creating user-code\n");
	thread_new_main();

	logi("Trigger per-CPU code\n");
	percpu_start();

	PANIC("Returned after starting CPUs\n");
	while(1);
}

static void percpu_start(void)	{
	// Call per-cpu functions
	ptr_t start, stop;
	start = (ptr_t)(&CPUCORE_START);
	stop = (ptr_t)(&CPUCORE_STOP);
	logi("Calling CPU-specific init-code\n");
	call_inits(start, stop);


	// We always release the boot cpu lock because all CPUs are using this lock
	// for waiting
	logi("Releasing readylock on boot CPU\n");
	mutex_release( &(osdata.cpus.cpus[0].readylock) );

	logi("Enabling IRQ\n");
	enable_irq();

	logi("Starting thread scheduler\n");
	if(cpu_id() == 0)
		thread_schedule_next(0, false);

	while(thread_has_busyloop() == false)	{
	}

	thread_schedule_next(0, false);
	loge("Unable to schedule on CPU\n");
	while(1);
}

void secondary_cpu_start(void)	{
	// Release own lock first
	int id = cpu_id();
	mutex_release( &(osdata.cpus.cpus[id].readylock) );

	// Wait until we can acquire boot lock before continuing
	mutex_acquire( &(osdata.cpus.cpus[0].readylock) );

	// Shared function for all per-cpu functionality
	percpu_start();
}

static void init_drivers(void)	{
	ptr_t start, stop;

	start = (ptr_t)(&EARLYHW_START);
	stop = (ptr_t)(&EARLYHW_STOP);
	call_inits(start, stop);
	
	start = (ptr_t)(&DRVFUNC_START);
	stop = (ptr_t)(&DRVFUNC_STOP);
	call_inits(start, stop);
}


void call_inits(ptr_t start, ptr_t stop)	{
	ptr_t curr;
	deviceinit_t func;
	for(curr = start; curr < stop; curr += sizeof(ptr_t))	{
		func = (deviceinit_t)(*((ptr_t*)(curr)));
		//logd("Calling driver @ %lx\n", func);

		// TODO: Should do some error checking here
		func();
		//logi("Driver @ %lx returned %i\n", func, ret);
	}
}

static void init_sbrk(void)	{
	struct sbrk* brk = cpu_get_kernbrk();

	brk->numpages = (MB*8) / PAGE_SIZE;

	brk->mappedpages = 0;
	brk->addr = (void*)vmmap_alloc_pages(brk->numpages, PROT_RW, VMMAP_FLAG_LAZY_ALLOC);
	if(brk->addr == NULL)	{
		PANIC("Unable to allocate memory");
	}
	brk->curroffset = 0;
	mutex_clear(&brk->lock);
}

#if defined(CONFIG_SIMPLE_LOG_FORMAT)
void klog(char* fmt, ...)	{
#else
void klog(const char* lvl, const char* file, const char* func, char* fmt, ...)	{
#endif
	if(logready == 0)	return;
	va_list argptr;
	va_start(argptr, fmt);
	mutex_acquire(cpu_loglock());
#if !defined(CONFIG_SIMPLE_LOG_FORMAT)
	printf("%s|%s|%s|", lvl, file, func);
#endif
	vprintf(fmt, argptr);
	va_end(argptr);
	mutex_release(cpu_loglock());
}
