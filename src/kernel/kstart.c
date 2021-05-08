#include "kernel.h"

#if defined(CONFIG_DRIVER_USERID_AUTO_INCREMENT)
uint32_t last_driver_uid = USERID_LAST;
#endif
__attribute__((__section__(".bss"))) struct os_data osdata;

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
static void init_after_linear_region(void);
static void kstart_stage2(void);
static void init_sbrk(void);
static void init_drivers(void);
static int init_memory(ptr_t kimage);
void secondary_cpu_start(void);
//static int get_memory_dtb(ptr_t* outaddr, ptr_t* outlen);

//ptr_t secondary_cpu_reset = 0;

#if defined(CONFIG_EARLY_UART)
int early_printf(const char* fmt, ...)	{
	uart_early_write(fmt);
}
#endif


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
__noreturn void kstart(ptr_t kimage, void* dtb, ptr_t kpgd, ptr_t upgd, ptr_t seccpu)	{
	struct os_data* osd = &(osdata);
	// Temporary location for DTB
	// We still use physical address, but it's been identity mapped
	osd->dtb = dtb;
	osd->kernel_start = (ptr_t)&(KERNEL_START);
	osd->kernel_end = (ptr_t)&(KERNEL_END);
	osd->linear_offset = 0;
	osd->cpu_reset_func = seccpu;

	mutex_clear(cpu_loglock()); 

	uart_early_init();
#if defined(CONFIG_EARLY_UART)
	// We can't use printf until after we have set up dynamic memory and brk
	osd->kgetc = uart_early_getc;
	osd->kputs = uart_early_write;
	osd->kputc = uart_early_putc;
	osd->printk = early_printf;
#endif

	// Initially we use identity map
	osd->kpgd = kpgd;
	osd->upgd = upgd;

	init_memory(kimage);

	init_vmmap();
	ptr_t stack = vmmap_alloc_pages(CONFIG_EXCEPTION_STACK_BLOCKS, PROT_RW, VMMAP_FLAG_NONE);
	stack += (PAGE_SIZE * CONFIG_EXCEPTION_STACK_BLOCKS);

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

	// Linear region is set up, we must now reconfigure some addresses so that we can
	// remove identity map and use that for user region instead
	osd->linear_offset = ARM64_VA_LINEAR_START;
	osd->kpgd += osd->linear_offset;
	osd->upgd += osd->linear_offset;

	init_after_linear_region();

	init_sbrk();

	mmu_second_init();

#if defined(CONFIG_KASAN)
	kasan_init();
	kasan_mark_valid((ptr_t)osd->dtb, MB);
	kasan_mark_valid(VMMAP_START, PAGE_SIZE);
	kasan_mark_valid(ARM64_VA_KERNEL_STACK_START, ARM64_VA_KERNEL_STACK_SIZE);
#endif

#if defined(CONFIG_EARLY_UART)
	osd->printk = printf;
#endif

	// This should be the first message printed
	logi("Reached stage 2 with memory set up\n");

	logi("Taking second pass at DTB\n");
	struct dtb_node* root = dtb_parse_data(osd->dtb);
	dtb_second_pass(root);
	osd->dtbroot = root;

	// All code from here on can use a nicer interface to retrieve DTB data

	logi("Initializing drivers\n");
	init_drivers();

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
	mutex_acquire( &(cps->cpus[0].readylock) );

	for(i = 1; i < cps->numcpus; i++)	{
		if(cps->cpu_on)	{
			// Acquire the lock first
			mutex_acquire( &(cps->cpus[i].readylock) );

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
	logi("Initializing user memory\n");
	mmu_init_user_memory((ptr_t*)osdata.upgd);

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

	logi("Enabling IRQ\n");
	enable_irq();

	// We always release the boot cpu lock because all CPUs are using this lock
	// for waiting
	logi("Releasing readylock on boot CPU\n");
	mutex_release( &(osdata.cpus.cpus[0].readylock) );

	logi("Starting thread scheduler\n");
	thread_schedule_next(0);
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
	int ret;
	for(curr = start; curr < stop; curr += sizeof(ptr_t))	{
		func = (deviceinit_t)(*((ptr_t*)(curr)));
		logd("Calling driver @ %lx\n", func);
		ret = func();
		logi("Driver @ %lx returned %i\n", func, ret);
	}
}

static int init_memory(ptr_t kimage)	{
	ptr_t addr, length;
	if(get_memory_dtb(&addr, &length) != OK)	PANIC("Unable to get memory from dtb\n");

	osdata.pmm.start = addr;
	osdata.pmm.end = addr + length;

	pmm_init();
	pmm_mark_mem(kimage, osdata.kernel_end - ARM64_VA_KERNEL_FIRST_ADDR);
	pmm_mark_mem((ptr_t)(osdata.dtb), ((ptr_t)osdata.dtb + MB) );

	//mmu_create_linear(0, osdata.pmm.end);
	mmu_create_linear(osdata.pmm.start, osdata.pmm.end);

	// Should use linear offset for DTB from now on
	osdata.dtb = (void*)((ptr_t)osdata.dtb + ARM64_VA_LINEAR_START);
	return OK;
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

static void init_after_linear_region(void)	{
	ptr_t start = (ptr_t)(&HMEMFUNC_START);
	ptr_t stop = (ptr_t)(&HMEMFUNC_STOP);
	ptr_t curr;
	ptr_t lin = cpu_linear_offset();
	int ret;

	highmeminit_t func;
	for(curr = start; curr < stop; curr += sizeof(ptr_t))	{
		func = (highmeminit_t)(*((ptr_t*)(curr)));
		ret = func(lin);
	}
}

#if defined(CONFIG_SIMPLE_LOG_FORMAT)
void klog(char* fmt, ...)	{
#else
void klog(const char* lvl, const char* file, const char* func, char* fmt, ...)	{
#endif
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
