#include "kernel.h"


struct os_data osdata;

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
static void call_inits(ptr_t start, ptr_t stop);
static void init_after_linear_region(void);
static void kstart_stage2(void);
static void init_sbrk(void);
static void init_drivers(void);
static int init_memory(ptr_t kimage);
static int get_memory_dtb(ptr_t* outaddr, ptr_t* outlen);

ptr_t secondary_cpu_reset = 0;

int early_printf(const char* fmt, ...)	{
	uart_early_write(fmt);
}


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
	// Temporary location for DTB
	// We still use physical address, but it's been identity mapped
	osdata.dtb = dtb;
	osdata.kernel_start = (ptr_t)&(KERNEL_START);
	osdata.kernel_end = (ptr_t)&(KERNEL_END);
	osdata.linear_offset = 0;

	secondary_cpu_reset = seccpu;
	mutex_clear(cpu_loglock()); 


#if defined(CONFIG_EARLY_UART)
	// We can't use printf until after we have set up dynamic memory and brk
	uart_early_init();
	osdata.kgetc = uart_early_getc;
	osdata.kputs = uart_early_write;
	osdata.kputc = uart_early_putc;
	osdata.printk = early_printf;
#endif
	// Initially we use identity map

	osdata.kpgd = kpgd;
	osdata.upgd = upgd;


	init_memory(kimage);

	init_vmmap();
	ptr_t stack = vmmap_alloc_pages(CONFIG_EXCEPTION_STACK_BLOCKS, PROT_RW, VMMAP_FLAG_NONE);
	stack += (PAGE_SIZE * CONFIG_EXCEPTION_STACK_BLOCKS);

	/*
	* todo: This is only a fix for gdb-scripts.
	* It can be at the top, but it them becomes more cumbersome to debug.
	*/
	stack -= 32;

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
static void kstart_stage2(void) {

	// Linear region is set up, we must now reconfigure some addresses so that we can
	// remove identity map and use that for user region instead
	osdata.linear_offset = ARM64_VA_LINEAR_START;
	osdata.kpgd += osdata.linear_offset;
	osdata.upgd += osdata.linear_offset;

	init_after_linear_region();

	init_sbrk();

	mmu_second_init();

	osdata.printk = printf;

	logi("Reached stage 2 with memory set up\n");

	osdata.fileids = bm_create(1000);
	ASSERT_TRUE(osdata.fileids != NULL, "memory");

	logi("Taking second pass at DTB\n");
	struct dtb_node* root = dtb_parse_data(osdata.dtb);
	dtb_second_pass(root);
	osdata.dtbroot = root;

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
	mutex_acquire( &(osdata.cpus.cpus[0].readylock) );

	for(i = 1; i < osdata.cpus.numcpus; i++)	{
		if(osdata.cpus.cpu_on)	{
			// Acquire the lock first
			mutex_acquire( &(osdata.cpus.cpus[i].readylock) );

			// Start the CPU
			osdata.cpus.cpu_on(osdata.cpus.cpus[i].cpuid, secondary_cpu_reset);

			// The CPU has finished booting, it will release the lock
			mutex_acquire( &(osdata.cpus.cpus[i].readylock) );
		}
		else	{
			logw("No driver is able to reset additional CPU with ID %i\n",
				osdata.cpus.cpus[i].cpuid
			);
		}
	}

	// Init user memory and remove identity map
	logi("Initializing user memory\n");
	mmu_init_user_memory();

	// Load ELF from initrd
	struct loaded_exe* exe = elf_load((void*)(osdata.linear_offset + 0x44000000));
	logi("entry @ 0x%lx\n", exe->entry);
	thread_new_main(exe);

	logi("Trigger per-CPU code\n");
	percpu_start();
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
	thread_schedule_next();
}

void secondary_cpu_start(void)	{
	// Release own lock first
	int id = cpu_id();
	mutex_release( &(osdata.cpus.cpus[id].readylock) );

	// Wait until we can acquire boot lock before continuing
	// We immediately release it so that the next CPU can continue
	mutex_acquire( &(osdata.cpus.cpus[0].readylock) );

	// Shared function for all per-cpu functionality
	percpu_start();
}


/**
* Panic implementation which prints an error message and halts execution.
*/
void panic(const char* msg, const char* file, int line)	{
	// We always want to reliably print some type of message
	osdata.kputs(msg);

	// We then try and print some details about environment
	osdata.printk("Location: %s:%i\n", file, line);
	arch_dump_regs();
	while(1);
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


static void call_inits(ptr_t start, ptr_t stop)	{
	ptr_t curr;
	deviceinit_t func;
	int ret;
	for(curr = start; curr < stop; curr += sizeof(ptr_t))	{
		func = (deviceinit_t)(*((ptr_t*)(curr)));
		logi("Calling driver @ %p\n", func);
		ret = func();
		logi("Driver @ %p returned %i\n", func, ret);
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
	osdata.dtb += cpu_linear_offset();
	return OK;
}

static void init_sbrk(void)	{
	struct sbrk* brk = cpu_get_kernbrk();
	logd("Initializing sbrk\n");

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

static int get_memory_dtb(ptr_t* outaddr, ptr_t* outlen)	{
	uint32_t cells_sz, cells_addr;

	void* reg = dtb_get_ref("memory", "reg", 0, &cells_sz, &cells_addr);
	ASSERT_TRUE(reg != NULL, "Unable to get memory from dtb");

	ASSERT_TRUE(cells_sz == 2 && cells_addr == 2, "Unsupported sizes");

	uint64_t addr = 0, length = 0;


	uint32_t tmp = dtb_translate_ref(reg);
	addr = (uint64_t)(tmp) << 32;
	tmp = dtb_translate_ref(reg + 4);
	addr += tmp;

	tmp = dtb_translate_ref(reg + 8);
	length = (uint64_t)(tmp) << 32;
	tmp = dtb_translate_ref(reg + 12);
	length += tmp;

	*outaddr = addr;
	*outlen = length;
	return OK;
}

