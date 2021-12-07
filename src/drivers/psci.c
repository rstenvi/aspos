/**
* Driver for v0.2 of ARM PSCI
*/
#include "kernel.h"


#define PSCI_VERSION  0x84000000
#define PSCI_POWEROFF 0x84000008
#define PSCI_CPU_ON   0x84000003

extern uint64_t cpustackptr;
typedef ptr_t (*psci_method_t)();

ptr_t hvc();
ptr_t smc();

struct psci_struct	{
	psci_method_t method;
	uint16_t minor, major;
};

static struct psci_struct psci;
extern struct os_data osdata;

// static int psci_version()	{
// 	ptr_t version = hvc(PSCI_VERSION);
// 	logi("PSCI version | major: %i minor: %i\n",
// 		(version & 0xffff0000) >> 16, (version & 0xffff));
// 	return (int)version;
// }

__noreturn void psci_poweroff(void)	{
	psci.method(PSCI_POWEROFF);

	loge("Poweroff was unsuccessful\n");
	while(1);
}

int psci_cpu_on(int cpuid, ptr_t entry)	{
	// TODO: The stack parameter is not passed to us when running under trusted firmware
	// The registers are cleared when entering trusted mode, so not on us
	ptr_t stack = vmmap_alloc_pages(CONFIG_KERNEL_STACK_BLOCKS, PROT_RW, VMMAP_FLAG_NONE);
	cpustackptr = stack + (CONFIG_KERNEL_STACK_BLOCKS * PAGE_SIZE);
	psci.method(PSCI_CPU_ON, cpuid, entry, stack + (CONFIG_KERNEL_STACK_BLOCKS * PAGE_SIZE));

	return 0;
}

int init_psci(void)	{
	struct dtb_node* dtb = dtb_find_name("psci", true, 0);
	ASSERT_TRUE(dtb != NULL, "Unable to find psci in dtb\n");

	char* method = (char*)dtb_get_string(dtb, "method");
	ASSERT_TRUE(method, "Unable to find method\n");
	if(strcmp(method, "smc") == 0)	psci.method = smc;
	else if(strcmp(method, "hvc") == 0)	psci.method = hvc;
	else	PANIC("Unrecognized method in psci\n");

	ptr_t v = psci.method(PSCI_VERSION);
	psci.major = (v & 0xffff0000) >> 16;
	psci.minor = (v & 0x0000ffff);

	logi("PSCI version %i.%i\n", psci.major, psci.minor);

	// Set function pointers to control CPUs
	osdata.cpus.poweroff = psci_poweroff;
	osdata.cpus.cpu_on = psci_cpu_on;

	return 0;
}

driver_init(init_psci);
