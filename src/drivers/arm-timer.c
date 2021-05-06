/**
* Arm64 timer which used the GIC
*
* DTB information
* - `interrupts` contain the following fields
*   - secure timer irq
*   - non-secure timer irq
*   - virtual timer irq
*   - hypervisor timer irq
*
* Example of DTB from qemu
* timer {
*	interrupts = <0x01 0x0d 0x104 0x01 0x0e 0x104 0x01 0x0b 0x104 0x01 0x0a 0x104>;
*	always-on;
*	compatible = "arm,armv8-timer\0arm,armv7-timer";
* };
*/

#include "kernel.h"
#include "gic.h"

#define INTRMAP_SECURE_IDX    0
#define INTRMAP_NONSECURE_IDX 1
#define INTRMAP_VIRTUAL_IDX   2
#define INTRMAP_HYPERV_IDX    3

#define ARM_TIMER_PRIORITY 1

struct arm_timer {
	struct dtb_intr_map intrmap[4];
	int idxinuse;
};
static struct arm_timer arm_timer = {0};

static int timer_reconf(void)	{
	uint64_t count, freq;
	// Configure timer
	arm64_disable_cntv();

	freq = read_cntfrq_el0();

	double mul = (double)CONFIG_TIMER_MS_DELAY / 1000;
	freq *= mul;

	// Current count
	count = read_cntvct_el0();

	// Write back count for interrupt
	write_cntv_cval_el0(count + (freq));

	// Enable timer
	arm64_enable_cntv();
	return 0;
}

int timer_irq_cb(int irqno)	{
	timer_reconf();
	thread_downtick();
	return 0;
}


int init_timer(void)	{
	logi("init timer\n");
	int count, res;
	struct dtb_node* timer = dtb_find_name("timer", true, 0);
	ASSERT_FALSE(PTR_IS_ERR(timer), "Unable to find timer DTB object");

	if(!dtb_is_compatible(timer, "arm,armv8-timer"))	{
		printf("driver for timer is not compatible\n");
		dtb_dump_compatible(timer);
		PANIC("");
	}

	uint32_t* ints = dtb_get_ints(timer, "interrupts", &count);
	if(count < 9)	{
		PANIC("Did not get virtual timer");
	}

	// Copy over the map
	memcpy(&(arm_timer.intrmap), ints, count * sizeof(uint32_t));

	// Use the virtual timer
	arm_timer.idxinuse = INTRMAP_VIRTUAL_IDX;

	gic_dtb_default_setup(&(arm_timer.intrmap[arm_timer.idxinuse]), ARM_TIMER_PRIORITY, timer_irq_cb);

	timer_reconf();

	return 0;
}

driver_init(init_timer);

