/**
* Arm64 timer which used the GIC
*
* DTB information
* - `interrupts` contain the following fields
*   - secure timer irq
*   - non-secure timer irq
*   - virtual timer irq
*   - hypervisor timer irq
*/
#include "kernel.h"

// TODO: Temporary mappings
// We use the virtual one here
#define TMP_INTR_EL1_TYPE     1
#define TMP_INTR_EL1_IRQNO    0x0b
#define TMP_INTR_EL1_IRQFLAGS 0x104

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

int timer_irq_cb(void)	{
	timer_reconf();
	thread_downtick();
	return 0;
}


int _init_irqno(int irqno)	{
	irqno += gic_ppi_offset();

//	gic_set_edge(irqno);
	gic_set_priority(irqno, 1);
	gic_clear_intr(irqno);
	gic_enable_intr(irqno);

	gic_register_cb(irqno, timer_irq_cb);

	// Do callback for initial config
	timer_reconf();

}

int init_timer(void)	{
	logi("init timer\n");
	int irqno = TMP_INTR_EL1_IRQNO;
	_init_irqno(irqno);

	return 0;
}

driver_init(init_timer);

