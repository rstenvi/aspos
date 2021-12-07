/**
* Driver to process CPU information.
*/

#include "kernel.h"

extern struct os_data osdata;

int init_cpus(void)	{
	int i;
	struct dtb_node* cpu = dtb_find_name("cpus", true, 0);
	struct cpus* c = &(osdata.cpus);

	c->numcpus = cpu->numchilds;
	if(c->numcpus > CONFIG_MAX_CPUS)	{
		logw("%i CPUs are available, but build only support %i\n",
			c->numcpus, CONFIG_MAX_CPUS);
		c->numcpus = CONFIG_MAX_CPUS;
	}

	for(i = 0; i < c->numcpus; i++)	{
		struct dtb_node* child = cpu->childs[i];
		c->cpus[i].compatible = (char*)dtb_get_string(child, "compatible");
		int count = 0;
		uint32_t* _x = dtb_get_ints(child, "reg", &count);
		ASSERT_TRUE(count == 1, "Unexpected count");
		c->cpus[i].cpuid = _x[0];

		// All CPUs are considered off until they are running a thread
		c->cpus[i].state = DEFAULT;
		c->cpus[i].busyloop = NULL;
		mutex_clear(&(c->cpus[i].readylock));
	}
	return 0;
}

driver_init(init_cpus);

int cpus_exit(void)	{
	int i;
	struct cpus* c = &(osdata.cpus);
	for(i = 0; i < c->numcpus; i++)	{
		if(c->cpus[i].busyloop)
			kfree(c->cpus[i].busyloop);
	}
	return OK;
}
poweroff_exit(cpus_exit);
