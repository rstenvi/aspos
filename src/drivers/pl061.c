/**
* General Purpose Input Output controller for arm
*/
#include "kernel.h"

#define GPIODATA 0x00
#define GPIODIR  0x400


struct pl061_struct {
	ptr_t base;
	ptr_t length;
	uint32_t phandle;
};

static struct pl061_struct pl061;

// static void _as_input()   { DMAW8(pl061.base + GPIODIR, 0x00); }
// static void _as_output()  { DMAW8(pl061.base + GPIODIR, 0xff); }

int init_pl061(void)	{
	logd("Init pl061\n");
	
	struct dtb_node* dtb = dtb_find_name("pl061", false, 0);
	ASSERT_TRUE(dtb != NULL, "Unable to find pl061 object\n");

	pl061.phandle = dtb_get_int(dtb, "phandle");

	// Get memory region and map it in as DMA
	dtb_get_as_reg(dtb, 0, &pl061.base, &pl061.length);
	pl061.base = mmu_map_dma(pl061.base, pl061.base + pl061.length);

// 	_as_input();
// 	DMAW8(pl061.base, 0x74);
	return 0;
}

driver_init(init_pl061);

