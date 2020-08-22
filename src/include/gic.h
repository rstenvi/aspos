#ifndef __GIC_H
#define __GIC_H

#include "kernel.h"


#define INTR_TYPE_SPI  0
#define INTR_TYPE_PPI  1

#define INTR_FLAG_EDGE_LOHI (1 << 0)
#define INTR_FLAG_EDGE_HILO (1 << 1)
#define INTR_FLAG_LEVEL_HI  (1 << 2)
#define INTR_FLAG_LEVEL_LO  (1 << 3)

#define INTR_IS_EDGE(x) (FLAG_SET(x,INTR_FLAG_EDGE_LOHI) || FLAG_SET(x,INTR_FLAG_EDGE_HILO))

struct dtb_intr_map {
	uint32_t type, irqno, flags;
} __attribute__((packed));

static inline int gic_dtb_to_irqno(struct dtb_intr_map* intr)	{
	switch(intr->type)	{
		case INTR_TYPE_SPI:
			return gic_spi_offset() + intr->irqno;
		case INTR_TYPE_PPI:
			return gic_ppi_offset() + intr->irqno;
		default:
			logw("Unsupported type: %i\n", intr->type);
			break;
	}
	return -1;
}

static inline int gic_dtb_default_setup(struct dtb_intr_map* intr, int pri, gic_cb cb)	{
	int irqno = gic_dtb_to_irqno(intr);
	if(INTR_IS_EDGE(intr->flags))	{
		gic_set_edge(irqno);
	}

	gic_set_priority(irqno, pri);
	gic_clear_intr(irqno);
	gic_enable_intr(irqno);

	gic_register_cb(irqno, cb);
	return OK;
}

#endif
