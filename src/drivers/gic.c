/*
* Registers
* - GICD - Distribution register
* - GICC - Legacy CPU register when system register access is disabled (GICv3)
*   - Should be replaced by ICC when system register access is enabled
*
* Enabling system register access
* - Set ICC_SRE_EL1.SRE = 1
*
* Relevant registers
* - ID_AA64PFR0_EL1.GIC - System register GIC interface support
* - ID_PFR0_EL1.GIC - System register GIC CPU interface support
* - ISR_EL1.A - SError pending (aarch64)
* 
* GICv3 legacy support
* - v3 may support code written for v2
*
* compatible flags and meaning
* - arm,cortex-a15-gic = GICv2
* 
* Memory access to registers
* - Memory regions used for these registers must be marked as Device or Strongly-ordered in the
*   translation tables. Memory regions marked as Normal memory cannot access any of the GIC
*   registers, but can access caches or external memory as required.
* - Access to these registers must be with the single load and store instructions. Load-multiple and
*   load-double instructions result in a data abort exception to the requesting processor.
*   Store-multiple and store-double instructions result in the assertion of nINTERRIRQ.
* - Most of the registers can only be accessed with a word-size request. Some registers can also be
*   accessed with a byte-size request. Halfword and doubleword reads result in a data abort
*   exception to the requesting processor. Halfword and doubleword writes result in the assertion
*   of nINTERRIRQ.
*/
#include "kernel.h"
#include "aarch64.h"


struct irq_cb {
	int irqno;
	gic_cb cb;
};

struct gic_struct {
	ptr_t gicd_base, gicc_base;

	int numcbs;
	struct irq_cb* callbacks;
};

struct gic_struct gic_struct;

// TODO: Unsure how universal these values are
#define QEMU_GIC_INTNO_PPIO    16
#define QEMU_GIC_INTNO_SPIO    32
#define QEMU_GIC_INT_MAX       64


#define GICC_OFF_CTLR (0*4)
#define GICC_OFF_PMR  (1*4)
#define GICC_OFF_BPR  (2*4)
#define GICC_OFF_IAR  (3*4)
#define GICC_OFF_EOIR (4*4)
#define GICC_OFF_RPR  (5*4)
#define GICC_OFF_HPIR (6*4)
#define GICC_OFF_ABPR (7*4)
#define GICC_OFF_IIDR (63*4)

// Enable group 1
#define GICC_CTLR_ENABLE	 0x1
#define GICC_CTLR_DISABLE 0x0

#define GICC_IAR_INTR_SPURIOUS 0x3ff


#define GICD_CTLR			(0x000)
#define GICD_TYPER			(0x004)
#define GICD_IIDR			(0x008)
#define GICD_ISENABLER      (0x100)
#define GICD_ICENABLER  	(0x180)
#define GICD_ICPENDR		(0x280)
#define GICD_IPRIORITYR 	(0x400)
#define GICD_ITARGETSR   	(0x800)
#define GICD_ICFGR  		(0xc00)
#define GICD_ISPENDR		(0x200)

#define GICD_SGIR (0xf00)

#define GICD_CTLR_ENABLE	(0x1)
#define GICD_CTLR_DISABLE	(0x0)
#define GICD_ICFGR_LEVEL	(0x0)
#define GICD_ICFGR_EDGE		(0x2)

static void _gic_set_bit_u32(ptr_t base, uint32_t bit)	{
	volatile uint32_t val = 0;
	DMAR32(base + ((bit / 32) * 4), val);
	DMAW32(base + ((bit / 32) * 4), val | (1 << (bit % 32)) );
}


/**
* Mask a value in any number of bits in a 32-bit register.
* 
* If for example, the value contains 2 bits of information, it would roughly do:
* reg[idx/16] |= (val << (idx % 16));
*/
int _gic_mask_reg(ptr_t base, int idx, uint32_t val, uint32_t bits)	{
	uint32_t shift, reg, div, mask;

	div = 32 / bits;

	shift = (idx % div) * bits;

	DMAR32((base + ((idx / div) * 4)), reg);

	// The bits we want to change
	mask = ((1 << bits) - 1) << shift;

	// Clear the bits fields we configure
	reg &= ~(mask);
	// Set field
	reg |= (val << shift);

	// Write value back
	DMAW32(base + ((idx / div) * 4), reg);

	return 0;
}

int gic_ppi_offset(void) { return QEMU_GIC_INTNO_PPIO; }
int gic_spi_offset(void) { return QEMU_GIC_INTNO_SPIO; }

int gic_set_edge(int irqno)	{
	ptr_t rbase = gic_struct.gicd_base + GICD_ICFGR;

	return _gic_mask_reg(rbase, irqno, GICD_ICFGR_EDGE, 2);
}

int gic_set_priority(int irqno, int pri)	{
	return _gic_mask_reg(
		gic_struct.gicd_base + GICD_IPRIORITYR,
		irqno,
		pri,
		8
	);
}


void gic_clear_intr(int irq)	{
	_gic_set_bit_u32(gic_struct.gicd_base + GICD_ICPENDR, irq);
}

void gic_enable_intr(int irq)	{
	_gic_set_bit_u32(gic_struct.gicd_base + GICD_ISENABLER, irq);
}

void gic_disable_intr(int irq)	{
	_gic_set_bit_u32(gic_struct.gicd_base + GICD_ICENABLER, irq);
}

int _gicd_init(ptr_t base, int count, int spio, int ppio)	{
	int i;
	
	DMAW32(base + GICD_CTLR, GICD_CTLR_DISABLE);	// Disable

	// TODO: Don't think <= is correct
	// 
	// Disable all IRQs
	for(i = 0; i <= count / 32; i++)	DMAW32(base + GICD_ICENABLER + (i * 4), 0xffffffff);

	// Clear pending IRQs
	for(i = 0; i <= count / 32; i++)	DMAW32(base + GICD_ICPENDR + (i * 4), 0xffffffff);

	// Set to lowest priority
	for(i = 0; i <= count / 4; i++)	DMAW32(base + GICD_IPRIORITYR + (i * 4), 0xffffffff);

	// TODO: This writes too far
	// Set target to CPU 0
	for(i = (spio / 4); i <= count / 4; i++)	DMAW32(base + GICD_ITARGETSR + (i * 4), 0x01010101);

	// TODO: Same problem as above
	// Set level-triggered
	for(i = (ppio / 16); i <= count / 16; i++)	{
		DMAW32(base + GICD_ICFGR + (i * 4), 0x00000000);	// LEVEL
	}

	DMAW32(base + GICD_CTLR, GICD_CTLR_ENABLE);
	return 0;
}

int _gicc_init(ptr_t base)	{
	#define MAX_COUNT 1024
	volatile uint32_t entry;
	int count = 0;
	// Disable
	DMAW32(base + GICC_OFF_CTLR, GICC_CTLR_DISABLE);

	// Set lowest priority
	DMAW32(base + GICC_OFF_PMR, 0xff);

	// Handle as single group
	DMAW32(base + GICC_OFF_BPR, 0x00);

	// Try and read interrupt acknowledge and ackowledge if any is unacknowledged
	DMAR32(base + GICC_OFF_IAR, entry);
	while( (entry & 0x3ff) != GICC_IAR_INTR_SPURIOUS && count < MAX_COUNT)	{
		DMAW32(base + GICC_OFF_EOIR, entry);		// ACK
		DMAR32(base + GICC_OFF_IAR, entry);
		count++;
	}
	
	// We have exhausted the maximum number of attempts, but we don't know why
	if(count >= MAX_COUNT)	return -(1);

	// Enable
	DMAW32(base + GICC_OFF_CTLR, GICC_CTLR_ENABLE);
	return 0;
}

int gic_intr_processed(int irq)	{
	DMAW32(gic_struct.gicc_base + GICC_OFF_EOIR, (uint32_t)irq);
	return 0;
}

static int gic_max_interrupts(ptr_t base)	{
	volatile uint32_t r;
	DMAR32(base + GICD_TYPER, r);
	r &= 0b11111;
	return (32 * (r+1));
}

static bool gic_probe_pending(int irq)	{
	uint32_t val;
	DMAR32((ptr_t)gic_struct.gicd_base + GICD_ISPENDR + ((irq / 32) * 4), val);
	return ( (val & (1 << (irq % 32))) != 0);
}

int gic_find_pending(void)	{
	uint32_t r = DMAR32(gic_struct.gicc_base + GICC_OFF_IAR, r);
	return (r & 0b1111111111);
	/*
	int irq = 0;
	for(irq = 0; irq < 64; irq++)	{
		if(gic_probe_pending(irq) == true)	{
			return irq;
		}
	}
	return -1;
	*/
}

int gic_register_cb(int irqno, gic_cb cb)	{
	int idx = gic_struct.numcbs;
	gic_struct.numcbs += 1;
	gic_struct.callbacks = (struct irq_cb*)realloc(gic_struct.callbacks, sizeof(struct irq_cb) * gic_struct.numcbs);

	gic_struct.callbacks[idx].irqno = irqno;
	gic_struct.callbacks[idx].cb = cb;
	return 0;
}

int gic_perform_cb(int irqno)	{
	int i, res = -1;;
	for(i = 0; i < gic_struct.numcbs; i++)	{
		if(gic_struct.callbacks[i].irqno == irqno)	{
			res = gic_struct.callbacks[i].cb();
			break;
		}
	}
	return res;
}

#define GICD_SGIR_TLF_ALL_CPUS (0b01 << 24)
#define GICD_SGIR_TLF_CPULIST  (0b00 << 24)
#define GICD_SGIR_TL_SHIFT     (16)
int gic_send_sgi_all(int irqno)	{
	uint32_t t = GICD_SGIR_TLF_ALL_CPUS | irqno;
	DMAW32(gic_struct.gicd_base + GICD_SGIR, t);
	return 0;
}

int gic_send_sgi_cpu(int irqno, int cpuid)	{
	uint32_t t = GICD_SGIR_TLF_CPULIST | (1 << (cpuid + GICD_SGIR_TL_SHIFT)) | irqno;
	DMAW32(gic_struct.gicd_base + GICD_SGIR, t);
	return 0;
}

int init_gicd(void)	{
	int res, count;
	ptr_t gicd_base, gicd_len, gicc_base, gicc_len;

	uint32_t* regs;
	struct dtb_node* gic = dtb_find_name("intc@", false, 0);
	ASSERT_FALSE(PTR_IS_ERR(gic), "Unable to find gic DTB object");

	if(!dtb_is_compatible(gic, "arm,cortex-a15-gic"))	{
		printf("driver for gic is not compatible\n");
		dtb_dump_compatible(gic);
		PANIC("");
	}
	res = dtb_get_as_reg(gic, 0, &gicd_base, &gicd_len);
	res = dtb_get_as_reg(gic, 1, &gicc_base, &gicc_len);

	mmu_map_dma(gicd_base, gicd_base + gicd_len);
	mmu_map_dma(gicc_base, gicc_base + gicc_len);

	gic_struct.numcbs = 0;
	gic_struct.callbacks = NULL;
	gic_struct.gicd_base = cpu_linear_offset() + gicd_base;
	gic_struct.gicc_base = cpu_linear_offset() + gicc_base;

	res = _gicd_init(gic_struct.gicd_base, gic_max_interrupts(gic_struct.gicd_base), QEMU_GIC_INTNO_SPIO, QEMU_GIC_INTNO_PPIO);
	return res;
}

early_hw_init(init_gicd);

int init_gicc(void)	{
	int res = _gicc_init(gic_struct.gicc_base);
	return res;
}
cpucore_init(init_gicc);
