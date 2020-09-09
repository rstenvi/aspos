/**
* Keep track of which CPU features are supported and which are enabled.
*/

#include "kernel.h"
#include "aarch64.h"
#include "arch.h"

extern ptr_t ALTINSTR_START;
extern ptr_t ALTINSTR_STOP;


static inline int mmfr1_get_bits(int off, int bits)	{
	ptr_t mmfr, mask;
	asm("mrs %0, ID_AA64MMFR1_EL1" : "=r"(mmfr));
	mask = ((1 << bits) - 1) << off;
	mmfr &= mask;
	mmfr >>= off;
	return mmfr;
}
static inline int mmfr2_get_bits(int off, int bits)	{
	ptr_t mmfr, mask;
	asm("mrs %0, ID_AA64MMFR2_EL1" : "=r"(mmfr));
	mask = ((1 << bits) - 1) << off;
	mmfr &= mask;
	mmfr >>= off;
	return mmfr;
}


#define MMFR1_PAN_SHIFT 20
#define MMFR1_PAN_BITS  4
#define SCTLR_SPAN_DISABLE (1UL<<23)

#if CONFIG_AARCH64_PAN
bool pan_supported(void)	{
	return (mmfr1_get_bits(MMFR1_PAN_SHIFT, MMFR1_PAN_BITS) != 0);
}

bool pan_enable_next_intr(void)	{
	if(pan_supported())	{
		ptr_t sctlr = read_sctlr_el1();
		sctlr &= ~(SCTLR_SPAN_DISABLE);
		write_sctlr_el1(sctlr);
		return true;
	}
	return false;
}
#endif


typedef bool (*cpu_feat_check_t)(void);
typedef bool (*cpu_feat_enable_t)(void);
typedef bool (*cpu_feat_disable_t)(void);

enum FEAT_STATUS {
	UNSET = 0,
	SUPPORTED,
	UNSUPPORTED,
	ENABLED,
};

struct cpu_feat {
	char* name;
	uint32_t id;
	cpu_feat_check_t check;
	cpu_feat_enable_t enable;
	cpu_feat_disable_t disable;
	bool percore;
	enum FEAT_STATUS status;
};

static struct cpu_feat features[] = {
#if CONFIG_AARCH64_PAN
	{
		.name = "PAN",
		.id = CPU_FEATURE_PAN,
		.check = pan_supported,
		.enable = pan_enable_next_intr,
		.disable = pan_disable,
		.percore = true,
	}
#endif
};

static int perform_patch(uint32_t id)	{
	ptr_t start = &(ALTINSTR_START);
	ptr_t stop = &(ALTINSTR_STOP);
	ptr_t i;
	struct altinstr_repl* r;
	uint32_t* ins;

	for(i = start; i < stop; i+= sizeof(struct altinstr_repl))	{
		r = (struct altinstr_repl*)i;
		if(r->id == id)	{
			ins = (uint32_t*)r->addr;
			*ins = r->instruction;
		}
	}
}

static int _cpufeature_init(bool percpu)	{
	int items = sizeof(features) / sizeof(struct cpu_feat);
	int i;
	struct cpu_feat* f;

	for(i = 0; i < items; i++)	{
		f = &(features[i]);
		if(f->percore == percpu)	{
			logi("Checking support for %s\n", f->name);
			if(f->check())	{
				f->status = SUPPORTED;
				if(f->enable())	{
					logi("Enabling %s\n", f->name);
					perform_patch(f->id);
					f->status = ENABLED;
				}
			}
			else	{
				f->status = UNSUPPORTED;
			}
		}
	}
	return OK;
}

int cpufeature_percore_init(void)	{ return _cpufeature_init(true); }
cpucore_init(cpufeature_percore_init);

int cpufeature_init(void)			{ return _cpufeature_init(false); }
driver_init(cpufeature_init);

