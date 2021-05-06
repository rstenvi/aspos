#ifndef __DRIVERS_H
#define __DRIVERS_H

#include <stdint.h>
#include <stddef.h>
#include "types.h"

/**
* Function signature for callbacks after an IRQ is triggered.
*/
typedef int (*gic_cb)(int);

int gic_find_pending(void);
void gic_disable_intr(int irq);
void gic_clear_intr(int irq);
void gic_enable_intr(int irq);

int gic_perform_cb(int irqno);
int gic_ppi_offset(void);
int gic_spi_offset(void);
int gic_intr_processed(int irq);
int gic_send_sgi_cpu(int irqno, int cpuid);

int gic_set_edge(int irqno);
int gic_set_priority(int irqno, int pri);

int gic_register_cb(int irqno, gic_cb cb);


#define SGI_IRQ_SCHEDULE 1

#include "kernel.h"

/**
* Signature driver init function registered with :c:type:`driver_init`,
* :c:type:`early_init` or :c:type:`early_hw_init`
*/
typedef int (*deviceinit_t)(void);

/**
* Signature for driver init function registered with :c:type:`highmem_init`.
*/
typedef int (*highmeminit_t)(ptr_t);



#define __kdatadrvfunc __attribute__((__section__(".kernel.data.drvfunc")))
#define __kdatacpufunc __attribute__((__section__(".kernel.data.cpufunc")))
#define __kdatahmemfunc __attribute__((__section__(".kernel.data.hmemfunc")))
#define __kdataearlyfunc __attribute__((__section__(".kernel.data.earlyfunc")))
#define __kdataearlyhwfunc __attribute__((__section__(".kernel.data.earlyhwfunc")))
#define __kdataexitfunc   __attribute__((__section__(".kernel.data.exitfunc")))

/**
* Functions registered at this step will be called after the system has been set
* up. Most drivers will register at this step.
*/
#define driver_init(func) __kdatadrvfunc deviceinit_t _UNIQUE_ID(func,__LINE__) = func


/**
* Functions registered at this step will be called by each CPU when they boot up.
*/
#define cpucore_init(func) __kdatacpufunc deviceinit_t _UNIQUE_ID(func,__LINE__) = func

/**
* Functions registered at this step will be called as early as possible. The
* functions will have access to DTB, but no other initializations has been
* performed. The system will be running virtual memory disabled and physical
* memory manager has not been intialized.
*
* Parsing of dtb entries can be done with `dtb_get_ref`
*/
#define early_init(func) __kdataearlyfunc deviceinit_t _UNIQUE_ID(func,__LINE__) = func

/**
* Functions registered at this step will be called AFTER the linear regions has
* been set up and BEFORE the identity map is removed. In other words, if the
* driver depends on some data in identity map or it has pointers pointing to the
* idmap regions, it should register this function and fix them.
*
* The function will receive the start of the linear region as the first argument.
*/
#define highmem_init(func) __kdatahmemfunc highmeminit_t _UNIQUE_ID(func,__LINE__) = func

/**
* Function which setup hardware that other drivers may be dependent on.
*
* These functions will be called after DTB has been parsed and after virtual
* memory has been set up. The environment is essentially the same as for
* `driver_init`, but some pieces of hardware has not been configured yet.
*/
#define early_hw_init(func) __kdataearlyhwfunc deviceinit_t _UNIQUE_ID(func,__LINE__) = func

#define poweroff_exit(func) __kdataexitfunc    deviceinit_t _UNIQUE_ID(func,__LINE__) = func

#endif
