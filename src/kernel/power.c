#include "kernel.h"

extern ptr_t EXITFUNC_START;
extern ptr_t EXITFUNC_STOP;

/**
* Power off the computer.
*
* The architecture must register :c:type:`poweroff`, otherwise the function will
* just panic.
*/
void _poweroff_cleanup(void)	{
	logi("System is powering down\n");
	ptr_t start, stop;
//	dtb_destroy(cpu_get_parsed_dtb());

	start = (ptr_t)(&EXITFUNC_START);
    stop = (ptr_t)(&EXITFUNC_STOP);
    call_inits(start, stop);

#if defined(CONFIG_KASAN)
	kasan_print_allocated();
#endif

}
__noreturn void kern_poweroff(bool force)	{
	if(!force)	_poweroff_cleanup();

	if(osdata.cpus.poweroff == NULL)	PANIC("Poweroff has not been configured\n");

	osdata.cpus.poweroff();
}
