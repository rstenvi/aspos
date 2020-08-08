#include <stdint.h>

#include "lib.h"
#include "lwip/sys.h"


void sys_init(void) {
	printf("%s\n", __func__);
}


sys_thread_t sys_thread_new(const char* name, lwip_thread_fn thread, void* arg, int stacksize, int prio) {
	printf("%s\n", __func__);
	new_thread( (uint64_t)thread, 1, arg);
	return ERR_OK;
}

void sys_msleep(uint32_t ms)	{ msleep(ms); }


void sys_mark_tcpip_thread(void) {
	printf("%s\n", __func__);
	// Not sure if we need to do anything
}

volatile uint8_t tcpip_lock = 0;

void sys_lock_tcpip_core(void)	{
	printf("%s\n", __func__);
	mutex_acquire(&tcpip_lock);
}

void sys_unlock_tcpip_core(void)	{
	printf("%s\n", __func__);
	mutex_release(&tcpip_lock);
}
