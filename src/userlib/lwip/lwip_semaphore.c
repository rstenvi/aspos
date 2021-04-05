#include <stdint.h>

#include "lib.h"
#include "lwip/sys.h"

err_t sys_sem_new(sys_sem_t *sem, u8_t count)	{
	*sem = sem_new(count);

	return ERR_OK;
}

void sys_sem_signal(sys_sem_t *sem)	{
	sem_signal(*sem);
}

uint32_t sys_arch_sem_wait(sys_sem_t *sem, uint32_t timeout)	{
	// Return SYS_ARCH_TIMEOUT on timeout
	signed long count = timeout;
	int ret;

	while(
		(ret = sem_try_wait(*sem)) < 0 &&
		((timeout > 0 && count > 0) || (timeout == 0))
	)	{
		count -= 20;
		msleep(20);
	}

	if(ret < 0)	return SYS_ARCH_TIMEOUT;

	return ERR_OK;
}

void sys_sem_free(sys_sem_t *sem)	{
	sem_free(*sem);
}
