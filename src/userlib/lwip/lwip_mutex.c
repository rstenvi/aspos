#include <stdint.h>

#include "lib.h"
#include "lwip/sys.h"


err_t sys_mutex_new (sys_mutex_t *mutex)	{
	printf("%s\n", __func__);
	return ERR_OK;
}
 
void sys_mutex_lock(sys_mutex_t *mutex)	{
	printf("%s\n", __func__);
}
 
void sys_mutex_unlock(sys_mutex_t *mutex)	{
	printf("%s\n", __func__);
}
 
void sys_mutex_free(sys_mutex_t *mutex)	{
	printf("%s\n", __func__);
}




