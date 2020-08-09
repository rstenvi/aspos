#include <stdint.h>

#include "lib.h"
#include "lwip/sys.h"

#define MBOX_INCREMENT 10
#define MBOX_FETCH_SLEEP_MS 10

struct sys_mbox {
	void** data;
	size_t numitems, maxitems;
};

err_t sys_mbox_new(sys_mbox_t *mbox, int size)	{
	struct sys_mbox* m;
	m = (struct sys_mbox*)malloc( sizeof(struct sys_mbox) );
	if(m == NULL)	return ERR_MEM;
	memset(m, 0x00, sizeof(struct sys_mbox));

	m->maxitems = size;
	m->numitems = 0;

	if(size > 0)	{
		m->data = (void**)malloc( sizeof(void*) * size);
		if(m->data == NULL)	{
			free(m);
			return ERR_MEM;
		}
	}

	*mbox = m;
	return ERR_OK;
}

static err_t _sys_mbox_check_space(sys_mbox_t *mbox)	{
	struct sys_mbox* m = *mbox;
	if(m->numitems == m->maxitems)	{
		m->maxitems += MBOX_INCREMENT;
		m->data = (void**)realloc(m->data, sizeof(void*) * m->maxitems);
		if(m->data == NULL)	return ERR_MEM;
	}
	return ERR_OK;
}
 
void sys_mbox_post(sys_mbox_t *mbox, void *msg)	{
	struct sys_mbox* m = *mbox;
	/*if(m->numitems == m->maxitems)	{
		printf("full, temporarily fatal\n");
		exit(1);
	}*/
	
	err_t ret = _sys_mbox_check_space(mbox);
	if(ret != ERR_OK)	{
		printf("FATAL: Failed to allocate space for mbox\n");
		exit(1);
	}

	m->data[m->numitems++] = msg;
}
 
err_t sys_mbox_trypost(sys_mbox_t *mbox, void *msg)	{
	/* todo: Unsure if this can cause problems */
	sys_mbox_post(mbox, msg);
	return ERR_OK;
}
 
err_t sys_mbox_trypost_fromisr(sys_mbox_t *mbox, void *msg)	{
	return sys_mbox_trypost(mbox, msg);
}
 
 
uint32_t sys_arch_mbox_tryfetch(sys_mbox_t *mbox, void **msg)	{
	struct sys_mbox* m = *mbox;
	if(m->numitems == 0)	return SYS_MBOX_EMPTY;

	*msg = m->data[--m->numitems];
	return ERR_OK;
}


uint32_t sys_arch_mbox_fetch(sys_mbox_t *mbox, void **msg, uint32_t timeout)	{
	struct sys_mbox* m = *mbox;
	err_t ret;
	signed long count = timeout;

	/* block for timeout milliseconds or forever if timeout == 0 */
	while(
		(ret = sys_arch_mbox_tryfetch(mbox, msg)) != ERR_OK &&
		((timeout > 0 && count > 0) || (timeout == 0))
	)	{
		msleep(MBOX_FETCH_SLEEP_MS);
		count -= MBOX_FETCH_SLEEP_MS;
	}

	// Return error if we exited loop without retrieving an item
	if(ret != ERR_OK)	return SYS_ARCH_TIMEOUT;

	return ret;
}
 
void sys_mbox_free(sys_mbox_t *mbox)	{
	struct sys_mbox* m = *mbox;
	if(m->data != NULL)	free(m->data);
}
