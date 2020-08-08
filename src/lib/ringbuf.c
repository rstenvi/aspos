#include "lib.h"


struct ringbuf* ringbuf_alloc(size_t sz)	{
	struct ringbuf* ret = (struct ringbuf*)malloc(sizeof(struct ringbuf));
	if(ret == NULL)	return ERR_ADDR_PTR(-1);

	ret->data = malloc(sz);
	if(ret->data == NULL)	return ERR_ADDR_PTR(-1);

	ret->len = sz;
	ret->nextfree = 0;
	mutex_clear(&ret->lock);

	return ret;
}

void* ringbuf_get_data(struct ringbuf* rb, size_t len)	{
	void* ret = ERR_ADDR_PTR(-1);
	if(len > rb->len)	return ret;

	mutex_acquire(&rb->lock);

	// If we don't have enough space in buffer, we start at beginning
	if(len > (rb->len - rb->nextfree))	rb->nextfree = 0;

	ret = (rb->data + rb->nextfree);
	rb->nextfree += len;

	mutex_release(&rb->lock);

	int i;
	for(i = 0; i < len; i++)	{
		*((char*)(ret+i)) = 0x00;
	}
	//memcpy(ret, 0x00, len);
	return ret;
}
