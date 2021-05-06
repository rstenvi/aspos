#include "lib.h"


struct ringbuf* ringbuf_alloc(size_t sz)	{
	TMALLOC(ret, struct ringbuf);
	if(PTR_IS_ERR(ret))	return ERR_ADDR_PTR(-MEMALLOC);

	ret->start = kmalloc(sz);
	if(ret->start == NULL)	return ERR_ADDR_PTR(-1);

	ret->maxlen = sz;
	ret->cidx = ret->lidx = 0;
	ret->full = false;
	mutex_clear(&ret->lock);

	return ret;
}

void ringbuf_delete(struct ringbuf* rb)	{
	mutex_acquire(&rb->lock);
	kfree(rb->start);
	kfree(rb);
}

int ringbuf_num_bytes(struct ringbuf* rb)	{
	int ret = rb->lidx - rb->cidx;

	if(ret <= 0 && rb->full)	return rb->maxlen + ret;

	return ret;
}

int ringbuf_write(struct ringbuf* rb, void* from, int size)	{
	int rsize = MIN(size, (rb->maxlen - rb->lidx));
	memcpy(rb->start + rb->lidx, from, rsize);

	rb->lidx += rsize;

	if(rb->lidx >= rb->maxlen)	{
		rb->full = true;
		rb->lidx = 0;
	}

	// If we have reached end of our array and we have more to copy
	if(rsize < size)	{
		return rsize + ringbuf_write(rb, from + rsize, size - rsize);
	}

	return rsize;
}

int ringbuf_read(struct ringbuf* rb, void* to, int size)	{
//	mutex_acquire(&rb->lock);
	int rsize = MIN(size, (rb->lidx - rb->cidx));
	/*
	* rsize can now be negative for three reasons
	* 1. The buffer is filled with exactly the max number of bytes, rsize == 0
	* 2. The buffer wraps around to beginning
	* 3. The buffer is empty
	*/
	if(rsize <= 0)	{
		if(rb->full)	{
			if(rsize == 0)	rsize = MIN(size, rb->maxlen);
			else			rsize = MIN(size, (rb->maxlen - rb->cidx));
		}
		else	{
			rsize = 0;
			goto done;
		}
	}

	memcpy(to, (rb->start + rb->cidx), rsize);

	rb->cidx += rsize;
	if(rb->cidx >= rb->maxlen)	{
		rb->full = false;
		rb->cidx = 0;
	}

	if(rsize < size)	{
		return rsize + ringbuf_read(rb, to + rsize, size - rsize);
	}

	// If we have not more data left, we reset to 0 so that we can potentially
	// get data quicker in the future by avoiding multiple calls to memcpy
	if(rb->lidx == rb->cidx)	{
		rb->lidx = rb->cidx = 0;
	}

done:
//	mutex_release(&rb->lock);
	return rsize;
}
