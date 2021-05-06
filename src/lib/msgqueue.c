/**
* Message queue implementation.
*/

#include "lib.h"

struct mq {
	void** msgs;
	size_t ccount, mcount;
	mutex_t lock;
};

int mq_init(struct mq* mq, size_t max)	{
	mq->msgs = (void**)kmalloc( sizeof(void*) * max);
	mq->ccount = 0;
	mq->mcount = max;
	mutex_clear(&mq->lock);
	return OK;
}

struct mq* mq_new(size_t max)	{
	TMALLOC(mq, struct mq);
	if(PTR_IS_ERR(mq))	return ERR_ADDR_PTR(-MEMALLOC);

	mq_init(mq, max);
	return mq;
}

int mq_send(struct mq* mq, void* msg)	{
	int res = -SPACE_FULL;
	mutex_acquire(&mq->lock);
	if(mq->ccount < mq->mcount)	{
		mq->msgs[mq->ccount++] = msg;
		res = OK;
	}
	mutex_release(&mq->lock);
	return res;
}

/* todo: Inefficient implementation */
static void _mq_push_down(struct mq* mq)	{
	int i;
	for(i = 0; i < mq->ccount; i++)	{
		mq->msgs[i] = mq->msgs[i+1];
	}
}

void* mq_try_recv(struct mq* mq)	{
	void* ret = NULL;
	mutex_acquire(&mq->lock);
	if(mq->ccount > 0)	{
		ret = mq->msgs[0];
		mq->ccount--;
		_mq_push_down(mq);
	}
	mutex_release(&mq->lock);
	return ret;
}

void* mq_recv(struct mq* mq)	{
	void* ret = NULL;
	ret = mq_try_recv(mq);
	if(PTR_IS_ERR(ret))	{
		ret = ERR_ADDR_PTR(-BLOCK_CURRENT);
	}
	return ret
}
