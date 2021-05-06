#include "kernel.h"

#define MAX_IOVEC_COUNT 256

struct iovec* copy_iovec_from_user(const struct iovec* iov, int iovcnt)	{
	struct iovec* ret = NULL;
	if(iovcnt > MAX_IOVEC_COUNT)	return ERR_ADDR_PTR(-USER_FAULT);

	ret = kmalloc( sizeof(struct iovec) * iovcnt );
	if(PTR_IS_ERR(ret))	return ret;

	if(memcpy_from_user(ret, iov, sizeof(struct iovec) * iovcnt ))	{
		kfree(ret);
		return ERR_ADDR_PTR(-USER_FAULT);
	}
	return ret;
}

bool iovec_validate_addrs(const struct iovec* iov, int iovcnt)	{
	int i;
	for(i = 0; i < iovcnt; i++)	{
		if(!ADDR_USER(iov[i].iov_base))	return false;
		if(!ADDR_USER(iov[i].iov_base + iov[i].iov_len))	return false;
	}
	return true;
}

struct readwritev* create_kernel_iov(const struct iovec* iov, int iovcnt, int job)	{
	struct readwritev* ret = kmalloc( sizeof(struct readwritev) );
	if(PTR_IS_ERR(ret))	return ret;

	ret->iov = (struct iovec*)iov;
	ret->iovcnt = iovcnt;
	ret->current = 0;
	ret->job = job;
	ret->retval = 0;
	return ret;
}
