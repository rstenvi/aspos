/**
* Driver for accessing memory as a file.
*
* This is mostly useful if user-mode need to check if a given memory region has
* been mapped in. I.e. caller can try and read a given set of bytes from memory
* region and and all bytes were read, the memory is mapped in.
*/

#include "kernel.h"
#include "vfs.h"
#include "lib.h"

static int _umem_rw(struct vfsopen* o, void* buf, size_t len, bool read)	{
	void* addr = (void*)o->offset;
	if(!ADDR_USER(addr) || !ADDR_USER(addr + len))	return -USER_FAULT;

	ptr_t oa;
	size_t rem = len;
	ptr_t* pgd = (ptr_t*)cpu_get_user_pgd();
	
	while(rem > 0)	{
		ptr_t tmp = GET_ALIGNED_DOWN_POW2((ptr_t)addr, PAGE_SIZE);
		oa = mmu_va_to_pa_pgd(pgd, tmp, NULL);

		// We've reached an unmapped page, exit early
		if(!oa)	break;

		// Get the number of bytes we should read
		size_t toread = MIN(rem, PAGE_SIZE - ((ptr_t)addr - tmp));
		rem -= toread;

		// Only read if a valid address was passed in
		if(buf)	{
			if(read)	{
				mmu_memcpy_user(pgd, buf, addr, toread);
			}
			else	{
				mmu_memcpy_user(pgd, addr, buf, toread);
			}
			buf += toread;
		}
		addr += toread;
	}
	return len - rem;
}
int umem_read(struct vfsopen* o, void* buf, size_t len)	{
	return _umem_rw(o, buf, len, true);
}
int umem_write(struct vfsopen* o, const void* buf, size_t len)	{
	return _umem_rw(o, (void*)buf, len, false);
}

static struct fs_struct umemfs = {
	.name = "umem",
	.open = vfs_empty_open,
	.close = vfs_empty_close,
	.read = umem_read,
	.write = umem_write,
	.perm = ACL_PERM(ACL_READ|ACL_WRITE, ACL_READ|ACL_WRITE, ACL_READ|ACL_WRITE),
};

int init_umem(void)	{
	device_register(&umemfs);
}
driver_init(init_umem);

