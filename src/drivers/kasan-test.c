#include <limits.h>
#include "kernel.h"
#include "lib.h"
#include "kasan.h"

static int _access_uaf(void)	{
	int* buf = (int*)kmalloc(2 * sizeof(int));
	kfree(buf);
	return buf[0];
}
static int _access_wrong(void)	{
	ptr_t* arr = (ptr_t*)0xffff0000deadbeef;
	return (int)arr[0];
}
/*
* This is not handled by KASAN, but should be detected by UBSAN
*/
static int _stack_access(void)	{
	char buf[10] = {0};
	return buf[25];
}
static int _overflow_access(void)	{
	int* buf = (int*)kmalloc(4 * sizeof(int));
	int ret = buf[-1];
	kfree(buf);
	return ret;
}
static int _overflow_access2(void)	{
	int* buf = (int*)kmalloc(4 * sizeof(int));
	int ret = buf[5];
	kfree(buf);
	return ret;
}
static int _access_after_alloc(void)	{
#define SIZE (4 * sizeof(int))
	int* buf, *_buf;
	buf = (int*)kmalloc(SIZE);
	kfree(buf);
	_buf = kmalloc(SIZE);
	if(_buf == buf)	{
		logi("%s will not trigger without quarantine in use\n", __func__);
	}
	int ret = buf[0];
	kfree(_buf);
	return ret;
}

int kasan_fcntl(struct vfsopen* o, ptr_t cmd, ptr_t arg)	{
	int res = OK;
	switch(cmd)	{
	case FCNTL_KASAN_ALL_TESTS:
		res = _overflow_access2();
		res = _access_after_alloc();
		res = _overflow_access();
		res = _stack_access();
		res = _access_wrong();
		res = _access_uaf();
		break;
	default:
		res = -USER_FAULT;
		break;
	}
	return OK;
}

static struct fs_struct kasandev = {
    .name = "kasan-test",
	.open = vfs_empty_open,
	.fcntl = kasan_fcntl,
	.perm = ACL_PERM(ACL_READ|ACL_CTRL, ACL_READ|ACL_CTRL, ACL_NONE),
};
int init_kasan_test(void)	{
	device_register(&kasandev);
	return OK;
}
driver_init(init_kasan_test);
