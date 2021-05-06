#include <limits.h>
#include "kernel.h"
#include "lib.h"
#include "ubsan.h"

static int _divide_by_zero(void)	{
	return 42/0;
}
static int _overflow_int(void)	{
	int a = INT_MAX;
	a++;
	return a;
}
static int _overflow_shift(void)	{
	int a = 2;
	a <<= 40;
	return a;
}
static int _underflow_int(void)	{
	int a = INT_MIN;
	a--;
	return a;
}
static int _int_oob(void)	{
	int a[] = {1,2,3};
	return a[3];
}
static int _aligned_pointer(void)	{
	int a = 42;
	int* _a = &a;
	_a = (ptr_t)_a + 1;
	return *_a;
}
static int _pointer_overflow(void)	{
	int a = 42;
	int* _a = &a;
	_a -= (ptr_t)_a / sizeof(int);
	return a;
}
__attribute__((nonnull)) static int _pass_nonnull(int* arr)	{
	if(arr)	return arr[0];
	return 0;
}
/*
static int _vla(int a)	{
	int* arr = kmalloc(a);
	return arr[-1];
}
static int _null_ptr_deref(void)	{
	int* a = NULL;
	return *a;
}
*/

int ubsan_fcntl(struct vfsopen* o, ptr_t cmd, ptr_t arg)	{
	int res = OK;
	switch(cmd)	{
	case FCNTL_UBSAN_ALL_TESTS:
		res = _divide_by_zero();
		res = _overflow_int();
		res = _overflow_shift();
		res = _underflow_int();
		res = _int_oob();
		res = _aligned_pointer();
		res = _pointer_overflow();
		res = _pass_nonnull(NULL);
//		res = _null_ptr_deref();
		break;
	case FCNTL_UBSAN_DIV_ZERO:
		res = _divide_by_zero();
		break;
	default:
		res = -USER_FAULT;
		break;
	}
	return OK;
}

static struct fs_struct ubsandev = {
    .name = "ubsan-test",
	.open = vfs_empty_open,
	.fcntl = ubsan_fcntl,
	.perm = ACL_PERM(ACL_READ|ACL_CTRL, ACL_READ|ACL_CTRL, ACL_NONE),
};
int init_ubsan_test(void)	{
	device_register(&ubsandev);
	return OK;
}
driver_init(init_ubsan_test);
