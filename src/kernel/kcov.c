#include "kernel.h"

#define KCOV_DATA_SIZE_BYTES(data) ((data->maxcount * sizeof(ptr_t)) + sizeof(struct kcov_data))

void __sanitizer_cov_trace_pc(void)	{
	ptr_t pc = (ptr_t)__builtin_return_address(0);

	struct kcov_data* data;
	struct kcov* kcov = get_current_kcov();
	if(PTR_IS_ERR(kcov) ||
		PTR_IS_ERR(READ_ONCE(kcov->data)) ||
		!READ_ONCE(kcov->enabled))		return;

	data = kcov->data;
	uint32_t ccount;

	/*
	* Write PC to array
	* If the value is the same as the previous, we increment the value instead.
	* This is to save some space and bandwidth if we do coverage tracing in a
	* loop. It does result in a less unique trace, but it's quite unlikely that
	* it will hit a different valid feedback PC.
	*/
	ccount = READ_ONCE(data->currcount);
	if(ccount > 0 && data->entries[ccount-1] == pc)	{
		WRITE_ONCE(data->entries[ccount-1], data->entries[ccount-1] + 1);
	} else if(ccount < kcov->allocated) {
		WRITE_ONCE(data->entries[ccount++], pc);
		WRITE_ONCE(data->currcount, ccount);
	}
}

int kcov_open(struct vfsopen* o, const char* name, int flags, int mode)	{
	return o->fd;
}

static int _kcov_init(struct vfsopen* o)	{
	TZALLOC_ERR(kcov, struct kcov);

	/*
	* Should already be zero after calling tzalloc
	*/
	WRITE_ONCE(kcov->enabled, false);
	WRITE_ONCE(kcov->data, NULL);
	WRITE_ONCE(kcov->allocated, 0);

	set_current_kcov(kcov);
	SET_VFS_DATA(o, kcov);

	return OK;
}

static inline int _kcov_set_status(bool value)	{
	struct kcov* kcov;
	kcov = get_current_kcov();
	if(PTR_IS_ERR(kcov))		return -USER_FAULT;
	if(PTR_IS_ERR(kcov->data))	return -USER_FAULT;

	// Writing to data->maxcolunt serves as enabling/disabling for user-mode
	uint32_t entries = (value) ? READ_ONCE(kcov->allocated) : 0;

	WRITE_ONCE(kcov->enabled, value);
	WRITE_ONCE(kcov->data->maxcount, entries);
	return OK;
}

int kcov_fcntl(struct vfsopen* o, ptr_t cmd, ptr_t arg)	{
	int res = OK;
	switch(cmd)	{
	case FCNTL_KCOV_INIT:
		res = _kcov_init(o);
		break;
	case FCNTL_KCOV_ENABLE:
		res = _kcov_set_status(true);
		break;
	case FCNTL_KCOV_DISABLE:
		res = _kcov_set_status(false);
		break;
	default:
		res = -USER_FAULT;
		break;
	}
	return res;
}


int kcov_close(struct vfsopen* o)	{
	struct kcov* kcov = get_current_kcov();
	if(PTR_IS_ERR(kcov))	return -USER_FAULT;
	WRITE_ONCE(kcov->data, NULL);

	set_current_kcov(NULL);
	kfree(kcov);
	return OK;
}

int kcov_mmap(struct vfsopen* o, void* addr, size_t length)	{
	struct kcov_data* data;
	GET_VFS_DATA(o, struct kcov, kcov);

	uint32_t entries = (length - sizeof(struct kcov_data)) / sizeof(ptr_t);
	data = (struct kcov_data*)addr;
	WRITE_ONCE(kcov->allocated, entries);

	// Set currcount and maxcount to 0
	WRITE_ONCE(data->currcount, 0);
	//put_user_u64((uint64_t*)data, 0);

	kcov->data = data;

	// Writing of this value will allow user-mode to start writing entries
	WRITE_ONCE(data->maxcount, entries);
	return OK;
}

static struct fs_struct kcovfs = {
	.name = "kcov",
	.open = kcov_open,
	.close = kcov_close,
	.fcntl = kcov_fcntl,
	.mmap = kcov_mmap,
	.perm = ACL_PERM(ACL_READ|ACL_CTRL, ACL_READ|ACL_CTRL, ACL_NONE),
};

int init_kcov(void)	{
	device_register(&kcovfs);
	return 0;
}
driver_init(init_kcov);
