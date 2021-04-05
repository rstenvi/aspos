/**
* Character driver in user space (CUSE)
*/

#include "kernel.h"
#include "vfs.h"
#include "lib.h"

static int _cuse_set_fs_ops(struct vfsopen* o, struct fs_struct* _fs)	{
	int ret = OK;
	TZALLOC(fs, struct fs_struct);
	if(memcpy_from_user(fs, _fs, sizeof(struct fs_struct)))	{
		ret = -USER_FAULT;
		goto err1;
	}
	// All function pointers must belong to user-space, otherwise
	// we would execute the functions in kernel mode
	if(!vfs_functions_valid(fs, true))	{
		ret = -USER_FAULT;
		goto err1;
	}
	// We enforce this variable, regardless of what sender said
	fs->user = true;
	SET_VFS_DATA(o, fs);
	return ret;
err1:
	free(fs);
	return ret;
}
static int _cuse_register(struct vfsopen* o)	{
	int ret;
	struct fs_struct* fs;
	fs = (struct fs_struct*)o->data;
	if(PTR_IS_ERR(fs))	return -USER_FAULT;

	ret = device_register(fs);
	return ret;
}
static int _cuse_mount(struct vfsopen* o, const char* name)	{
	char* kname;
	int ret = -USER_FAULT;
	GET_VFS_DATA(o, struct fs_struct, fs);
	if(PTR_IS_ERR(fs))	return -USER_FAULT;

	kname = strdup_user(name);

	ret = vfs_register_mount(kname, fs);

	free_user(kname);
	return ret;
}

static int _cuse_unregister(struct vfsopen* o)	{
	int ret;
	GET_VFS_DATA(o, struct fs_struct, fs);
//	struct fs_struct* fs;
//	fs = (struct fs_struct*)o->data;
	if(PTR_IS_ERR(fs))	return -USER_FAULT;

	ret = device_unregister(fs);
	return ret;
}

static int _cuse_set_func_empty(struct fs_struct* fs, enum VFS_FUNC func)	{
	int res = OK;
	if(PTR_IS_ERR(fs))	return -USER_FAULT;

	switch(func)	{
	case VFS_FUNC_OPEN:
		fs->open = vfs_empty_open;
		break;
	case VFS_FUNC_CLOSE:
		fs->close = vfs_empty_close;
		break;
	case VFS_FUNC_READ:
		fs->read = vfs_empty_read;
		break;
	case VFS_FUNC_WRITE:
		fs->write = vfs_empty_write;
		break;
	case VFS_FUNC_GETC:
		fs->getc = vfs_empty_getc;
		break;
	case VFS_FUNC_PUTC:
		fs->putc = vfs_empty_putc;
		break;
	case VFS_FUNC_FCNTL:
		fs->fcntl = vfs_empty_fcntl;
		break;
	case VFS_FUNC_LSEEK:
		fs->lseek = vfs_empty_lseek;
		break;
	case VFS_FUNC_FSTAT:
		fs->fstat = vfs_empty_fstat;
		break;
	default:
		res = -USER_FAULT;
	}
	return res;
}
int cuse_open(struct vfsopen* o, const char* name, int flags, int mode)	{
	int ret = OK;
	o->data = (void*)NULL;
	return ret;
}
int cuse_close(struct vfsopen* o)	{
	int ret;
	struct fs_struct* fs;
	fs = (struct fs_struct*)o->data;
	ret = _cuse_unregister(o);
	if(ret == OK)	{
		free(fs);
	}
	return ret;
}

int cuse_fcntl(struct vfsopen* o, ptr_t cmd, ptr_t arg)	{
	int ret = OK;
	switch(cmd)	{
	case CUSE_SET_FS_OPS:
		ret = _cuse_set_fs_ops(o, (struct fs_struct*)arg);
		break;
	case CUSE_REGISTER:
		ret = _cuse_register(o);
		break;
	case CUSE_UNREGISTER:
		ret = _cuse_unregister(o);
		break;
	case CUSE_DETACH:
		// If we remove the reference, then close will do nothing, but
		// free up the file descriptor. It will no longer be possible
		// to free the pointer, so this should only be used if the device
		// should exist until poweroff.
		o->data = NULL;
		break;
	case CUSE_SET_FUNC_EMPTY:
		ret = _cuse_set_func_empty((struct fs_struct*)o->data, arg);
		break;
	case CUSE_MOUNT:
		ret = _cuse_mount(o, (const char*)arg);
	default:
		ret = -USER_FAULT;
		break;
	}
	return ret;
}

static struct fs_struct cusefs = {
	.name = "cuse",
	.open = cuse_open,
	.close = cuse_close,
	.fcntl = cuse_fcntl,
};

int init_cuse(void)	{
	device_register(&cusefs);
}
driver_init(init_cuse);

