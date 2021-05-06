/**
* Character driver in user space (CUSE)
*/

#include "kernel.h"
#include "vfs.h"
#include "lib.h"

struct process* cuse_get_process(struct fs_struct* fs)	{
	//ASSERT_VALID_PTR(fs->private_data);
	return (struct process*)fs->private_data;
}

static int _cuse_set_fs_ops(struct vfsopen* o, struct fs_struct* _fs)	{
	int ret = OK;
	TZALLOC_ERR(fs, struct fs_struct);
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
	fs->private_data = current_proc();
	ASSERT_TRUE(fs->private_data, "Tried to set cuse-fs w/o proc");
	SET_VFS_DATA(o, fs);
	return ret;
err1:
	kfree(fs);
	return ret;
}
static int _cuse_register(struct vfsopen* o)	{
	int ret = OK;
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
	int ret = OK;
	GET_VFS_DATA(o, struct fs_struct, fs);
//	struct fs_struct* fs;
//	fs = (struct fs_struct*)o->data;
	if(PTR_IS_ERR(fs))	return -USER_FAULT;

	ret = device_unregister(fs);
	return ret;
}

static int _cuse_set_func_empty(struct fs_struct* fs, uint32_t func)	{
	int res = OK;
	if(PTR_IS_ERR(fs))	return -USER_FAULT;

	if(FLAG_SET(func, VFS_FUNC_OPEN))	fs->open  = vfs_empty_open;
	if(FLAG_SET(func, VFS_FUNC_CLOSE)) 	fs->close = vfs_empty_close;
	if(FLAG_SET(func, VFS_FUNC_READ)) 	fs->read  = vfs_empty_read;
	if(FLAG_SET(func, VFS_FUNC_WRITE))	fs->write = vfs_empty_write;
	if(FLAG_SET(func, VFS_FUNC_GETC))	fs->getc  = vfs_empty_getc;
	if(FLAG_SET(func, VFS_FUNC_PUTC))	fs->putc  = vfs_empty_putc;
	if(FLAG_SET(func, VFS_FUNC_FCNTL))	fs->fcntl = vfs_empty_fcntl;
	if(FLAG_SET(func, VFS_FUNC_LSEEK))	fs->lseek = vfs_empty_lseek;
	if(FLAG_SET(func, VFS_FUNC_FSTAT))	fs->fstat = vfs_empty_fstat;

	return res;
}
int cuse_open(struct vfsopen* o, const char* name, int flags, int mode)	{
	int ret = OK;
	o->data = (void*)NULL;
	return ret;
}
int cuse_close(struct vfsopen* o)	{
	int ret = OK;
	struct fs_struct* fs;
	fs = (struct fs_struct*)o->data;
	ret = _cuse_unregister(o);
	if(ret == OK)	{
		kfree(fs);
	}
	return OK;
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
#if defined(CONFIG_KASAN)
		kasan_never_freed(o->data);
#endif
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
	.perm = ACL_PERM(ACL_READ|ACL_CTRL, ACL_READ|ACL_CTRL, ACL_NONE),
};

int init_cuse(void)	{
	device_register(&cusefs);
}
driver_init(init_cuse);

