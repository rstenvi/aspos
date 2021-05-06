/**
* /proc/ mountpoint
*/
#include <fcntl.h>
#include <unistd.h>
#include "lib.h"
#include "vfs.h"

#define MOUNT_POINT "/proc"
#define VERSION "aspos 0.1"

static int _read_generic(char* buf, size_t mlen, const char* from, size_t len)	{
	size_t sz = MIN(mlen, len);
	memcpy(buf, from, sz);
	if(sz < mlen)	{
		// Finish with zero-byte if there is space for is
		buf[sz] = 0x00;
		sz++;
	}
	return sz;
}
static int _read_version(struct vfsopen* o, void* buf, size_t len)	{
	return _read_generic((char*)buf, len, VERSION, strlen(VERSION));
}

int proc_open(struct vfsopen* o, const char* fname, int mode, int flags) {
	int ret = -USER_FAULT;
	TZALLOC_ERR(fs, struct fs_struct);
	if(!strcmp(fname, "version"))	{
		fs->read = _read_version;
	}
	else	{
		goto err1;
	}
	SET_VFS_DATA(o, fs);
	return o->fd;
err1:
	kfree(fs);
	return ret;
}
int proc_read(struct vfsopen* o, void* buf, size_t len)	{
	GET_VFS_DATA(o, struct fs_struct, fs);
	if(PTR_IS_ERR(fs))  return -USER_FAULT;

	if(fs->read)	return fs->read(o, buf, len);
	return -USER_FAULT;
}
int proc_close(struct vfsopen* o)	{
	int res = OK;
	GET_VFS_DATA(o, struct fs_struct, fs);
	if(PTR_IS_ERR(fs))  return -USER_FAULT;

	if(fs->close)	res = fs->close(o);

	SET_VFS_DATA(o, NULL);
	kfree(fs);
	return res;
}

static struct fs_struct proc_fs = {
	.name = "",
	.open = proc_open,
	.read = proc_read,
	.close = proc_close,
	.perm = ACL_PERM(ACL_READ|ACL_WRITE, ACL_READ|ACL_WRITE, ACL_READ),
};

int init_proc(bool detach)	{
	int fd;
	fd = open("/dev/cuse", OPEN_FLAG_READ|OPEN_FLAG_CTRL, 0);
	if(fd < 0)	{
		printf("Unable to open /dev/cuse\n");
		return fd;
	}

	// Register fs_struct
	fcntl(fd, CUSE_SET_FS_OPS, (ptr_t)(&proc_fs));

	// After register, driver is effective
	fcntl(fd, CUSE_MOUNT, MOUNT_POINT);

	// After detaching, it is not longer possible to unload the driver
	// The driver will remain in effect until the system is powered off
	// This is useful to free up the fd
	if(detach)	{
		fcntl(fd, CUSE_DETACH);
		close(fd);
		fd = 0;
	}
	return fd;
}

int close_proc(int fd) { close(fd); }
