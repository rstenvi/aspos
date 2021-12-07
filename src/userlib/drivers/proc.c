/**
* /proc/ mountpoint
*/
#include <fcntl.h>
#include <unistd.h>
#include "lib.h"
#include "vfs.h"
#include "arch.h"

#define MOUNT_POINT "/proc"
#define VERSION "aspos 0.1"

#define SVC_DONE(fd,svcid,res) \
	fcntl(fd, CUSE_SVC_DONE, ((ptr_t)(svcid) << 32) | (res & 0xffffffff)); \
	while(1)

static int procfd;

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

__noreturn int proc_open(struct vfsopen* o, const char* fname, int openf, int modef) {
	int ret = -USER_FAULT;
	TZALLOC(fs, struct fs_struct);
	if(!strcmp(fname, "version"))	{
		fs->read = _read_version;
	}
	else	{
		goto err1;
	}
	SET_VFS_DATA(o, fs);

	SVC_DONE(procfd, o->svcid, o->fd);
err1:
	kfree(fs);
	SVC_DONE(procfd, o->svcid, ret);
}
__noreturn int proc_read(struct vfsopen* o, void* buf, size_t len)	{
	int ret = -USER_FAULT;
	GET_VFS_DATA(o, struct fs_struct, fs);
	if(!PTR_IS_ERR(fs))	{
		if(fs->read)	ret = fs->read(o, buf, len);
	}
	SVC_DONE(procfd, o->svcid, ret);
}
__noreturn int proc_close(struct vfsopen* o)	{
	int res = OK;
	GET_VFS_DATA(o, struct fs_struct, fs);
	if(PTR_IS_ERR(fs))	{
		res = -USER_FAULT;
	} else {
		if(fs->close)	res = fs->close(o);

		SET_VFS_DATA(o, NULL);
		kfree(fs);
	}
	SVC_DONE(procfd, o->svcid, res);
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
	procfd = fd;

	// Register fs_struct
	fcntl(fd, CUSE_SET_FS_OPS, (ptr_t)(&proc_fs));

	// After register, driver is effective
	fcntl(fd, CUSE_MOUNT, MOUNT_POINT);

	// Map in memory region to hold arguments
	mmap(NULL, 4096, PROT_RW, 0, fd);

// 	if(detach)	{
// 		fcntl(fd, CUSE_DETACH);
// 		close(fd);
// 		fd = 0;
// 	}
	return fd;
}

// int close_proc(int fd) { close(fd); }
