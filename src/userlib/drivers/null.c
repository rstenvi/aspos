/**
* /dev/null in user-mode
*/

#include <fcntl.h>
#include <unistd.h>
#include "lib.h"
#include "vfs.h"

static struct fs_struct dev_null_fs = {
	.name = "null",
	.perm = ACL_PERM(ACL_READ|ACL_WRITE, ACL_READ|ACL_WRITE, ACL_READ|ACL_WRITE),
};

int init_dev_null(bool detach)	{
	int fd;
	fd = open("/dev/cuse", OPEN_FLAG_READ|OPEN_FLAG_CTRL, 0);
	if(fd < 0)	{
		printf("Unable to open /dev/cuse\n");
		return fd;
	}

	// Register fs_struct
	fcntl(fd, CUSE_SET_FS_OPS, (ptr_t)(&dev_null_fs));

	// open and write is valid, but we don't do anything
	fcntl(fd, CUSE_SET_FUNC_EMPTY, VFS_FUNC_OPEN | VFS_FUNC_WRITE);

	// After register, driver is effective
	fcntl(fd, CUSE_REGISTER);

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

int close_dev_null(int fd) { close(fd); }
