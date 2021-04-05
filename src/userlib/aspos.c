#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include "lib.h"
#include "vfs.h"

// TODO: Makes sense to move these into kernel to save a syscall
int seek_read(int fd, void* buf, size_t len, size_t off)	{
	size_t noff;
	noff = lseek(fd, off, SEEK_SET);
	if(noff != off)	return -1;
	return read(fd, buf, len);
}
int seek_write(int fd, void* buf, size_t len, size_t off)	{
	size_t noff;
	noff = lseek(fd, off, SEEK_SET);
	if(noff != off)	return -1;
	return write(fd, buf, len);
}

int cuse_mount(struct fs_struct* fs, const char* mnt, bool detach)	{
	int fd;
	fd = open("/dev/cuse", 0, 0);
	if(fd < 0)	{
		printf("Unable to open /dev/cuse\n");
		return fd;
	}

	// Register fs_struct
	fcntl(fd, CUSE_SET_FS_OPS, (ptr_t)fs);

	// After register, driver is effective
	fcntl(fd, CUSE_MOUNT, mnt);

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

