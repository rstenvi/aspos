#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include "lib.h"
#include "vfs.h"
#include "arch.h"
#ifdef CONFIG_KASAN
#include "kasan.h"
#endif

// TODO: Makes sense to move these into kernel to save a syscall
int seek_read(int fd, void* buf, size_t len, size_t off)	{
	off_t noff;
	noff = lseek(fd, off, SEEK_SET);
	if(noff != (off_t)off)	{
		printf("Unable to seek to %lx | res: %lx\n", off, noff);
		return -1;
	}
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
	fd = open("/dev/cuse", OPEN_FLAG_READ | OPEN_FLAG_CTRL, 0);
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
void* mmap(void* addr, size_t len, int prot, int flags, int fd)	{
	void* ret;
	ret = _mmap(addr, len, prot, flags, fd);
#ifdef CONFIG_KASAN
	if(PTR_IS_VALID(ret) && ADDR_USER(ret))	{
		kasan_mmap(ret, len);
	}
#endif
	return ret;
}
int munmap(void* addr)	{
	int ret = _munmap(addr);
#ifdef CONFIG_KASAN
	kasan_munmap(addr);
#endif
	return ret;
}

/*
// Helper functions to list data in directort
struct dir_state* flistdir(int fd)	{
	TZALLOC(ret, struct dir_state);
	// Should verify that fd is dir
	// 
}

struct dir_state* listdir(const char* d)	{
	int fd;
	fd = open(d);
	if(fd < 0)	return fd;

	return flistdir(fd);
}

struct dir_entry* direnum(struct dir_state* s)	{
	struct dir_entry* e;
	if(s->offset + DIR_ENTRY_PRESIZE >= s->len)	return NULL;

	e = (struct dir_entry*)(buf + s->offset);
	s->offset += e->length;
	return e;
}
void free_dirstate(struct dir_state* s)	{
	free(s);
}
*/
