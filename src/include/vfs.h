#ifndef __VFS_H
#define __VFS_H

#include "types.h"


#define DEVICE_NAME_MAXLEN 16


struct vfsopen;

// ------------------- Function prototypes for drivers -------------- //

typedef int (*drvfunc_open_t)(struct vfsopen*,const char*,int,int);
typedef int (*drvfunc_fcntl_t)(struct vfsopen*,ptr_t,ptr_t);
typedef int (*drvfunc_fstat_t)(struct vfsopen*,void*);
typedef int (*drvfunc_write_t)(struct vfsopen*,void*,size_t);
typedef int (*drvfunc_read_t)(struct vfsopen*,void*,size_t);
typedef int (*drvfunc_close_t)(struct vfsopen*);
typedef off_t (*drvfunc_lseek_t)(struct vfsopen*,off_t,int);



struct vfsopen {
	int tid;
	int fd;
	struct fs_struct* fs;
	off_t offset;
	void* data;
};


struct fs_struct {
	char name[DEVICE_NAME_MAXLEN];
	drvfunc_open_t open;
	drvfunc_fcntl_t fcntl;
	drvfunc_fstat_t fstat;
	drvfunc_write_t write;
	drvfunc_read_t read;
	drvfunc_lseek_t lseek;
	drvfunc_close_t close;
};

struct fs_component {
	char name[DEVICE_NAME_MAXLEN];
	size_t maxdevs, currdevs;
	struct fs_struct** subfs;
	struct llist* opened;

	// Should hold things like /dev/
	struct fs_component** childs;
};


static inline ptr_t vfs_offset(struct vfsopen* o) { return o->offset; }

// ------------------------- vfs.c ------------------------------ //

int vfs_open(const char* name, int flags, int mode);
int vfs_read(int fd, void* buf, size_t max);
int vfs_write(int fd, void* buf, size_t max);
int vfs_close(int fd);
int thread_lseek(int fd, off_t offset, int whence);
off_t vfs_lseek(int fd, off_t offset, int whence);

#endif
