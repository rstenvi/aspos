#ifndef __VFS_H
#define __VFS_H

#include "types.h"

#define DEVICE_NAME_MAXLEN 15


enum VFS_FUNC {
	VFS_FUNC_NONE = 0,
	VFS_FUNC_OPEN,
	VFS_FUNC_CLOSE,
	VFS_FUNC_READ,
	VFS_FUNC_WRITE,
	VFS_FUNC_GETC,
	VFS_FUNC_PUTC,
	VFS_FUNC_FCNTL,
	VFS_FUNC_LSEEK,
	VFS_FUNC_FSTAT,
};

struct vfsopen;
struct thread_fd_open;

// ------------------- Function prototypes for drivers -------------- //

typedef int (*drvfunc_open_t)(struct vfsopen*,const char*,int,int);
typedef int (*drvfunc_fcntl_t)(struct vfsopen*,ptr_t,ptr_t);
typedef int (*drvfunc_fstat_t)(struct vfsopen*,struct stat*);
typedef int (*drvfunc_write_t)(struct vfsopen*,const void*,size_t);
typedef int (*drvfunc_read_t)(struct vfsopen*,void*,size_t);
typedef int (*drvfunc_mmap_t)(struct vfsopen*,void*,size_t);
typedef int (*drvfunc_close_t)(struct vfsopen*);
typedef int (*drvfunc_getc_t)(struct vfsopen*);
typedef int (*drvfunc_putc_t)(struct vfsopen*, int);
typedef int (*drvfunc_lseek_t)(struct vfsopen*,off_t,int);

#define GET_VFS_DATA(vfs,type,name) type* name = (type*)vfs->data
#define SET_VFS_DATA(vfs,name) vfs->data = (void*)name



int vfs_empty_open(struct vfsopen* o, const char* name, int flags, int mode);
int vfs_empty_close(struct vfsopen* o);
int vfs_empty_read(struct vfsopen* o, void* buf, size_t len);
int vfs_empty_fcntl(struct vfsopen* o, ptr_t cmd, ptr_t arg);
int vfs_empty_fstat(struct vfsopen* o, struct stat* statbuf);
int vfs_empty_write(struct vfsopen* o, const void* data, size_t len);
int vfs_empty_getc(struct vfsopen* o);
int vfs_empty_putc(struct vfsopen* o, int c);
int vfs_empty_lseek(struct vfsopen* o, off_t off, int op);

int vfs_unsupported_open(struct vfsopen* o, const char* name, int flags, int mode);
int vfs_unsupported_close(struct vfsopen* o);
int vfs_unsupported_read(struct vfsopen* o, void* buf, size_t len);
int vfs_unsupported_fcntl(struct vfsopen* o, ptr_t cmd, ptr_t arg);
int vfs_unsupported_fstat(struct vfsopen* o, struct stat* statbuf);
int vfs_unsupported_write(struct vfsopen* o, const void* data, size_t len);
int vfs_unsupported_getc(struct vfsopen* o);
int vfs_unsupported_putc(struct vfsopen* o, int c);
int vfs_unsupported_lseek(struct vfsopen* o, off_t off, int op);

struct vfsopen {
	int tid;
	int fd;
	off_t offset;
	void* data;
};


struct fs_struct {
	char name[DEVICE_NAME_MAXLEN];
	bool user;
	drvfunc_open_t open;
	drvfunc_fcntl_t fcntl;
	drvfunc_fstat_t fstat;
	drvfunc_write_t write;
	drvfunc_read_t read;
//	drvfunc_mmap_t mmap;
	drvfunc_lseek_t lseek;
	drvfunc_close_t close;
	drvfunc_getc_t getc;
	drvfunc_putc_t putc;
};

struct fs_component {
	char name[DEVICE_NAME_MAXLEN];
	size_t maxdevs, currdevs;
	struct fs_struct* rootfs;
	struct fs_struct** subfs;
//	struct llist* opened;

	// Should hold things like /dev/
	size_t numchilds, maxchilds;
	struct fs_component** childs;
};


static inline ptr_t vfs_offset(struct vfsopen* o) { return o->offset; }

// ------------------------- vfs.c ------------------------------ //

int vfs_open(struct thread_fd_open* fdo, const char* name, int flags, int mode);
int vfs_read(struct thread_fd_open* fdo, void* buf, size_t max);
int vfs_write(struct thread_fd_open* fdo, const void* buf, size_t max);
off_t vfs_lseek(struct thread_fd_open* fdo, off_t offset, int whence);
int vfs_close(struct thread_fd_open* fdo);
int vfs_getchar(struct thread_fd_open* fdo);
int vfs_putchar(struct thread_fd_open* fdo, int c);
int vfs_fcntl(struct thread_fd_open* fdo, ptr_t cmd, ptr_t arg);

int vfs_register_mount(const char* n, struct fs_struct* cb);
struct fs_struct* vfs_find_open(char** name);
struct vfsopen* vfs_alloc_open(int tid, int fd, struct fs_struct* ds);
void vfs_free_open(struct thread_fd_open* fdo);
int vfs_fstat(struct thread_fd_open* fdo, struct stat* statbuf);

#endif
