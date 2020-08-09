/**
* Management of Virtual File System (VFS).
*
* todo: Should be generic to handle several subdirs, like /dev/
*/

#include "kernel.h"
#include "vfs.h"


static int vfs_find_name(struct fs_component* d, const char* name)	{
	int i;
	for(i = 0; i < d->currdevs; i++)	{
		if(strcmp(name, d->subfs[i]->name) == 0)	return i;
	}
	return -1;
}

int generic_open(struct fs_component* d, const char* name, int flags, int mode)	{
	const char* rname = (name + strlen(d->name));
	int idx = vfs_find_name(d, rname);
	if(idx < 0)	return -(USER_FAULT);

	struct fs_struct* ds = d->subfs[idx];
	int fd;
	int res = 0;

	struct vfsopen* n = (struct vfsopen*)malloc( sizeof(struct vfsopen) );
	ASSERT_TRUE(n != NULL, "error");

	n->tid = current_tid();
	n->fd = fileid_unique();
	n->fs = ds;
	n->data = NULL;
	n->offset = 0;

	if(ds->open != NULL)	res = ds->open(n, rname, flags, mode);

	if(res < 0)	{
		free(n);
		return res;
	}

	llist_insert(d->opened, n, n->fd);
	return n->fd;
}

int vfs_open(const char* name, int flags, int mode)	{
	struct fs_component* d = &(osdata.root);
	return generic_open(d, name, flags, mode);
}

int vfs_dup(int oldfd)	{
	struct fs_component* d = &(osdata.root);
	struct vfsopen* o = llist_find(d->opened, oldfd);
	if(o == NULL)	return -USER_FAULT;

	struct vfsopen* n = (struct vfsopen*)malloc( sizeof(struct vfsopen) );
	if(n == NULL)	return -MEMALLOC;

	n->tid = current_tid();
	n->fd = fileid_unique();
	n->fs = o->fs;
	n->data = o->data;
	n->offset = o->offset;

	llist_insert(d->opened, n, n->fd);
	return n->fd;
}

int vfs_read(int fd, void* buf, size_t max)	{
	struct fs_component* d = &(osdata.root);
	struct vfsopen* o = llist_find(d->opened, fd);
	if(o == NULL)	return -1;

	if(o->fs->read != NULL)	return o->fs->read(o, buf, max);

	return -1;
}
int vfs_write(int fd, void* buf, size_t max)	{
	struct fs_component* d = &(osdata.root);
	struct vfsopen* o = llist_find(d->opened, fd);
	if(o == NULL)	return -1;

	if(o->fs->write != NULL)	return o->fs->write(o, buf, max);

	return -1;
}

off_t generic_lseek(struct vfsopen* o, off_t offset, int whence)	{
	switch(whence)	{
		case SEEK_SET:
			o->offset = offset;
			break;
		case SEEK_CUR:
			o->offset += offset;
			break;
		case SEEK_END:
//		case SEEK_DATA:
//		case SEEK_HOLE:
		default:
			logw("Unsupported lseek: %i\n", whence);
			return (off_t)-1;
	}
	return (o->offset);
}

off_t vfs_lseek(int fd, off_t offset, int whence)	{
	int res = OK;
	struct fs_component* d = &(osdata.root);
	struct vfsopen* o = llist_find(d->opened, fd);
	if(o == NULL)	return -1;

	if(o->fs->lseek != NULL)	res = o->fs->lseek(o, offset, whence);
	else						res = generic_lseek(o, offset, whence);
	
	return res;
}

int vfs_close(int fd)	{
	int res = OK;
	struct fs_component* d = &(osdata.root);
	struct vfsopen* o = llist_remove(d->opened, fd);
	if(o == NULL)	return -1;

	if(o->fs->close != NULL)	res = o->fs->close(o);

	// Might be called twice, but doesn't matter
	fileid_free(fd);

	free(o);

	return res;
}

int vfs_getchar(int fd)	{
	int res = -USER_FAULT;
	struct fs_component* d = &(osdata.root);
	struct vfsopen* o = llist_find(d->opened, fd);
	if(o == NULL)	return -1;

	if(o->fs->getc != NULL)	res = o->fs->getc(o);

	return res;
}

int vfs_putchar(int fd, int c)	{
	int res = -USER_FAULT;
	struct fs_component* d = &(osdata.root);
	struct vfsopen* o = llist_find(d->opened, fd);
	if(o == NULL)	return -1;

	if(o->fs->putc != NULL)	res = o->fs->putc(o, c);

	return res;
}


int init_vfs(void)	{
	struct fs_component* d = &(osdata.root);
	strcpy(d->name, "/");

	d->opened = llist_alloc();
	ASSERT_TRUE(d->opened != NULL, "Cannot allocate memory");

	return OK;
}

driver_init(init_vfs);
