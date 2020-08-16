/**
* Management of Virtual File System (VFS).
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

static const char* vfs_next_node(const char* name)	{
	char* end = strchr(name, '/');
	return (end != NULL) ? end : name;
}

static int _vfs_find_child(struct fs_component* d, const char* name)	{
	char* end = strchr(name, '/');
	int len = (end == NULL) ? strlen(name) : (end - name);
	int i;
	for(i = 0; i < d->numchilds; i++)	{
		if(strncmp(d->childs[i]->name, name, len) == 0)	return i;
	}
	return -1;
}

static struct fs_component* vfs_find_child(struct fs_component* d, const char** name)	{
	*name = *name + strlen(d->name) + 1;
	const char* rname = (*name);
	int idx;
	idx = _vfs_find_child(d, rname);
	if(idx < 0)	return d;

	return vfs_find_child(d->childs[idx], name);
}

static int vfs_add_to_open_root(struct vfsopen* n)	{
	struct fs_component* d = &(osdata.root);
	llist_insert(d->opened, n, n->fd);
	return OK;
}

int generic_open(struct fs_component* d, const char* name, int flags, int mode)	{
	int idx;
	char* rname = name;
	d = vfs_find_child(d, &rname);

//	const char* rname = (cname + strlen(d->name) + 1);

	idx = vfs_find_name(d, rname);
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
	
	vfs_add_to_open_root(n);
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


int vfs_register_child(struct fs_component* child)	{
	struct fs_component* d = &(osdata.root);
	if(d->numchilds == d->maxchilds)	{
		d->maxchilds += 4;
		d->childs = (struct fs_component*)realloc(d->childs, (sizeof(void*) * d->maxchilds));
		ASSERT_FALSE(PTR_IS_ERR(d->childs), "Memory error");
	}

	d->childs[d->numchilds++] = child;
	return OK;
}

int init_vfs(void)	{
	struct fs_component* d = &(osdata.root);

	// rootfs has no name
	d->name[0] = 0x00;

	d->opened = llist_alloc();
	ASSERT_TRUE(d->opened != NULL, "Cannot allocate memory");

	return OK;
}

driver_init(init_vfs);

struct fs_component vfs_dev;

int init_vfs_dev(void)	{
	struct fs_component* d = &(vfs_dev);
	strcpy(d->name, "dev");

	d->opened = llist_alloc();
	ASSERT_TRUE(d->opened != NULL, "Cannot allocate memory");

	vfs_register_child(d);

	return OK;
}

driver_init(init_vfs_dev);

int device_register(struct fs_struct* dev)	{
	struct fs_component* d = &(vfs_dev);
	if(d->currdevs >= d->maxdevs)	{
		d->maxdevs += 10;
		d->subfs = (struct fs_struct**)realloc(d->subfs, sizeof(void*) * d->maxdevs);
		ASSERT_TRUE(d->subfs != NULL, "Unable to allocate space for devices");
	}
	d->subfs[d->currdevs++] = dev;
	return OK;
}

