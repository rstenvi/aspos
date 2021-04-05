/**
* Management of Virtual File System (VFS).
*/

#include "kernel.h"
#include "vfs.h"
#include "slab.h"


static int vfs_find_name(struct fs_component* d, const char* name)	{
	int i, best_match = -1, len = strlen(name), l;
	if(len == 0)	return -1;

	for(i = 0; i < d->currdevs; i++)	{
		l = strlen(d->subfs[i]->name);
		// The empty-entry serves as a catch-all if there is no perfect match
		if(l == 0)	best_match = i;
		if(len >= l)	{
			if(strncmp(name, d->subfs[i]->name, l) == 0)	{
				if(len == l)	{
					return i;
				}
				else if(name[len] == '/')	{
					return i;
				}
			}
		}
	}
	return best_match;
}

static const char* vfs_next_node(const char* name)	{
	char* end = strchr(name, '/');
	return (end != NULL) ? end : name;
}
/*
static int _vfs_find_child(struct fs_component* d, const char** name)	{
	const char* rname = (*name);
	char* end = strchr(rname, '/');
	int len = (end == NULL) ? strlen(rname) : (end - rname);
	if(len == 0)	return -1;
	int i;
	for(i = 0; i < d->numchilds; i++)	{
		if(strncmp(d->childs[i]->name, rname, len) == 0)	{
			*name = end + 1;
			return i;
		}
	}
	return -1;
}
static struct fs_component* vfs_find_child(struct fs_component* d, char** name)	{
	*name = *name + strlen(d->name);
	int idx;
	idx = _vfs_find_child(d, name);
	if(idx < 0)	return d;

	return vfs_find_child(d->childs[idx], name);
}
*/
/*
static int vfs_add_to_open_root(struct vfsopen* n)	{
	struct fs_component* d = &(osdata.root);
	llist_insert(d->opened, n, n->fd);
	return OK;
}
*/
/*
int generic_open(struct fs_component* d, const char* name, int flags, int mode)	{
	int idx;
	char* rname = (char*)name;
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
*/

// Static check in size of vfsopen
SLAB_CHK_SIZE(struct vfsopen, 24);

#define VFS_GET_FS(o) (ADDR_USER(o)) ? get_user(o->fs, ptr_t) : o->fs

struct vfsopen* vfs_alloc_open(int tid, int fd, struct fs_struct* fs)	{
	struct vfsopen entry;
	struct vfsopen* n;
	n = slab_alloc_32(fs->user);
	if(PTR_IS_ERR(n))	return NULL;

	entry.tid = tid;
	entry.fd = fd;
	//entry.fs = fs;
	entry.data = NULL;
	entry.offset = 0;

	if(fs->user)	{
		memcpy_to_user(n, &entry, sizeof(struct vfsopen));
	}
	else	{
		memcpy(n, &entry, sizeof(struct vfsopen));
	}
	return n;
}
void vfs_free_open(struct thread_fd_open* fdo)	{
	slab_free_32(fdo->open, fdo->fs->user);
}
struct fs_struct* vfs_walk_path(struct fs_component* root, char** _name)	{
	char* name = *_name, * end;
	struct fs_component* curr, *_root = root;
	int clen, i, len;
	do {
		_root = root;
		clen = strlen(root->name);
		if(strlen(name) < clen || strncmp(root->name, name, clen))	{
			logw("Unable to find path for %s\n", name);
			return NULL;
		}
		name = name + clen;
		if(*name == '/')	name++;
		curr = NULL;
		for(i = 0; i < root->numchilds; i++)	{
			curr = root->childs[i];
			len = strlen(name);
			clen = strlen(curr->name);
			if(clen <= len && strncmp(curr->name, name, clen) == 0)	{
				root = curr;
				break;
			}
		}
		
	} while(root != _root);
	for(i = 0; i < root->currdevs; i++)	{
		// Subfs requires exact match
		if(strcmp(root->subfs[i]->name, name) == 0)	{
			return root->subfs[i];
		}
	}
	// If no exact match is found, we return rootfs
	// this may also be NULL, in which case, the caller will
	// report error
	return root->rootfs;
}
struct fs_struct* vfs_find_open(char** name)	{
	struct fs_component* d = &(osdata.root), * open;
	int idx/*, len = strlen(*name)*/;
	struct fs_struct* fs;

	fs = vfs_walk_path(d, name);
	
	/*
	open = vfs_find_child(d, name);
	if(PTR_IS_ERR(open))	return NULL;

	// idx searches for best match, if none is found, we use root
	// root may still be NULL, if none has been registered
	idx = vfs_find_name(open, *name);
	if(idx < 0 || idx >= open->currdevs)	fs = open->rootfs;
	else									fs = open->subfs[idx];
	*/
	return fs;
}

static int _vfs_generic_user(struct vfsopen* o, ptr_t entry, int num, ...)	{
	struct thread* t;
	struct threads* allt = cpu_get_threads();
	va_list ap;
	int i;
	ptr_t arg;

	t = new_thread_kernel(entry, allt->exc_exit, true, false);
	if(PTR_IS_ERR(t))	return PTR_TO_ERRNO(t);

	// Add the necessary arguments
	arch_thread_set_arg((void*)(t->stackptr), (ptr_t)o, 0);
	va_start(ap, num);
	for(i = 1; i <= num; i++)	{
		arg = va_arg(ap, ptr_t);
		arch_thread_set_arg((void*)(t->stackptr), arg, i);
	}
	va_end(ap);

	// Add to front of ready-list
	thread_add_ready(t, true);

	// This will not return
	thread_wait_tid(t->id);

	// The current thread must block until new thread has finished
	return OK;
}

static int _vfs_open_user(struct thread_fd_open* fdo, const char* name, int flags, int mode)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	return _vfs_generic_user(o, (ptr_t)fs->open, 3, name, flags, mode);
}

int vfs_open(struct thread_fd_open* fdo, const char* name, int flags, int mode)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	if(fs->open != NULL)	{
		return ADDR_USER(fs->open) ? _vfs_open_user(fdo, name, flags, mode) : fs->open(fdo->open, name, flags, mode);
	}
	return res;
}

static int _vfs_fstat_user(struct thread_fd_open* fdo, struct stat* statbuf)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	return _vfs_generic_user(o, (ptr_t)fs->fstat, 1, statbuf);
}
int vfs_fstat(struct thread_fd_open* fdo, struct stat* statbuf)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	if(fs->fstat != NULL)	{
		return ADDR_USER(fs->fstat) ? _vfs_fstat_user(fdo, statbuf) : fs->fstat(fdo->open, statbuf);
	}
	return res;
}

/*
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
*/
/*
int vfs_mmap(struct vfsopen* o, void* addr, size_t len)	{
	int res = -USER_FAULT;
	if(o->fs->mmap != NULL)	return o->fs->mmap(o, addr, len);
	return res;
}*/

static int _vfs_fcntl_user(struct thread_fd_open* fdo, ptr_t cmd, ptr_t arg)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	return _vfs_generic_user(o, (ptr_t)fs->fcntl, 2, cmd, arg);
}
int vfs_fcntl(struct thread_fd_open* fdo, ptr_t cmd, ptr_t arg)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	if(fs->fcntl != NULL)	{
		res = ADDR_USER(fs->fcntl) ? _vfs_fcntl_user(fdo, cmd, arg) : fs->fcntl(o, cmd, arg);
	}
	return res;
}

static int _vfs_read_user(struct thread_fd_open* fdo, const void* buf, size_t max)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	return _vfs_generic_user(o, (ptr_t)fs->read, 2, buf, max);
}
int vfs_read(struct thread_fd_open* fdo, void* buf, size_t max)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	if(fs->open != NULL)	{
		res = ADDR_USER(fs->read) ? _vfs_read_user(fdo, buf, max) : fs->read(o, buf, max);
	}

	return res;
}
static int _vfs_write_user(struct thread_fd_open* fdo, const void* buf, size_t max)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	return _vfs_generic_user(o, (ptr_t)fs->write, 2, buf, max);
}
int vfs_write(struct thread_fd_open* fdo, const void* buf, size_t max)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	if(fs->write != NULL)	{
		res = ADDR_USER(fs->write) ? _vfs_write_user(fdo, buf, max) : fs->write(o, buf, max);
	}
	return res;
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
static int _vfs_lseek_user(struct thread_fd_open* fdo, off_t offset, int whence)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	return _vfs_generic_user(o, (ptr_t)fs->lseek, 2, offset, whence);
}
off_t vfs_lseek(struct thread_fd_open* fdo, off_t offset, int whence)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	if(fs->lseek != NULL)	{
		res = ADDR_USER(fs->lseek) ? _vfs_lseek_user(fdo, offset, whence) : fs->lseek(o, offset, whence);
	}
	else	{
		res = generic_lseek(o, offset, whence);
	}
	return res;
}

static int _vfs_close_user(struct thread_fd_open* fdo)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	return _vfs_generic_user(o, (ptr_t)fs->close, 0);
}
int vfs_close(struct thread_fd_open* fdo)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	if(fs->close != NULL)	{
		res = ADDR_USER(fs->close) ? _vfs_close_user(fdo) : fs->close(o);
	}
	return res;
}
static int _vfs_getchar_user(struct thread_fd_open* fdo)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	return _vfs_generic_user(o, (ptr_t)fs->getc, 0);
}
int vfs_getchar(struct thread_fd_open* fdo)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	if(fs->getc != NULL)	{
		res = ADDR_USER(fs->getc) ? _vfs_getchar_user(fdo) : fs->getc(o);
	}
	return res;
}
static int _vfs_putchar_user(struct thread_fd_open* fdo, int c)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	return _vfs_generic_user(o, (ptr_t)fs->putc, 1, c);
}
int vfs_putchar(struct thread_fd_open* fdo, int c)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	if(fs->putc != NULL)	{
		res = ADDR_USER(fs->putc) ? _vfs_putchar_user(fdo, c) : fs->putc(o, c);
	}
	return res;
}

int vfs_register_child(struct fs_component* parent, struct fs_component* child)	{
	if(parent->numchilds == parent->maxchilds)	{
		parent->maxchilds += 4;
		parent->childs = (struct fs_component**)realloc(parent->childs, (sizeof(void*) * parent->maxchilds));
		ASSERT_FALSE(PTR_IS_ERR(parent->childs), "Memory error");
	}

	parent->childs[parent->numchilds++] = child;
	return OK;
}

int _vfs_create_subfs(struct fs_component* fs, struct fs_struct* cb, int count)	{
	int res = OK;
	fs->maxdevs = count;
	fs->currdevs = 1;
	fs->subfs = (struct fs_struct**)malloc(sizeof(struct fs_struct*) * fs->maxdevs);
	if(PTR_IS_ERR(fs->subfs))	{
		res = -USER_FAULT;
		goto err1;
	}
	fs->subfs[0] = (struct fs_struct*)malloc(sizeof(struct fs_struct));
	if(PTR_IS_ERR(fs->subfs[0]))	{
		res = -USER_FAULT;
		goto err2;
	}

	memcpy(fs->subfs[0], cb, sizeof(struct fs_struct));
err1:
	return res;
err2:
	free(fs->subfs);
	return res;
}

int _vfs_copy_name(struct fs_component* fs, const char* n)	{
	int sz = strlen(n);
	if(sz > DEVICE_NAME_MAXLEN)	{
		return -USER_FAULT;
	}
	strncpy(fs->name, n, DEVICE_NAME_MAXLEN);
	return OK;
}

int vfs_register_mount(const char* n, struct fs_struct* cb)	{
	int res = OK;
	struct fs_component* parent = NULL;
	struct fs_component* root = &(osdata.root);
	if(strlen(n) == 1 && n[0] == '/')	{
		root->rootfs = cb;
		root->name[0] = '/';
		root->name[1] = 0x00;
	}
	else	{
		PANIC("Don't know how to register mount");
	}
	return res;

	/*
	char** name = (char**)(&n);
	TZALLOC(fs, struct fs_component);
	

	res = _vfs_create_subfs(fs, cb, 1);
	if(res)	goto err1;
	// Register in the device tree
	parent = vfs_find_child(root, name);
	ASSERT_FALSE(PTR_IS_ERR(parent), "Unable to find mount point")
	
	res = _vfs_copy_name(fs, *name);
	if(res)	goto err2;
	
	res = vfs_register_child(parent, fs);

	return res;

err2:
	free(fs->subfs[0]);
	free(fs->subfs);
err1:
	free(fs);
	return res;
	*/
}

int init_vfs(void)	{
	struct fs_component* d = &(osdata.root);

	// rootfs has no name
	d->name[0] = '/';
	d->name[1] = 0x00;


//	d->opened = llist_alloc();
//	ASSERT_TRUE(d->opened != NULL, "Cannot allocate memory");

	return OK;
}

driver_init(init_vfs);

struct fs_component vfs_dev;

int init_vfs_dev(void)	{
	int res;
	struct fs_component* d = &(vfs_dev);
	struct fs_component* root = &(osdata.root);
	strcpy(d->name, "dev");

//	d->opened = llist_alloc();
//	ASSERT_TRUE(d->opened != NULL, "Cannot allocate memory");

	res = vfs_register_child(root, d);

	return res;
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

int device_unregister(struct fs_struct* dev)	{
	int i, ret = -GENERAL_FAULT;
	struct fs_component* d = &(vfs_dev);

	for(i = 0; i < d->currdevs; i++)	{
		if(strcmp(d->subfs[i]->name, dev->name) == 0)	{
			d->subfs[i] = d->subfs[--(d->currdevs)];
			ret = OK;
			break;
		}
	}
	return ret;
}

bool vfs_functions_valid(struct fs_struct* fs, bool user)	{
	// Functions can be null or they can be in user- or kernel-mode
	// This function checks address is as expected
	if(fs->open != NULL && (user != ADDR_USER(fs->open)))	return false;
	if(fs->fcntl != NULL && (user != ADDR_USER(fs->fcntl)))	return false;
	if(fs->fstat != NULL && (user != ADDR_USER(fs->fstat)))	return false;
	if(fs->write != NULL && (user != ADDR_USER(fs->write)))	return false;
	if(fs->read != NULL && (user != ADDR_USER(fs->read)))	return false;
	if(fs->lseek != NULL && (user != ADDR_USER(fs->lseek)))	return false;
	if(fs->close != NULL && (user != ADDR_USER(fs->close)))	return false;
	if(fs->getc != NULL && (user != ADDR_USER(fs->getc)))	return false;
	if(fs->putc != NULL && (user != ADDR_USER(fs->putc)))	return false;

	return true;
}

/*
* Series of empty functions which do nothing, but do return value indicating success.
* Exception is fcntl, if 0 is returned, caller expects that fcntl structure has been populated.
* Read is also somewhat awkward since we always return 0 indicating that no bytes have been read
*/
int vfs_empty_open(struct vfsopen* o, const char* name, int flags, int mode) { return o->fd; }
int vfs_empty_close(struct vfsopen* o)							{ return OK; }
int vfs_empty_read(struct vfsopen* o, void* buf, size_t len)	{ return OK; }
int vfs_empty_fcntl(struct vfsopen* o, ptr_t cmd, ptr_t arg)	{ return OK; }
int vfs_empty_fstat(struct vfsopen* o, struct stat* statbuf)				{ return -UNSUPPORTED_FUNC; }
int vfs_empty_write(struct vfsopen* o, const void* data, size_t len) { return len; }
int vfs_empty_getc(struct vfsopen* o)							{ return OK; }
int vfs_empty_putc(struct vfsopen* o, int c)					{ return OK; }
int vfs_empty_lseek(struct vfsopen* o, off_t off, int op)		{ return OK; }

/*
* Series of functions which indicate that the function is unsupported.
*/
int vfs_unsupported_open(struct vfsopen* o, const char* name, int flags, int mode) { return -UNSUPPORTED_FUNC; }
int vfs_unsupported_close(struct vfsopen* o)						{ return -UNSUPPORTED_FUNC; }
int vfs_unsupported_read(struct vfsopen* o, void* buf, size_t len)	{ return -UNSUPPORTED_FUNC; }
int vfs_unsupported_fcntl(struct vfsopen* o, ptr_t cmd, ptr_t arg)	{ return -UNSUPPORTED_FUNC; }
int vfs_unsupported_fstat(struct vfsopen* o, struct stat* statbuf)			{ return -UNSUPPORTED_FUNC; }
int vfs_unsupported_write(struct vfsopen* o, const void* data, size_t len) { return -UNSUPPORTED_FUNC; }
int vfs_unsupported_getc(struct vfsopen* o)							{ return -UNSUPPORTED_FUNC; }
int vfs_unsupported_putc(struct vfsopen* o, int c)					{ return -UNSUPPORTED_FUNC; }
int vfs_unsupported_lseek(struct vfsopen* o, off_t off, int op)		{ return -UNSUPPORTED_FUNC; }


