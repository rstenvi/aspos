/**
* Management of Virtual File System (VFS).
*/

#include "kernel.h"
#include "vfs.h"
#include "syscalls.h"


#define VFS_GET_FS(o) (ADDR_USER(o)) ? get_user(o->fs, ptr_t) : o->fs

struct vfsopen* vfs_alloc_open(int tid, int fd, struct fs_struct* fs)	{
	struct vfsopen entry;
	TMALLOC(n, struct vfsopen);
	if(PTR_IS_ERR(n))	return n;

	entry.tid = tid;
	entry.fd = fd;
	//entry.fs = fs;
	entry.data = fs;
	entry.offset = 0;
	entry.svcid = curr_svcid();

	// Thread manager should fill this in, to avoid a default-root user, we
	// overwrite the entire struct with 1's
	memset(&(entry.caller), 0xff, sizeof(struct user_id));

	memcpy(n, &entry, sizeof(struct vfsopen));
	return n;
}

struct fs_component* _vfs_walk_path(struct fs_component* root, char** _name, int* plus)	{
	char* name = *_name;
	struct fs_component* curr, *_root = root;
	size_t clen, i, len;
	do {
		_root = root;
		clen = strlen(root->name);
		if(strlen(name) < clen || strncmp(root->name, name, clen))	{
			logw("Unable to find path for '%s'\n", name);
			return NULL;
		}
		*plus += clen;
		name = name + clen;
		if(*name == '/')	{
			name++;
			*plus += 1;
		}
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
	return root;
}


struct fs_struct* vfs_walk_path(struct fs_component* root, char** _name)	{
	size_t i;
	int plus = 0;
	char* name = *_name;
	root = _vfs_walk_path(root, &name, &plus);
	if(!root)	return NULL;

	name += plus;
	*_name = name;
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
	struct fs_component* d = &(osdata.root);
	struct fs_struct* fs;

	fs = vfs_walk_path(d, name);
	// fs may be NULL
	return fs;
}
int vfs_open(struct thread_fd_open* fdo, const char* name, int flags, int mode)	{
	int res = -USER_FAULT;
	struct fs_struct* fs = fdo->fs;

	if(fs->open != NULL)	{
		res = fs->open(fdo->open, name, flags, mode);
	}
	return res;
}

int vfs_fstat(struct thread_fd_open* fdo, struct stat* statbuf)	{
	int res = -USER_FAULT;
	struct fs_struct* fs = fdo->fs;
	ASSERT_USER(statbuf);

	if(fs->fstat != NULL)	{
		res = fs->fstat(fdo->open, statbuf);
	}
	return res;
}

int vfs_fcntl(struct thread_fd_open* fdo, ptr_t cmd, ptr_t arg)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	if(fs->fcntl != NULL)	{
		res = fs->fcntl(o, cmd, arg);
	}
	return res;
}
int vfs_read(struct thread_fd_open* fdo, void* buf, size_t max)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	ASSERT_USER_MEM(buf, max);

	if(fs->read != NULL)	{
		res = fs->read(o, buf, max);
	}

	return res;
}
int vfs_write(struct thread_fd_open* fdo, const void* buf, size_t max)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	ASSERT_USER_MEM(buf, max);
	if(fs->write != NULL)	{
		res = fs->write(o, buf, max);
	}
	return res;
}
int vfs_mmap(struct thread_fd_open* fdo, void* addr, size_t length)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	//ASSERT_USER_MEM(addr, length);
	if(fs->mmap != NULL)	{
		res = fs->mmap(o, addr, length);
	}
	return res;
}

off_t generic_lseek(struct vfsopen* o, off_t offset, int whence)	{
	off_t res;
	switch(whence)	{
		case SEEK_SET:
			o->offset = offset;
			break;
		case SEEK_CUR: {
			if(__builtin_add_overflow(o->offset, offset, &res))	{
				logw("seek resulted in overflow %lx + %lx\n", o->offset, offset);
				res = (off_t)-1;
			}
			else	{
				o->offset = res;
			}
			break;
		}
		case SEEK_END:
//		case SEEK_DATA:
//		case SEEK_HOLE:
		default:
			logw("Unsupported lseek: %lx\n", whence);
			return (off_t)-1;
	}
	return (o->offset);
}
off_t vfs_lseek(struct thread_fd_open* fdo, off_t offset, int whence)	{
	off_t res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	if(fs->lseek != NULL)	{
		res = fs->lseek(o, offset, whence);
	}
	else	{
		res = generic_lseek(o, offset, whence);
	}
	return res;
}

int vfs_close(struct thread_fd_open* fdo)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	if(fs->close != NULL)	{
		res = fs->close(o);
	}
	return res;
}
int vfs_getchar(struct thread_fd_open* fdo)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	if(fs->getc != NULL)	{
		res = fs->getc(o);
	}
	return res;
}
int vfs_putchar(struct thread_fd_open* fdo, int c)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	if(fs->putc != NULL)	{
		res = fs->putc(o, c);
	}
	return res;
}

int vfs_register_child(struct fs_component* parent, struct fs_component* child)	{
	if(parent->numchilds == parent->maxchilds)	{
		parent->maxchilds += 4;
		parent->childs = (struct fs_component**)krealloc(parent->childs, (sizeof(void*) * parent->maxchilds));
		ASSERT_FALSE(PTR_IS_ERR(parent->childs), "Memory error");
	}

	parent->childs[parent->numchilds++] = child;
	return OK;
}

int _vfs_create_subfs(struct fs_component* fs, struct fs_struct* cb, int count)	{
	int res = OK;
	fs->maxdevs = count;
	fs->currdevs = 1;
	fs->subfs = (struct fs_struct**)kmalloc(sizeof(struct fs_struct*) * fs->maxdevs);
	if(PTR_IS_ERR(fs->subfs))	{
		res = -USER_FAULT;
		goto err1;
	}
	fs->subfs[0] = cb;
err1:
	return res;
}

int _vfs_copy_name(struct fs_component* fs, const char* n)	{
	int sz = strlen(n);
	if(sz > DEVICE_NAME_MAXLEN)	{
		return -USER_FAULT;
	}
	memcpy(fs->name, n, DEVICE_NAME_MAXLEN);
	return OK;
}
bool _subfs_exists(struct fs_component* fs, const char* name)	{
	size_t i;
	for(i = 0; i < fs->currdevs; i++)	{
		if(!strcmp(name, fs->subfs[i]->name))	return true;
	}
	return false;
}

int vfs_register_mount(const char* n, struct fs_struct* cb)	{
	int res = OK;
	struct fs_component* parent = NULL;
	struct fs_component* root = &(osdata.root);
	if(strlen(n) == 0)	{
		logw("Tried to register mount with empty string\n");
		return -USER_FAULT;
	}
	if(strlen(n) == 1 && n[0] == '/')	{
		root->rootfs = cb;
		root->name[0] = '/';
		root->name[1] = 0x00;
	}
	else	{
		char** name = (char**)(&n), *_n = (char*)n;
		int plus = 0;
		parent = _vfs_walk_path(root, name, &plus);
		if(!parent)	return -USER_FAULT;

		_n += plus;
		if(_subfs_exists(parent, _n))	{
			logw("Device already exists: %s\n", _n);
			return -USER_FAULT;
		}

		TZALLOC(fs, struct fs_component);
		if(PTR_IS_ERR(fs))	return -MEMALLOC;

		res = _vfs_copy_name(fs, _n);
		if(res != OK)		goto err1;

		// Register this as the default fs to use
		fs->rootfs = cb;

		res = vfs_register_child(parent, fs);
		return res;
err1:
		kfree(fs);
	}
	return res;
}

int init_vfs(void)	{
	struct fs_component* d = &(osdata.root);

	// rootfs has no name
	d->name[0] = '/';
	d->name[1] = 0x00;
	return OK;
}

driver_init(init_vfs);

static void _delete_fs_comp(struct fs_component* fs)	{
	size_t i;
	for(i = 0; i < fs->numchilds; i++)	{
		_delete_fs_comp(fs->childs[i]);
	}
	kfree(fs->childs);
	kfree(fs->subfs);
}
int vfs_exit(void)	{
	struct fs_component* d = &(osdata.root);
	_delete_fs_comp(d);
	return 0;
}
poweroff_exit(vfs_exit);

static struct fs_component vfs_dev;

int init_vfs_dev(void)	{
	int res;
	struct fs_component* d = &(vfs_dev);
	struct fs_component* root = &(osdata.root);
	strcpy(d->name, "dev");

	res = vfs_register_child(root, d);
	return res;
}

driver_init(init_vfs_dev);

int device_register(struct fs_struct* dev)	{
	struct fs_component* d = &(vfs_dev);

#if defined(CONFIG_SUPPORT_USERS)
	dev->owner.uid = driver_uid();
	dev->owner.gid = driver_gid();
#endif
	if(strlen(dev->name) == 0)	{
		logw("Tried to register device with empty name\n");
		return -USER_FAULT;
	}

	if(_subfs_exists(d, dev->name))	{
		logw("Dev %s already exists");
		return -USER_FAULT;
	}

	if(d->currdevs >= d->maxdevs)	{
		d->maxdevs += 10;
		d->subfs = (struct fs_struct**)krealloc(d->subfs, sizeof(void*) * d->maxdevs);
		ASSERT_TRUE(d->subfs != NULL, "Unable to allocate space for devices");
	}
	d->subfs[d->currdevs++] = dev;
	return OK;
}

int device_unregister(struct fs_struct* dev)	{
	size_t i;
	int ret = -GENERAL_FAULT;
	struct fs_component* d = &(vfs_dev);

	for(i = 0; i < d->currdevs; i++)	{
		if(strcmp(d->subfs[i]->name, dev->name) == 0)	{
			d->subfs[i] = d->subfs[--(d->currdevs)];
			ret = OK;
			break;
		}
	}
	for(i = 0; i < d->numchilds; i++)	{
		if(strcmp(d->childs[i]->name, dev->name) == 0)	{
			d->childs[i] = d->childs[--(d->numchilds)];
			ret = OK;
			break;
		}
	}
	if(osdata.root.rootfs == dev)	{
		WRITE_ONCE(osdata.root.rootfs, NULL);
		ret = OK;
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

int vfs_fstat_fill_common(struct fs_struct* fs, struct stat* sb, enum file_type ft)	{
	sb->st_mode = (1 << (((uint32_t)ft) + 16)) | (uint32_t)fs->perm;
#if defined(CONFIG_SUPPORT_USERS)
	sb->st_uid = fs->owner.uid;
	sb->st_gid = fs->owner.gid;
#endif
	return OK;
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


/*
static int _vfs_generic_user(struct thread_fd_open* fdo, ptr_t entry, int num, ...)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	struct process* p = cuse_get_process(fs);
	struct thread* t;
	struct threads* allt = cpu_get_threads();
	va_list ap;
	int i;
	ptr_t arg;

	t = new_thread_kernel(current_proc(), entry, allt->exc_exit, true, false);
	if(PTR_IS_ERR(t))	return PTR_TO_ERRNO(t);
	set_thread_owner(t);

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

	thread_wait_tid(t->id, false);

	// The current thread must block until new thread has finished
	return -BLOCK_THREAD_ID;
}
static int _vfs_open_user(struct thread_fd_open* fdo, const char* name, int flags, int mode)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	return thread_create_driver_thread(fdo, (ptr_t)fs->open, SYS_OPEN, 3, name, flags, mode);
}
static int _vfs_fstat_user(struct thread_fd_open* fdo, struct stat* statbuf)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	return thread_create_driver_thread(fdo, (ptr_t)fs->fstat, SYS_FSTAT, 1, statbuf);
}
static int _vfs_fcntl_user(struct thread_fd_open* fdo, ptr_t cmd, ptr_t arg)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	return thread_create_driver_thread(fdo, (ptr_t)fs->fcntl, SYS_FCNTL, 2, cmd, arg);
}
static int _vfs_read_user(struct thread_fd_open* fdo, const void* buf, size_t max)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	return thread_create_driver_thread(fdo, (ptr_t)fs->read, SYS_READ, 2, buf, max);
}
static int _vfs_write_user(struct thread_fd_open* fdo, const void* buf, size_t max)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	return thread_create_driver_thread(fdo, (ptr_t)fs->write, SYS_WRITE, 2, buf, max);
}
static int _vfs_mmap_user(struct thread_fd_open* fdo, void* addr, size_t length)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	PANIC("Not implemented yet\n");
//	return thread_create_driver_thread(fdo, (ptr_t)fs->write, SYS_MMAP, 2, buf, max);
}
static off_t _vfs_lseek_user(struct thread_fd_open* fdo, off_t offset, int whence)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	return thread_create_driver_thread(fdo, (ptr_t)fs->lseek, SYS_LSEEK, 2, offset, whence);
}
static int _vfs_close_user(struct thread_fd_open* fdo)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	return thread_create_driver_thread(fdo, (ptr_t)fs->close, SYS_CLOSE, 0);
}
static int _vfs_getchar_user(struct thread_fd_open* fdo)	{
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;
	return thread_create_driver_thread(fdo, (ptr_t)fs->getc, SYS_GET_CHAR, 0);
}
static int _vfs_putchar_user(struct thread_fd_open* fdo, int c)	{
	return thread_create_driver_thread(fdo, (ptr_t)fdo->fs->putc, SYS_PUT_CHAR, 1, c);
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
int vfs_mmap(struct vfsopen* o, void* addr, size_t len)	{
	int res = -USER_FAULT;
	if(o->fs->mmap != NULL)	return o->fs->mmap(o, addr, len);
	return res;
}

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
static int vfs_add_to_open_root(struct vfsopen* n)	{
	struct fs_component* d = &(osdata.root);
	llist_insert(d->opened, n, n->fd);
	return OK;
}
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
		kfree(n);
		return res;
	}
	
	vfs_add_to_open_root(n);
	return n->fd;
}
static const char* vfs_next_node(const char* name)	{
	char* end = strchr(name, '/');
	return (end != NULL) ? end : name;
}
static int vfs_find_name(struct fs_component* d, const char* name)	{
	int best_match = -1, len = strlen(name), l;
	size_t i;
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
void vfs_free_open(struct thread_fd_open* fdo)	{
	if(!ADDR_USER(fdo->open))	{
		kfree(fdo->open);
	}
//	slab_free_32(fdo->open, fdo->fs->user);
}
int vfs_dup(struct thread_fd_open* fdo)	{
	int res = -USER_FAULT;
	struct vfsopen* o = fdo->open;
	struct fs_struct* fs = fdo->fs;

	if(fs->dup != NULL)	{
		res = fs->dup(o);
	}
	return res;
}

*/

// Static check in size of vfsopen
//SLAB_CHK_SIZE(struct vfsopen, 24);
