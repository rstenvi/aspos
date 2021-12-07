/**
* Character driver in user space (CUSE)
*
* This driver is basically a middle-layer to VFS and is the essential driver
* which allows user-mode drivers.
*
* Since each driver must open a FD for this driver to create a driver and all
* interaction to this driver and to user-mode driver passes through this driver,
* we got a somewhat messy system of pointers.
*
* - CUSE: vfsopen->data -- Holds `struct cuse_proc` with information about
*   user-mode devices
* - UMODE: vfsopen->data -- Holds the `struct fs_struct` which the VFS uses to
*   reach all `cuse_mitm_*` defined in this driver
* - UMODE (fake): fs_struct->private_data -- Holds the same `struct cuse_proc`
*   mentioned in the first list item
*
* Both file descriptors can be closed out-of-order. As a result, we close
* everything when umode driver file descriptor is closed.
* - TODO: Must implement this
*/

#include "kernel.h"
#include "vfs.h"
#include "lib.h"
#include "syscalls.h"

#define THREAD_EXIT (0)

#define ALLOC_BLK_SZ (16)

#define JOBID_FREE  (1)
#define JOBID_COPY  (2)
#define JOBID_ADDR  (3)
#define JOBID_CLOSE (4)
#define JOBID_OPEN  (5)
//#define JOBID_COPYKERN (6)


struct cuse_addr {
	ptr_t addr;
	ptr_t size;
};
struct cuse_memregion {
	mutex_t lock;
	struct cuse_addr region;
	struct bm*       free;
};
struct cuse_job {
	int id;
	struct cuse_memregion* region;
	void* data;
};
struct cuse_job_copy {
	struct cuse_addr alloc;
	void* addr;
	struct process* caller;
};
struct cuse_job_close {
	struct process* p;
	struct cuse_proc* cproc;
	int fid;
};
struct cuse_open {
	struct thread_fd_open* fdo;
	struct process* p;
};
struct cuse_proc {
	struct cuse_memregion region;
	struct fs_struct* realfs;
	struct fs_struct* fakefs;
	struct process* owner;
	bool detached;
};
struct cuse_data {
	mutex_t lock;
	struct llist* jobs;
	struct llist* openfds;
};

struct cuse_data cuse_data = {0};

static int _cuse_init_memregion(struct cuse_memregion* mem, ptr_t addr, ptr_t size)	{
	mutex_clear(&mem->lock);
	mem->region.addr = addr;
	mem->region.size = size;

	int blocks = size / ALLOC_BLK_SZ;
	int bytes = blocks / 8;

	mem->free = bm_create(bytes);
	return 0;
}

static int _cuse_free_memory(struct cuse_memregion* mem, ptr_t addr, size_t sz)	{
	if(!IS_ALIGNED_ON(addr, ALLOC_BLK_SZ))	return -USER_FAULT;

	sz = GET_ALIGNED_UP_POW2(sz, ALLOC_BLK_SZ);
	int numblks = sz / ALLOC_BLK_SZ;

	if(addr < mem->region.addr)	return -USER_FAULT;
	if(addr + sz > (mem->region.addr + mem->region.size))	return -USER_FAULT;

	int startidx = (addr - mem->region.addr) / ALLOC_BLK_SZ;
	bm_clear_nums(mem->free, startidx, numblks);
	return OK;
}
static int _cuse_job_open_perform(struct cuse_job* job, int res)	{
	struct cuse_open* copen = (struct cuse_open*)job->data;
	struct process* p = copen->p;
	if(res > 0)	{
		llist_insert(p->fds, copen->fdo, res);
	} else {
		kfree((void*)copen->fdo);
	}
	return res;
}
static int _cuse_job_close_perform(struct cuse_job* job, int res)	{
	logw("cuse: Need to properly close\n");
	struct cuse_job_close* jobd = (struct cuse_job_close*)job->data;
//	struct process* p = jobd->p;
	struct cuse_proc* cproc = jobd->cproc;
	if(PTR_IS_VALID(cproc->realfs))	{
		kfree(cproc->realfs);
		WRITE_ONCE(cproc->realfs, NULL);
	}
	/*
	if(PTR_IS_VALID(cproc->fakefs))	{
		kfree(cproc->fakefs);
		WRITE_ONCE(cproc->fakefs, NULL);
	}*/

// 	struct cuse_memregion* mem = &cproc->region;
// 	if(mem->region.addr)	{
// 		bm_delete(mem->free);
// 	}
// 	kfree(cproc);
	//int fid = jobd->fid;
/*
	struct thread_fd_open* fdo = llist_remove(p->fds, fid);
	if(PTR_IS_ERR(fdo))	{
		loge("Error ptr %p\n", fdo);
	} else	{
		bm_clear(p->fileids, fid);
		_thread_free_vfsopen(fdo);
		kfree(fdo);
	}
	*/

/*
	*/

	return 0;
}
static int _cuse_job_free_perform(struct cuse_job* job)	{
	struct cuse_addr* caddr = (struct cuse_addr*)job->data;
	return _cuse_free_memory(job->region, caddr->addr, caddr->size);
}
static int _cuse_job_copy_perform(struct cuse_job* job, int res)	{
	struct cuse_job_copy* copy = (struct cuse_job_copy*)job->data;

	// Copy data back to caller
	if(res >= 0)	{
		if(ADDR_USER(copy->addr))	{
			mmu_memcpy(copy->caller->user_pgd, (void*)copy->addr, (void*)copy->alloc.addr, copy->alloc.size);
		} else {
			memcpy((void*)copy->addr, (void*)copy->alloc.addr, copy->alloc.size);
		}
	}

	// Free up the region
	return _cuse_free_memory(job->region, copy->alloc.addr, copy->alloc.size);
}
static int _cuse_perform_job(struct cuse_job* job, int res)	{
	int ret = OK;
	switch(job->id)	{
	case JOBID_FREE:
		_cuse_job_free_perform(job);
		kfree((void*)job->data);
		break;
	case JOBID_COPY:
		_cuse_job_copy_perform(job, res);
		kfree((void*)job->data);
		break;
	case JOBID_OPEN:
		_cuse_job_open_perform(job, res);
		kfree((void*)job->data);
		break;
	case JOBID_CLOSE:
		_cuse_job_close_perform(job, res);
		kfree((void*)job->data);
		ret = 1;
		break;
	default:
		PANIC("Unsupported job");
		break;
	}
	kfree(job);
	return ret;
}
static int _cuse_perform_jobs(int svcid, int res)	{
	int r = 0, _r;
	struct cuse_data* d = &cuse_data;
	struct cuse_job* j;
	mutex_acquire(&d->lock);
	while((j = llist_remove(d->jobs, svcid)) != NULL)	{
		_r = _cuse_perform_job(j, res);
		if(_r)	r = _r;
	}
	mutex_release(&d->lock);
	return r;
}
/*
static ptr_t cuse_alloc(struct cuse_memregion* mem, struct process* target, size_t len)	{
	len = GET_ALIGNED_UP_POW2(len, ALLOC_BLK_SZ);

	ptr_t vaddr = cuse_get_addr(mem, len);
	TZALLOC_ERR(job, struct cuse_job);
	TZALLOC_ERR(data, struct cuse_addr);
	data->addr = vaddr;
	data->size = len;
	job->id = JOBID_FREE;
	job->data = (void*)data;

	_cuse_add_job(svcid, job);
	return vaddr;
}*/

static ptr_t _cuse_alloc_memory(struct cuse_memregion* mem, size_t sz)	{
	size_t asz = GET_ALIGNED_UP_POW2(sz, ALLOC_BLK_SZ);
	if(asz > mem->region.size)		return -USER_FAULT;

	int numblks = (int)(asz / ALLOC_BLK_SZ);
	long off = bm_get_first_num(mem->free, numblks);
	ASSERT(off >= 0);

	return mem->region.addr + ((ptr_t)off * ALLOC_BLK_SZ);
}
static int _cuse_add_job(struct cuse_job* job)	{
	struct cuse_data* d = &cuse_data;
	llist_insert(d->jobs, job, curr_svcid());
	return OK;
}
static int _cuse_add_job_open(struct vfsopen* o, struct process* p, struct fs_struct* fs, int flags)	{
	struct cuse_data* d = &cuse_data;
	TZALLOC(job, struct cuse_job);
	job->id = JOBID_OPEN;
	TZALLOC(open, struct cuse_open);
	TZALLOC(fdo, struct thread_fd_open);

	fdo->fs = fs;
	fdo->open = o;
	fdo->open_flags = flags;

	open->fdo = fdo;
	open->p = p;

	job->data = (void*)open;
	llist_insert(d->jobs, job, curr_svcid());
	return OK;
}
static int _cuse_add_job_close(struct vfsopen* o, struct process* p, struct cuse_proc* cproc)	{
	struct cuse_data* d = &cuse_data;
	TZALLOC(job, struct cuse_job);
	TZALLOC(data, struct cuse_job_close);

	data->fid = o->fd;
	data->p = p;
	data->cproc = cproc;

	job->id = JOBID_CLOSE;
	job->data = (void*)data;

	// Add to list
	llist_insert(d->jobs, job, curr_svcid());
	return OK;
}
/*
static int _cuse_add_job_copykern(ptr_t from, ptr_t to, size_t sz)	{
	TZALLOC(job, struct cuse_job);
	TZALLOC(caddr1, struct cuse_addr);
	TZALLOC(caddr2, struct cuse_addr);
	caddr->addr = addr;
	caddr->size = sz;
	job->data = caddr;
	_cuse_add_job(job);
	return OK;
}
*/

#define ONEWAY_FROM (1 << 1)
#define ONEWAY_TO   (1 << 2)
#define TWOWAYS     (ONEWAY_FROM | ONEWAY_TO)


#define CUSE_COPYBACK true
#define CUSE_COPYTO   true
static ptr_t cuse_memcpy(struct cuse_memregion* mem, struct process* target, ptr_t data, size_t len, bool copyback, bool copyto)	{
	int alen = GET_ALIGNED_UP_POW2(len, ALLOC_BLK_SZ);
	ptr_t vaddr = _cuse_alloc_memory(mem, alen);

	TZALLOC_ERR(job, struct cuse_job);
	job->region = mem;
	if(copyback)	{
		if(copyto)	{
			mmu_memcpy(target->user_pgd, (void*)vaddr, (void*)data, len);
		}
		TZALLOC_ERR(jobd, struct cuse_job_copy);
		job->id = JOBID_COPY;
		jobd->alloc.addr = vaddr;
		jobd->alloc.size = alen;
		jobd->addr = (void*)data;
		jobd->caller = current_proc();
		job->data = (void*)jobd;

	} else {
		if(copyto)	{
			mmu_memcpy(target->user_pgd, (void*)vaddr, (void*)data, len);
		}
		TZALLOC_ERR(jobd, struct cuse_addr);
		job->id = JOBID_FREE;
		jobd->addr = vaddr;
		jobd->size = alen;
		job->data = (void*)jobd;
	}
	_cuse_add_job(job);
	return vaddr;
}
static ptr_t cuse_store_addr(struct cuse_memregion* mem, struct process* target, ptr_t addr)	{
	TZALLOC_ERR(job, struct cuse_job);
	job->id = JOBID_ADDR;
	// TODO: This leaks adresses, not a big problem, but undesirable
	job->data = (void*)addr;
	return 0;
}
static ptr_t sysno_to_entry(struct fs_struct* fs, int sysno)	{
	ptr_t ret = 0;
	switch(sysno)	{
	case SYS_CLOSE:
		ret = (ptr_t)fs->close;
		break;
	case SYS_OPEN:
		ret = (ptr_t)fs->open;
		break;
	case SYS_WRITE:
		ret = (ptr_t)fs->write;
		break;
	case SYS_READ:
		ret = (ptr_t)fs->read;
		break;
	case SYS_GET_CHAR:
		ret = (ptr_t)fs->getc;
		break;
	case SYS_PUT_CHAR:
		ret = (ptr_t)fs->putc;
		break;
	case SYS_FSTAT:
		ret = (ptr_t)fs->fstat;
		break;
	case SYS_FCNTL:
		ret = (ptr_t)fs->fcntl;
		break;
	default:
		loge("Unknown sysno: %i\n", sysno);
		break;
	}
	return ret;
}
static struct vfsopen* _cuse_find_vfsopen(tid_t tid, fd_t fd)	{
	struct cuse_data* d = &cuse_data;
	uint64_t id = ((uint64_t)tid << 32) | (fd & 0xffffffff);
	struct vfsopen* o;
	mutex_acquire(&d->lock);
	o = llist_find(d->openfds, id);
	mutex_release(&d->lock);
	return o;
}
static struct vfsopen* _cuse_get_new_vfsopen(struct vfsopen* kerno, tid_t tid, fd_t fd)	{
	struct cuse_data* d = &cuse_data;
	uint64_t id = ((uint64_t)tid << 32) | (fd & 0xffffffff);
	TZALLOC(o, struct vfsopen);
	o->tid = tid;
	o->fd = fd;
	memcpy(&(o->caller), &(kerno->caller), sizeof(struct user_id));

	mutex_acquire(&d->lock);
	llist_insert(d->openfds, o, id);
	mutex_release(&d->lock);

	return o;
}
static int cuse_new_thread(struct vfsopen* o, struct vfsopen* usero, int sysno, int num, ...)	{
	struct thread* t;
	int i;
	va_list ap;
	ptr_t arg, allargs[8] = {0};
	GET_VFS_DATA(o, struct fs_struct, fs);
	struct cuse_proc* cproc = (struct cuse_proc*)fs->private_data;
	struct fs_struct* ufs = cproc->realfs;
	struct process* p = current_proc();
//	struct vfsopen local;

	ASSERT(PTR_IS_VALID(p));
	ASSERT(PTR_IS_VALID(ufs));
	ASSERT(PTR_IS_VALID(cproc));
	ASSERT(PTR_IS_VALID(fs));

	ptr_t entry = sysno_to_entry(ufs, sysno);
	if(entry == 0)	return -USER_FAULT;

	t = new_thread_kernel(cproc->owner, entry, THREAD_EXIT, THREAD_UMODE, THREAD_NOT_READY);
	ASSERT(PTR_IS_VALID(t));

#if defined(CONFIG_KCOV)
	struct kcov* kcov = get_current_kcov();
	if(PTR_IS_VALID(kcov))	{
		t->tinfo.caller_kcov = kcov->data;
	}
#endif

	// First argunment is the vfsopen specified by the caller
//	memcpy(&local, o, sizeof(struct vfsopen));
//	local.svcid = curr_svcid();
//	local.data = NULL;
	usero->svcid = curr_svcid();
	ptr_t uo = cuse_memcpy(&cproc->region, cproc->owner, (ptr_t)usero, sizeof(struct vfsopen), true, true);
	arch_thread_set_arg(t->stackptr, (ptr_t)uo, 0);

	va_start(ap, num);
	for(i = 1; i <= num; i++)	{
		arg = va_arg(ap, ptr_t);
		arch_thread_set_arg(t->stackptr, arg, i);
		allargs[i-1] = arg;
	}
	va_end(ap);

	switch(sysno)	{
	case SYS_OPEN: {
		int l = strlen_user((char*)allargs[0]);
		if(l > 0)	{
			ptr_t nvaddr = cuse_memcpy(&cproc->region, cproc->owner, allargs[0], l, false, true);
			arch_thread_set_arg(t->stackptr, nvaddr, 1);
			_cuse_add_job_open(o, p, fs, allargs[1]);
		}
		break;
	}
	case SYS_WRITE: {
		ptr_t nvaddr = cuse_memcpy(&cproc->region, cproc->owner, allargs[0], allargs[1], false, true);
		arch_thread_set_arg(t->stackptr, nvaddr, 1);
		break;
	}
	case SYS_READ: {
		ptr_t nvaddr = cuse_memcpy(&cproc->region, cproc->owner, allargs[0], allargs[1], true, false);
		arch_thread_set_arg(t->stackptr, nvaddr, 1);
		break;
	}
	case SYS_FCNTL:
		cuse_store_addr(&cproc->region, cproc->owner, allargs[1]);
		break;
	case SYS_CLOSE:
		_cuse_add_job_close(o, p, cproc);
		break;
	default:
		logw("Unknown syscall: %i", sysno);
		break;
	}

	thread_wait_tid(t->id, THREAD_NO_SCHEDULE, LOCK_NOT_HELD);
	thread_add_ready(t, THREAD_ADD_FRONT, LOCK_NOT_HELD);

	// Block this thread until we 
	return -BLOCK_THREAD_ID;
}

#define CUSE_EXEC(func, o, usero, sysno, num, ...) \
	GET_VFS_DATA(o, struct fs_struct, fs);\
	if(PTR_IS_VALID(fs)) {\
		struct cuse_proc* cproc = (struct cuse_proc*)fs->private_data; \
		if(PTR_IS_VALID(cproc)) {\
			struct fs_struct* ufs = cproc->realfs; \
			return ADDR_USER(ufs->func) ? \
				cuse_new_thread(o, usero, sysno, num, ##__VA_ARGS__) : \
				ufs->func(o, ##__VA_ARGS__);\
		}\
	}\
	return -USER_FAULT

int cuse_mitm_open(struct vfsopen* o, const char* name, int flags, int mode) {
	struct vfsopen* usero = _cuse_get_new_vfsopen(o, o->tid, o->fd);
	CUSE_EXEC(open, o, usero, SYS_OPEN, 3, name, flags, mode);
}
int cuse_empty_close(struct vfsopen* o)	{
	logw("cuse: empty_close called\n");
	return OK;
}
int cuse_mitm_close(struct vfsopen* o) {
	// TODO: Might need to do some cleanup
	struct vfsopen* usero = _cuse_find_vfsopen(o->tid, o->fd);
	CUSE_EXEC(close, o, usero, SYS_CLOSE, 0);
}
int cuse_mitm_read(struct vfsopen* o, void* buf, size_t len) {
	struct vfsopen* usero = _cuse_find_vfsopen(o->tid, o->fd);
	CUSE_EXEC(read, o, usero, SYS_READ, 2, buf, len);
}
int cuse_mitm_fcntl(struct vfsopen* o, ptr_t cmd, ptr_t arg)	{
	struct vfsopen* usero = _cuse_find_vfsopen(o->tid, o->fd);
	CUSE_EXEC(fcntl, o, usero, SYS_FCNTL, 2, cmd, arg);
}
int cuse_mitm_fstat(struct vfsopen* o, struct stat* statbuf) {
	struct vfsopen* usero = _cuse_find_vfsopen(o->tid, o->fd);
	CUSE_EXEC(fstat, o, usero, SYS_FSTAT, 1, statbuf);
}
int cuse_mitm_write(struct vfsopen* o, const void* buf, size_t len) {
	struct vfsopen* usero = _cuse_find_vfsopen(o->tid, o->fd);
	CUSE_EXEC(write, o, usero, SYS_WRITE, 2, buf, len);
}
int cuse_mitm_getc(struct vfsopen* o) {
	struct vfsopen* usero = _cuse_find_vfsopen(o->tid, o->fd);
	CUSE_EXEC(getc, o, usero, SYS_GET_CHAR, 0);
}
int cuse_mitm_putc(struct vfsopen* o, int c) {
	struct vfsopen* usero = _cuse_find_vfsopen(o->tid, o->fd);
	CUSE_EXEC(putc, o, usero, SYS_PUT_CHAR, 1, c);
}
int cuse_mitm_lseek(struct vfsopen* o, off_t off, int op) {
	struct vfsopen* usero = _cuse_find_vfsopen(o->tid, o->fd);
	CUSE_EXEC(lseek, o, usero, SYS_LSEEK, 2, off, op);
}
int cuse_mitm_mmap(struct vfsopen* o, void* addr, size_t length)	{
	PANIC("Not supported yet");
	return -GENERAL_FAULT;
}
struct fs_struct* _cuse_alloc_mitm(void)	{
	TZALLOC(fs, struct fs_struct);
	fs->open   = cuse_mitm_open;
	fs->close  = cuse_mitm_close;
	fs->read   = cuse_mitm_read;
	fs->fcntl  = cuse_mitm_fcntl;
	fs->fstat  = cuse_mitm_fstat;
	fs->write  = cuse_mitm_write;
	fs->getc   = cuse_mitm_getc;
	fs->putc   = cuse_mitm_putc;
	fs->lseek  = cuse_mitm_lseek;

	return fs;
}

struct process* cuse_get_process(struct fs_struct* fs)	{
	PANIC("Should not be called");
	//ASSERT_VALID_PTR(fs->private_data);
	//return (struct process*)fs->private_data;
	return NULL;
}

static int _cuse_set_fs_ops(struct vfsopen* o, struct fs_struct* _fs)	{
	int ret = OK;
	if(PTR_IS_ERR(_fs) || !ADDR_USER(_fs))	{
		return -USER_FAULT;
	}

	GET_VFS_DATA(o, struct cuse_proc, cproc);
	if(PTR_IS_ERR(cproc))	{
		return -USER_FAULT;
	}

	if(cproc->realfs != NULL)	{
		logw("Tried to set fs_ops twice\n");
		return -USER_FAULT;
	}

	struct fs_struct* fs = cproc->fakefs;
	if(PTR_IS_ERR(fs))	{
		return -USER_FAULT;
	}

	TZALLOC_ERR(ufs, struct fs_struct);
	if(memcpy_from_user(ufs, _fs, sizeof(struct fs_struct)))	{
		logw("Unable to copy from user\n");
		return -USER_FAULT;
	}
	// All function pointers must belong to user-space, otherwise
	// we would execute the functions in kernel mode
	if(!vfs_functions_valid(ufs, true))	{
		ret = -USER_FAULT;
		goto err1;
	}

	// Register under the name specified by caller
	memcpy(fs->name, ufs->name, DEVICE_NAME_MAXLEN);
	WRITE_ONCE(cproc->realfs, ufs);
	WRITE_ONCE(fs->private_data, (void*)cproc);
	return ret;

err1:
	kfree(ufs);
	return ret;
}
static int _cuse_register(struct vfsopen* o)	{
	int ret = OK;
	GET_VFS_DATA(o, struct cuse_proc, cproc);
	struct fs_struct* fs = cproc->fakefs;

	if(PTR_IS_ERR(fs))	return -USER_FAULT;
	if(strlen(fs->name) > 0) {
		ret = device_register(fs);
	} else {
		ret = -USER_FAULT;
	}

	return ret;
}
static int _cuse_mount(struct vfsopen* o, const char* name)	{
	char* kname;
	int ret = -USER_FAULT;
	GET_VFS_DATA(o, struct cuse_proc, cproc);

	if(PTR_IS_ERR(name) || !ADDR_USER(name))	return -USER_FAULT;

	struct fs_struct* fs = cproc->fakefs;
	if(PTR_IS_ERR(fs))	return -USER_FAULT;

	kname = strdup_user(name);

	if(strlen(kname) > 0)	{
		ret = vfs_register_mount(kname, fs);
	} else {
		ret = -USER_FAULT;
	}

	free_user(kname);
	return ret;
}

static int _cuse_unregister(struct vfsopen* o)	{
	int ret = OK;
	GET_VFS_DATA(o, struct cuse_proc, cproc);

	struct fs_struct* fs = cproc->fakefs;

	if(PTR_IS_ERR(fs))	return -USER_FAULT;

	ret = device_unregister(fs);
	return ret;
}
static int _cuse_detach(struct vfsopen* o)	{
	GET_VFS_DATA(o, struct cuse_proc, cproc);
	cproc->detached = true;
	return 0;
}

static int _cuse_set_func_empty(struct vfsopen* o, uint32_t func)	{
	int res = OK;
	GET_VFS_DATA(o, struct cuse_proc, cproc);

	// We change on the fakefs, so that we don't have to forward the calls
	struct fs_struct* fs = cproc->realfs;

	if(PTR_IS_ERR(fs))	return -USER_FAULT;

	if(FLAG_SET(func, VFS_FUNC_OPEN))	fs->open  = vfs_empty_open;
	if(FLAG_SET(func, VFS_FUNC_CLOSE)) 	fs->close = cuse_empty_close;
	if(FLAG_SET(func, VFS_FUNC_READ)) 	fs->read  = vfs_empty_read;
	if(FLAG_SET(func, VFS_FUNC_WRITE))	fs->write = vfs_empty_write;
	if(FLAG_SET(func, VFS_FUNC_GETC))	fs->getc  = vfs_empty_getc;
	if(FLAG_SET(func, VFS_FUNC_PUTC))	fs->putc  = vfs_empty_putc;
	if(FLAG_SET(func, VFS_FUNC_FCNTL))	fs->fcntl = vfs_empty_fcntl;
	if(FLAG_SET(func, VFS_FUNC_LSEEK))	fs->lseek = vfs_empty_lseek;
	if(FLAG_SET(func, VFS_FUNC_FSTAT))	fs->fstat = vfs_empty_fstat;

	return res;
}
int cuse_open(struct vfsopen* o, const char* name, int flags, int mode)	{
	int ret = OK;
	struct fs_struct* fs = _cuse_alloc_mitm();
	TZALLOC(cproc, struct cuse_proc);

	cproc->fakefs = fs;
	cproc->realfs = NULL;
	cproc->owner = current_proc();
	cproc->detached = false;
	SET_VFS_DATA(o, cproc);
	return ret;
}
int cuse_close(struct vfsopen* o)	{
	int ret = OK;
	GET_VFS_DATA(o, struct cuse_proc, cproc);
	if(PTR_IS_VALID(cproc))	{
		//struct fs_struct* fs = cproc->fakefs;

		if(!(cproc->detached))	{
			ret = _cuse_unregister(o);

			if(PTR_IS_VALID(cproc->fakefs))	{
				kfree(cproc->fakefs);
				cproc->fakefs = NULL;
			}
			if(PTR_IS_VALID(cproc->realfs))	{
				kfree(cproc->realfs);
				cproc->realfs = NULL;
			}
			
			struct cuse_memregion* mem = &cproc->region;
			if(mem->region.addr)	{
				bm_delete(mem->free);
				mem->region.addr = 0;
			}

			kfree(cproc);
			SET_VFS_DATA(o, NULL);
		}
	}
	return ret;
}

// int _cuse_delete_fd(int fd)	{
// }

int _cuse_svc_done(struct vfsopen* o, int svcid, int res)	{
	// Perform all pending jobs
	if(_cuse_perform_jobs(svcid, res) == 1)	{
		// Need to delete everything
		GET_VFS_DATA(o, struct cuse_proc, cproc);
		loge("Should delete everything: %p\n", cproc);
		if(PTR_IS_VALID(cproc->fakefs))	{
			kfree(cproc->fakefs);
			WRITE_ONCE(cproc->fakefs, NULL);
		}

	 	struct cuse_memregion* mem = &cproc->region;
	 	if(mem->region.addr)	{
	 		bm_delete(mem->free);
			mem->region.addr = 0;
	 	}
//	 	kfree(cproc);
//		SET_VFS_DATA(
	}

	// TODO:
	// - Need to copy vfsopen from user mode back to kernel

	// Wakeup the caller
	thread_exit(res);
//	thread_wakeup(o->tid, res);
	return OK;
}

int cuse_mmap(struct vfsopen* o, void* addr, size_t length)	{
	GET_VFS_DATA(o, struct cuse_proc, cproc);
	return _cuse_init_memregion(&cproc->region, (ptr_t)addr, (ptr_t)length);
}

int cuse_fcntl(struct vfsopen* o, ptr_t cmd, ptr_t arg)	{
	int ret = OK;
	switch(cmd)	{
	case CUSE_SET_FS_OPS:
		ret = _cuse_set_fs_ops(o, (struct fs_struct*)arg);
		break;
	case CUSE_REGISTER:
		ret = _cuse_register(o);
		break;
	case CUSE_UNREGISTER:
		ret = _cuse_unregister(o);
		break;
	case CUSE_DETACH:
		// If we remove the reference, then close will do nothing, but
		// free up the file descriptor. It will no longer be possible
		// to free the pointer, so this should only be used if the device
		// should exist until poweroff.
		/*
#if defined(CONFIG_KASAN)
		kasan_never_freed(o->data);
#endif
		o->data = NULL;
		*/
		ret = _cuse_detach(o);
		break;
	case CUSE_SET_FUNC_EMPTY:
		ret = _cuse_set_func_empty(o, arg);
		break;
	case CUSE_SVC_DONE:
		ret = _cuse_svc_done(o, (int)(arg >> 32), (arg & 0xffffffff));
		break;
	case CUSE_MOUNT:
		ret = _cuse_mount(o, (const char*)arg);
		break;
	default:
		ret = -USER_FAULT;
		break;
	}
	return ret;
}

static struct fs_struct cusefs = {
	.name = "cuse",
	.open = cuse_open,
	.close = cuse_close,
	.fcntl = cuse_fcntl,
	.mmap = cuse_mmap,
	.perm = ACL_PERM(ACL_READ|ACL_CTRL, ACL_READ|ACL_CTRL, ACL_NONE),
};

int init_cuse(void)	{
	mutex_clear(&cuse_data.lock);
	cuse_data.jobs = llist_alloc();
	cuse_data.openfds = llist_alloc();

	return device_register(&cusefs);
}
driver_init(init_cuse);

int cuse_exit(void)	{
	llist_delete(cuse_data.jobs);
	llist_delete(cuse_data.openfds);
	return OK;
}
poweroff_exit(cuse_exit);
