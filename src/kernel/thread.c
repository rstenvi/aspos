/**
* Thread manager.
*/
#include "kernel.h"
#include "arch.h"

void uthread_exit(void);
int thread_schedule_cb(void);

#define MAIN_EXE_NAME "main"

int init_threads()	{
	struct threads* t = cpu_get_threads();
	struct cpu* c = curr_cpu();
	long bmbytes = CONFIG_MAX_THREADS;
	ALIGN_UP_POW2(bmbytes, 8);
	bmbytes /= 8;
	t->freetids = bm_create(bmbytes);

	c->running = NULL;

	t->ready = xifo_alloc(5, 5);

	t->blocked = llist_alloc();
	ASSERT_FALSE(PTR_IS_ERR(t->blocked), "Unable to allocate list");

	t->waittid = llist_alloc();
	ASSERT_FALSE(PTR_IS_ERR(t->waittid), "Unable to allocate list");

//	t->userfuncavail = xifo_alloc(2, 2);
//	ASSERT_FALSE(PTR_IS_ERR(t->userfuncavail), "Unable to allocate xifo");

	t->proc.user_pgd = cpu_get_user_pgd();
	t->proc.ubrk.numpages = (MB*8) / PAGE_SIZE;
	t->proc.ubrk.mappedpages = 0;
	t->proc.ubrk.addr = (void*)(8 * GB);
	t->proc.fds = llist_alloc();
	ASSERT_FALSE(PTR_IS_ERR(t->proc.fds), "Unable to allocate opened fds")
	mutex_clear(&t->proc.ubrk.lock);

	t->sleeping = tlist_new();

	t->thread_exit = t->exc_exit = 0;

	t->busyloop = new_thread_kernel( (ptr_t)arch_busyloop, 0x00, false, false );
	ASSERT_TRUE(t->busyloop != NULL, "Cannot create thread");

	/* Register callback when CPU 0 indicates that other CPUs should wake up and
	 * potentially run some threads.
	 */
	gic_register_cb(SGI_IRQ_SCHEDULE, thread_schedule_cb);

	mutex_clear(&(t->lock));
	return 0;
}

struct thread* new_thread_kernel(ptr_t entry, ptr_t exit, bool user, bool addlist)	{
	struct threads* allt = cpu_get_threads();

	struct thread* t = (struct thread*)xalloc( sizeof(struct thread) );

	mutex_acquire(&allt->lock);
	int ntid = bm_get_first(allt->freetids);
	ASSERT_TRUE(ntid >= 0, "Unable to find free thread ID")

	t->ustack = 0;
	t->kstack = vmmap_alloc_pages(CONFIG_EXCEPTION_STACK_BLOCKS, PROT_RW, VMMAP_FLAG_NONE);
	t->kstack += (PAGE_SIZE * CONFIG_EXCEPTION_STACK_BLOCKS);
	t->pending = NULL;

	if(user)	{
		/* Kernel thread can run on multiple cores simultaneously, so they
		 * should not use the stack at all. Since use of a shared stack can
		 * cause subtle problems, we avoid it by simple not allocating a stack
		 * and setting stack pointer to 0.
		 */
		mmu_map_pages(
			THREAD_STACK_BOTTOM(ntid),
			CONFIG_THREAD_STACK_BLOCKS,
			PROT_RW
		);
		t->ustack = THREAD_STACK_TOP(ntid);
	}

	t->stackptr = arch_prepare_thread_stack((void*)(t->kstack), entry, t->ustack, user);

	if(user)	{
		/* Kernel thread should never exit */
		//arch_thread_set_exit((void*)t->stackptr, (ptr_t)_uthread_exit);
		arch_thread_set_exit((void*)t->stackptr, exit);
	}

	t->id = (tid_t)ntid;

	// Place at the back of the queue
	if(addlist)	{
		xifo_push_back(allt->ready, (void*)t);
	}

	mutex_release(&allt->lock);
	return t;
}

int thread_add_ready(struct thread* t, bool front)	{
	struct threads* allt = cpu_get_threads();

	mutex_acquire(&allt->lock);
	if(front)	{
		xifo_push_front(allt->ready, (void*)t);
	}
	else	{
		xifo_push_back(allt->ready, (void*)t);
	}
	mutex_release(&allt->lock);
}

int thread_new_main(struct loaded_exe* exe)	{
	struct threads* allt = cpu_get_threads();
	struct thread* t = new_thread_kernel(exe->entry, 0x00, true, true);
	if(t == NULL)	PANIC("Create thread\n");

	struct mem_region* last = &(exe->regions[exe->num_regions - 1]);

	// Get the next memory region where we can store parameter data
	ptr_t nextbase = last->start + last->size;
	ALIGN_UP_POW2(nextbase, PAGE_SIZE);

	// Add region to struct
	int nidx = exe->num_regions;
	exe->num_regions++;

	exe->regions = (struct mem_region*)realloc(exe->regions, sizeof(struct mem_region) * exe->num_regions);
	exe->regions[nidx].start = nextbase;
	exe->regions[nidx].size = PAGE_SIZE;
	exe->regions[nidx].prot = PROT_RW;

	// Store pointer to exe loaded
	allt->proc.exe = exe;

	mmu_map_page(nextbase, PROT_RW);
	memset((void*)nextbase, 0x00, PAGE_SIZE);

	char* argv, * sep;
	ptr_t* argvptrs = (ptr_t*)nextbase;
	int numargs = 0, i, len;
	void* data;

	// args is in "chosen" -> "bootargs"
	argv = cmdarg_value("userargs");
	if(argv != NULL)	{
		numargs = char_in_string(argv, ',') + 1;
	}

	// Data starts directly after array of pointers
	data = (void*)(nextbase + sizeof(ptr_t*) * (numargs + 1));

	strcpy(data, MAIN_EXE_NAME);
	argvptrs[0] = (ptr_t)data;
	data += strlen(MAIN_EXE_NAME) + 1;

	for(i = 0; i < numargs; i++)	{
		sep = strchr(argv, ',');
		if(sep == NULL)	len = strlen(argv);
		else			len = (sep - argv);

		memcpy(data, argv, len);
		argvptrs[i+1] = (ptr_t)data;
		data += len + 1;
		argv += len + 1;
	}

	// Set argc and argv
	// TODO: Also set envp
	arch_thread_set_arg((void*)(t->stackptr), numargs+1, 0);
	arch_thread_set_arg((void*)(t->stackptr), nextbase, 1);

	return OK;
}

int thread_new_syscall(ptr_t entry, int count, ptr_t* args)	{
	struct threads* allt = cpu_get_threads();
	struct thread* t = new_thread_kernel(entry, allt->thread_exit, true, true);
	int i, rcount;

	// Ensure validity on number of arguments passed
	rcount = MIN(count, arch_max_supported_args());
	if(count != rcount)	{
		logw("Attempted to pass more parameters than arch supports %i > %i\n", count, rcount);
	}

	for(i = 0; i < rcount; i++)	{
		arch_thread_set_arg((void*)(t->stackptr), args[i], i);
	}
	return t->id;
}


int thread_schedule_next(void)	{
	struct cpu* c = curr_cpu();
	struct threads* allt = cpu_get_threads();
	struct thread* t = NULL;

	t = (struct thread*)xifo_pop_front(allt->ready);
	if(t == NULL)	{
		if(c->running == NULL)	{
			logd("Switching busyloop on %i\n", c->cpuid);
			c->running = allt->busyloop;
			c->state = BUSYLOOP;
			goto schedule;
		}
		else if(c->running == allt->busyloop)	{
			logd("Continuing busyloop on %i\n", c->cpuid);
			c->state = BUSYLOOP;
			goto noschedule;
		}
		else	{
			// Continue executing c->running
			logd("No switch performed on %i\n", c->cpuid);
			goto noschedule;
		}
	}
	else	{
		logd("Performing task switch on %i\n", c->cpuid);
		// If one is already running, we push it at the back of the queue
		if(c->running != NULL && c->running != allt->busyloop)
			xifo_push_back(allt->ready, c->running);
		c->running = t;
		c->state = RUNNING;
		goto schedule;
	}

schedule:
	mutex_release(&allt->lock);
	arch_schedule((void*)(c->running->stackptr));

noschedule:
	mutex_release(&allt->lock);
	return -1;
}

int thread_tick_sleep(int ticks)	{
	logd("sleeping %i\n", ticks);
	struct threads* allt = cpu_get_threads();
	struct cpu* c = curr_cpu();
	struct thread* s = c->running;

	mutex_acquire(&allt->lock);
	tlist_add(allt->sleeping, s, ticks);

	// Set running to NULL to avoid returning on this
	c->running = NULL;

	mutex_release(&allt->lock);
	return thread_schedule_next();
}

int thread_ms_sleep(ptr_t ms)	{
	// Calculate as number of ticks and use that API
	int ticks = (ms / CONFIG_TIMER_MS_DELAY);
	if((ms % CONFIG_TIMER_MS_DELAY) != 0)	ticks++;
	return thread_tick_sleep(ticks);
}

int thread_sleep(ptr_t seconds)	{
	int ticks = ((double)CONFIG_TIMER_MS_DELAY / 1000) * seconds;

	// TODO: Might be sleeping slightly less than the seconds provided
	return thread_tick_sleep(ticks);
}


int thread_ready(void)	{
	struct threads* allt = cpu_get_threads();
	return xifo_count(allt->ready);
}

int thread_downtick(void)	{
	struct threads* allt = cpu_get_threads();
	mutex_acquire(&allt->lock);
	struct thread* s = (struct thread*)tlist_downtick(allt->sleeping);
	if(s != NULL)	{
		arch_thread_set_return((void*)(s->stackptr), 0);
		xifo_push_back(allt->ready, s);
	}

	/* Call schedule and leave c->running intact, so that we can return on the
	 * same thread.
	 */
	mutex_release(&allt->lock);
	return thread_schedule_next();
}

int thread_yield(void)	{
	/* We will try and schedule something else, but we might return on this same
	 * thread if there is nothing else to execute.
	 */
	return thread_schedule_next();
}

int thread_exit(ptr_t ret)	{
	struct threads* allt = cpu_get_threads();
	struct cpu* c = curr_cpu();
	struct thread* t = c->running;
	int tid = t->id;

	logd("Destroying thread %i\n", t->id);
	mutex_acquire(&allt->lock);
	c->running = NULL;

	bm_clear(allt->freetids, t->id);
	vmmap_unmap(t->kstack - PAGE_SIZE);
	mmu_unmap_pages(
		t->ustack - (PAGE_SIZE * CONFIG_THREAD_STACK_BLOCKS),
		CONFIG_THREAD_STACK_BLOCKS
	);

	// TODO: Close all open fds

	free(t);

	while( (t = (struct thread*)llist_remove(allt->waittid, tid)) != NULL)	{
		logd("Thread %i can wakeup\n", t->id);
		arch_thread_set_return((void*)(t->stackptr), ret);
		xifo_push_back(allt->ready, t);
	}

	mutex_release(&allt->lock);
	return thread_schedule_next();
}

static int block_current(void)	{
	struct thread* t;
	struct threads* allt = cpu_get_threads();
	struct cpu* c = curr_cpu();
	int res;

	mutex_acquire(&allt->lock);
	t = c->running;

	c->running = NULL;

	res = llist_insert(allt->blocked, t, t->id);
	if(res != OK)	{
		logw("list insert returned %i\n", res);
		PANIC("q");
	}
	mutex_release(&allt->lock);
	return thread_schedule_next();
}

static int _handle_retcode(int res)	{
	switch(-res) {
		case BLOCK_THREAD:
			block_current();
			break;
		case USER_FAULT:
			break;
		default:
			logw("unknown error code: %i\n", res);
			break;
	}
	return res;
}
/*
ptr_t kern_handle_return(ptr_t retval)	{
	struct thread* t = c->current;
	struct siginfo* si = NULL;

	si = xifo_pop_front(t->sigpending);
	if(PTR_IS_ERR(si))	return retval;

	t->retval = retval;

	handle_signal(t, si);
}*/

int thread_configure(ptr_t cmd, ptr_t arg)	{
	int ret = OK;
	struct threads* allt = cpu_get_threads();

	switch(cmd)	{
	case THREAD_CONF_THREAD_EXIT:
		mutex_acquire(&allt->lock);
		allt->thread_exit = arg;
		mutex_release(&allt->lock);
		break;
	case THREAD_CONF_EXC_EXIT:
		mutex_acquire(&allt->lock);
		allt->exc_exit = arg;
		mutex_release(&allt->lock);
		break;
	default:
		ret = -USER_FAULT;
		break;
	}
	return ret;
}

int thread_open(const char* name, int flags, int mode)	{
	int res = OK, nfd;
	char* kname, *fname, *uname;
	struct fs_struct* fs = NULL;
	struct vfsopen* o;
	struct threads* allt = cpu_get_threads();
	TZALLOC_ERR(fdo, struct thread_fd_open);

	kname = strdup_user(name);
	if(PTR_IS_ERR(kname))	{
		res = -MEMALLOC;
		goto err1;
	}

	fname = kname;
	fs = vfs_find_open(&kname);
	uname = name + (kname - fname);
	free_user(fname);
	if(PTR_IS_ERR(fs))	{
		res= -1;
		goto err1;
	}

	nfd = fileid_unique();
	o = vfs_alloc_open(current_tid(), nfd, fs);
	if(PTR_IS_ERR(o))	{
		res = -MEMALLOC;
		goto err2;
	}

	fdo->fs = fs;
	fdo->open = o;

	llist_insert(allt->proc.fds, fdo, nfd);

	res = vfs_open(fdo, (const char*)uname, flags, mode);
	if(res < 0)	{
		_handle_retcode(res);

		// TODO:
		// - If open is blocked, we will not return the correct fd
		// - We will also not remove fd-data from list or free fd-num
		goto err3;
	}

	return nfd;
err3:
	llist_remove(allt->proc.fds, nfd);
err2:
	vfs_free_open(fdo);
err1:
	free(fdo);
	return res;
}

int thread_fcntl(int fd, ptr_t cmd, ptr_t arg)	{
	int res = OK;
	struct vfsopen* o;
	struct threads* allt = cpu_get_threads();
	struct thread_fd_open* fdo;

	fdo = llist_find(allt->proc.fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;

	res = vfs_fcntl(fdo, cmd, arg);
	if(res < 0)	_handle_retcode(res);
	return res;
}
int thread_close(int fd)	{
	int res = OK;
	struct vfsopen* o;
	struct threads* allt = cpu_get_threads();
	struct thread_fd_open* fdo;

	fdo = llist_remove(allt->proc.fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;

	res = vfs_close(fdo);
	if(res < 0)	_handle_retcode(res);

	fileid_free(fd);
	vfs_free_open(fdo);

	// Might not return here
	// Thread might be blocked
	return res;
}
struct vfsopen* thread_find_fd(int fd)	{
	struct threads* allt = cpu_get_threads();
	return llist_find(allt->proc.fds, fd);
}
int _thread_vjob_perform(struct readwritev* rwv, vjob_perform perform)	{
	int i, ret, start = rwv->current;
	struct iovec* iov = rwv->iov, *curr;
	for(i = start; i < rwv->iovcnt; i++)	{
		curr = &(iov[i]);
		rwv->current = i;
		ret = perform(rwv->open, curr->iov_base, curr->iov_len);
		if(ret >= 0)	{
			rwv->retval += ret;
		}
		else {
			return ret;
		}
	}
	return OK;
}

int _thread_readwritev_cont(struct readwritev* rwv, size_t bytes)	{
	int ret;
	rwv->retval += bytes;
	vjob_perform job = (rwv->job == VFS_JOB_READ) ? vfs_read : vfs_write;
	ret = _thread_vjob_perform(rwv, job);
	return ret;
}

int _thread_readwritev(int fd, const struct iovec* _iov, int iovcnt, int job)	{
	int ret = OK;
	struct readwritev* rwv = NULL;
	struct iovec* iov = NULL;
	struct vfsopen* o;
	struct thread_fd_open* fdo;
	struct threads* allt = cpu_get_threads();
	struct cpu* c = curr_cpu();

	// Ensure fd is real
	fdo = llist_find(allt->proc.fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;

	// Copy whole array from user
	iov = copy_iovec_from_user(_iov, iovcnt);
	if(PTR_IS_ERR(iov))	return PTR_TO_ERRNO(iov);

	// Ensure all addresses in array are valid
	if(!iovec_validate_addrs(iov, iovcnt))	{
		ret = -USER_FAULT;
		goto err1;
	}

	// Create a kernel object we can halt with
	rwv = create_kernel_iov(iov, iovcnt, job);
	if(PTR_IS_ERR(rwv))	{
		ret = PTR_TO_ERRNO(rwv);
		goto err1;
	}
	rwv->open = fdo->open;

	ret = _thread_readwritev_cont(rwv, 0);
	if(ret == -BLOCK_THREAD)	{
		c->running->pending = rwv;
		block_current();
	} else {
		free(iov);
		free(rwv);
	}
	return ret;
err1:
	free(iov);
	return ret;
}
int thread_fstat(int fd, struct stat* statbuf)	{
	int res = OK;
	struct thread_fd_open* fdo;
	struct threads* allt = cpu_get_threads();

	fdo = llist_find(allt->proc.fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;

	res = vfs_fstat(fdo, statbuf);
	if(res < 0)	_handle_retcode(res);
	return res;
}
int thread_writev(int fd, const struct iovec *_iov, int iovcnt)	{
	int ret = OK;
	ret = _thread_readwritev(fd, _iov, iovcnt, VFS_JOB_WRITE);
	return ret;
}
int thread_readv(int fd, const struct iovec* _iov, int iovcnt)	{
	int ret = OK;
	ret = _thread_readwritev(fd, _iov, iovcnt, VFS_JOB_READ);
	return ret;
}
int thread_write(int fd, const void* buf, size_t count)	{
	int res = OK;
	struct vfsopen* o;
	struct thread_fd_open* fdo;
	struct threads* allt = cpu_get_threads();

	fdo = llist_find(allt->proc.fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;

	res = vfs_write(fdo, buf, count);

	if(res < 0)	_handle_retcode(res);

	return res;
}
/*
static int _thread_mmap_fd(int fd, void* addr, size_t len)	{
	struct threads* allt = cpu_get_threads();
	struct vfsopen* o;
	o = llist_find(allt->proc.fds, fd);
	if(PTR_IS_ERR(o))		return -USER_FAULT;
	return vfs_mmap(o, addr, len);
}
static int _thread_mmap_mem(void* addr, size_t len)	{
	PANIC("not implemented yet\n");
}
int thread_mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)	{
	// TODO: Should allow NULL-ptr in the future
	if(addr == NULL || !ADDR_USER(addr))	return -USER_FAULT;
	if(fd >= 0)	{
		return _thread_mmap_fd(fd, addr, len);
	}
	else	{
		return _thread_mmap_mem(addr, len);
	}
}
*/
int thread_read(int fd, void* buf, size_t count)	{
	int i, res = OK;
	struct vfsopen* o;
	struct thread_fd_open* fdo;
	struct threads* allt = cpu_get_threads();
	char* b = (char*)buf;

	fdo = llist_find(allt->proc.fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;

	res = vfs_read(fdo, buf, count);

	if(res < 0)	_handle_retcode(res);
	return res;
}

int thread_lseek(int fd, off_t offset, int whence)	{
	int res = OK;
	struct vfsopen* o;
	struct thread_fd_open* fdo;
	struct threads* allt = cpu_get_threads();

	fdo = llist_find(allt->proc.fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;

	res = vfs_lseek(fdo, offset, whence);

	if(res < 0)	_handle_retcode(res);

	return res;
}

int _thread_dup(struct thread_fd_open* _fdo)	{
	struct threads* allt = cpu_get_threads();
	TZALLOC_ERR(fdo, struct thread_fd_open);
	TZALLOC_ERR(o, struct vfsopen);
	o->tid = current_tid();
	o->fd = fileid_unique();
	o->data = o->data;
	o->offset = o->offset;
	fdo->open = o;
	fdo->fs = _fdo->fs;

	llist_insert(allt->proc.fds, fdo, o->fd);
	return o->fd;
}

int thread_dup(int fd)	{
	int res = OK;
	struct vfsopen* o;
	struct thread_fd_open* fdo;
	struct threads* allt = cpu_get_threads();

	fdo = llist_find(allt->proc.fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;

	res = _thread_dup(fdo);
	if(res < 0)	_handle_retcode(res);
	return res;
}

int thread_getchar(int fd)	{
	int res = OK;
	struct vfsopen* o;
	struct thread_fd_open* fdo;
	struct threads* allt = cpu_get_threads();

	fdo = llist_find(allt->proc.fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;

	res = vfs_getchar(fdo);

	if(res < 0)	_handle_retcode(res);
	return res;
}

int thread_putchar(int fd, int c)	{
	int res = OK;
	struct vfsopen* o;
	struct thread_fd_open* fdo;
	struct threads* allt = cpu_get_threads();

	fdo = llist_find(allt->proc.fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;

	res = vfs_putchar(fdo, c);
	if(res < 0)	_handle_retcode(res);
	return res;
}

int thread_get_tid(void)	{
	return curr_cpu()->running->id;
}

int thread_wait_tid(int tid)	{
	struct threads* allt = cpu_get_threads();
	struct cpu* c = curr_cpu();
	struct thread* t;
	int res = OK;
	mutex_acquire(&allt->lock);

	// If tid has not been allocated, there is nothing to wait for
	if(bm_index_free(allt->freetids, tid))	{
		goto done;
	}

	// We must schedule something new
	t = c->running;
	c->running = NULL;

	/*
	* Insert in list and sort by tid we are waiting on. Because of the way this
	* list is organized, a thread cannot wait on multiple other threads, but
	* multiple threads can wait on the same thread. This makes sense as the
	* problem of waiting on multiple threads can easily be solved in use more.
	*/
	res = llist_insert(allt->waittid, t, tid);

	// Release the lock and schedule something else
	mutex_release(&allt->lock);
	return thread_schedule_next();

done:
	mutex_release(&allt->lock);
	return res;
}

int thread_wakeup(int tid, ptr_t res)	{
	struct threads* allt = cpu_get_threads();
	struct thread* t;
	struct cpu* c = curr_cpu();
	int ret = OK;

	mutex_acquire(&allt->lock);

	t = llist_remove(allt->blocked, tid);
	if(PTR_IS_ERR(t))	{
		BUG("Tried to wakeup thread which is not blocked\n");
		ret = -GENERAL_FAULT;
		goto done;
	}
	if(c->running->pending)	{
		ret = _thread_readwritev_cont(c->running->pending, res);
		if(ret != -BLOCK_THREAD)	{
			// Still more to R/W, just exit
			goto done;
		} else {
			// R/W is done, we must store return value, free everything and wakeup thread
			struct readwritev* rem = c->running->pending;
			res = rem->retval;
			free(rem->iov);
			free(rem);
			c->running->pending = NULL;
		}
	}

	arch_thread_set_return((void*)(t->stackptr), res);
	xifo_push_back(allt->ready, t);

done:
	mutex_release(&allt->lock);
	return ret;
}

/**
* Callback from GIC when SGI to schedule has been received
*/
int thread_schedule_cb(void)	{
	return thread_schedule_next();
}

