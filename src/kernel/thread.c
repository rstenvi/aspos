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

	t->proc.user_pgd = cpu_get_user_pgd();
	t->proc.ubrk.numpages = (MB*8) / PAGE_SIZE;
	t->proc.ubrk.mappedpages = 0;
	t->proc.ubrk.addr = (void*)(8 * GB);
	mutex_clear(&t->proc.ubrk.lock);

	t->sleeping = tlist_new();

	t->busyloop = new_thread_kernel( (ptr_t)arch_busyloop, false, false );
	ASSERT_TRUE(t->busyloop != NULL, "Cannot create thread");

	/* Register callback when CPU 0 indicates that other CPUs should wake up and
	 * potentially run some threads.
	 */
	gic_register_cb(SGI_IRQ_SCHEDULE, thread_schedule_cb);

	mutex_clear(&(t->lock));
	return 0;
}

struct thread* new_thread_kernel(ptr_t entry, bool user, bool addlist)	{
	struct threads* allt = cpu_get_threads();

	struct thread* t = (struct thread*)xalloc( sizeof(struct thread) );

	mutex_acquire(&allt->lock);
	int ntid = bm_get_first(allt->freetids);
	ASSERT_TRUE(ntid >= 0, "Unable to find free thread ID")
	

	t->ustack = 0;
	t->kstack = vmmap_alloc_pages(CONFIG_EXCEPTION_STACK_BLOCKS, PROT_RW, VMMAP_FLAG_NONE);
	t->kstack += (PAGE_SIZE * CONFIG_EXCEPTION_STACK_BLOCKS);


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
		arch_thread_set_exit((void*)t->stackptr, (ptr_t)_uthread_exit);
	
	}

	t->id = (tid_t)ntid;

	// Place at the back of the queue
	if(addlist)	{
		xifo_push_back(allt->ready, (void*)t);
	}

//	arch_schedule((void*)(t->stackptr));
	mutex_release(&allt->lock);
	return t;
}

int thread_new_main(ptr_t entry)	{
	struct thread* t = new_thread_kernel(entry, true, true);
	if(t == NULL)	PANIC("Create thread\n");

// TODO: Define a proper place where this should be stored
#define USER_ADDR_USE 0x80000000
	mmu_map_page(USER_ADDR_USE, PROT_RW);
	memset((void*)USER_ADDR_USE, 0x00, PAGE_SIZE);

	char* argv, * sep;
	ptr_t* argvptrs = (ptr_t*)USER_ADDR_USE;
	int numargs = 0, i, len;
	void* data;
	
	
	// args is in "chosen" -> "bootargs"
	argv = cmdarg_value("userargs");
	if(argv != NULL)	{
		numargs = char_in_string(argv, ',') + 1;
	}

	// Data starts directly after array of pointers
	data = (void*)(USER_ADDR_USE + sizeof(ptr_t*) * (numargs + 1));

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
	arch_thread_set_arg((void*)(t->stackptr), USER_ADDR_USE, 1);

	return OK;
}

int thread_new_syscall(ptr_t entry, int count, ptr_t* args)	{
	struct thread* t = new_thread_kernel(entry, true, true);
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

	logi("Destroying thread %i\n", t->id);
	mutex_acquire(&allt->lock);
	c->running = NULL;

	bm_clear(allt->freetids, t->id);
	vmmap_unmap(t->kstack - PAGE_SIZE);
	mmu_unmap_pages(
		t->ustack - (PAGE_SIZE * CONFIG_THREAD_STACK_BLOCKS),
		CONFIG_THREAD_STACK_BLOCKS
	);

	free(t);
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
		logw("lsit insert returned %i\n", res);
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

int thread_open(const char* name, int flags, int mode)	{
	int res = OK;
	res = vfs_open(name, flags, mode);
	if(res < 0)	_handle_retcode(res);

	// Might not return here
	// Thread might be blocked
	return res;
}

int thread_close(int fd)	{
	int res = OK;
	res = vfs_close(fd);
	if(res < 0)	_handle_retcode(res);

	// Might not return here
	// Thread might be blocked
	return res;
}
int thread_write(int fd, void* buf, size_t count)	{
	int res;
	res = vfs_write(fd, buf, count);

	if(res < 0)	_handle_retcode(res);

	return res;
}

int thread_read(int fd, void* buf, size_t count)	{
	int i, res = OK;
	char* b = (char*)buf;

	res = vfs_read(fd, buf, count);

	if(res < 0)	{
		switch(-res) {
			case BLOCK_THREAD:
				block_current();
				break;
			default:
				logw("unknown error code\n");
				PANIC("p");
				break;
		}
	}
	return res;
}

int thread_lseek(int fd, off_t offset, int whence)	{
	int res = 0;

	res = vfs_lseek(fd, offset, whence);

	if(res < 0)	_handle_retcode(res);

	return res;
}

int thread_dup(int fd)	{
	int res = OK;
	res = vfs_dup(fd);
	if(res < 0)	_handle_retcode(res);
	return res;
}

int thread_getchar(int fd)	{
	int res = OK;
	res = vfs_getchar(fd);
	if(res < 0)	_handle_retcode(res);
	return res;

}


int thread_putchar(int fd, int c)	{
	int res = OK;
	res = vfs_putchar(fd, c);
	if(res < 0)	_handle_retcode(res);
	return res;
}


int thread_wakeup(int tid, ptr_t res)	{
	struct threads* allt = cpu_get_threads();
	struct thread* t = llist_remove(allt->blocked, tid);
	struct cpu* c = curr_cpu();
	if(PTR_IS_ERR(t))	return -GENERAL_FAULT;

	// TODO: This should be return, is the same on arm64, but we shouldn't assume that
	arch_thread_set_arg((void*)(t->stackptr), res, 0);

	mutex_acquire(&allt->lock);

	xifo_push_back(allt->ready, t);
	mutex_release(&allt->lock);

	return OK;
}

/**
* Callback from GIC when SGI to schedule has been received
*/
int thread_schedule_cb(void)	{
	return thread_schedule_next();
}

