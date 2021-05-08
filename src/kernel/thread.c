/**
* Thread manager.
*/
#include "kernel.h"
#include "arch.h"
#include "slab.h"
#include "acl.h"
#include "syscalls.h"

static int _munmap_all(struct process* p);
int _thread_free_memregion(struct process* p, ptr_t addr, int pages);
int thread_free_slabs(struct process* p, ptr_t addr, int bytes);
void uthread_exit(void);
int thread_schedule_cb(int);

#define CUSOM_JOBS_START (1 << 16)
#define JOB_UNMAP_MMU    (CUSOM_JOBS_START + 1)

#define MAIN_EXE_NAME "main"
#define CONFIG_MAX_FILENO_PROC (128*8)
/*
static void switch_upgd(ptr_t pgd)	{
	if(osdata.upgd != pgd)	{
		osdata.upgd = pgd;
		write_sysreg_ttbr0(mmu_va_to_pa(pgd));
	}
}
*/

static int _thread_poweroff(struct threads* allt)	{
	// Free all the resources before we power down
	// This is mostly done to more easily detect memory leaks
	kfree(allt->busyloop);
	bm_delete(allt->freetids);
	tlist_delete(allt->sleeping);
	llist_delete(allt->blocked);
	llist_delete(allt->waittid);
	llist_delete(allt->texitjobs);
	llist_delete(allt->lowhalfjobs);
	xifo_delete(allt->ready);
#if defined(CONFIG_MULTI_PROCESS)
	llist_delete(allt->procs);
	bm_delete(allt->procids);
#endif
	kern_poweroff(false);
}

ptr_t thread_get_upgd(struct thread* t)	{
//	ptr_t lin = osdata.upgd;
	ptr_t lin;
	if(!PTR_IS_ERR(t) && !PTR_IS_ERR(t->owner))	{
		lin = t->owner->user_pgd;
	}	
	ASSERT(lin)
	return mmu_va_to_pa(lin);
}
static int _thread_free_vfsopen(struct thread_fd_open* fdo)	{
	struct process* p = cuse_get_process(fdo->fs);
	struct vfsopen* o = fdo->open;
	if(ADDR_USER(o))	{
		if(p)	{
			thread_free_slabs(p, (ptr_t)o, sizeof(struct vfsopen));
		}
		else	{
			logw("Tried to free vfsopen user-ptr w/o valid process\n");
		}
	}
	else	{
		kfree(o);
	}
}
int __handle_driver_ret_open(struct threads* allt, struct process* p, struct thread_fd_open* fdo, int ret)	{
	if(ret > 0)	{
		/*
		* Sanity check on the returned file descriptor
		* - Must not exist in fds-list
		* - Must use an fd-id which has been reserved
		*/
		void* r = llist_find(p->fds, ret);
		if(r == NULL && bm_index_taken(p->fileids, ret))	{
			logi("TODO: We trust user-mode driver to return correct fd\n");
			llist_insert(p->fds, fdo, ret);
			return ret;
		}
		else	{
			logw("Driver returned unexpected value: %i\n", ret);
			ret = -GENERAL_FAULT;
		}
	}
error:
	logi("TODO: Can't free fd because we don't store id\n");
	//bm_clear(p->fileids, ret);
	_thread_free_vfsopen(fdo);
	kfree(fdo);
	return ret;
}
int __handle_driver_ret_unmap(struct threads* allt, struct process* caller, struct process* p, struct driver_job_unmap* job, int ret) {
	int i;
	ptr_t oa1, oa2, addr = job->drv_addr, _addr = job->call_addr, entry;
	logi("TODO: unmap: %lx (%i)\n", job->drv_addr, job->pages);

	_thread_free_memregion(p, addr, job->pages);

	for(i = 0; i < job->pages; i++)	{
		oa1 = mmu_va_to_pa_pgd((ptr_t*)p->user_pgd, addr + ((ptr_t)i * PAGE_SIZE), &entry);
		oa2 = mmu_va_to_pa_pgd((ptr_t*)caller->user_pgd, _addr + ((ptr_t)i * PAGE_SIZE), NULL);

		// We ensure that page uncloned when we map the page, so this should
		// never differ.
		if(oa1 != oa2)	{
			PANIC("oa1 != oa2");
//			mmu_map_page_pgd_oa_entry((ptr_t*)caller->user_pgd, _addr + ((ptr_t)i * PAGE_SIZE), oa1, entry);
//			pmm_free(oa2);
		}
		else	{
			pmm_free(oa1);
		}
	}
	kfree(job);
	return ret;
}

int _handle_driver_ret(struct threads* allt, struct thread* curr, struct driver_job* d, bool texit, int ret)	{
	int res = OK;
//	struct process* p = t->owner;
//	if(texit)	p = d->driver;
	switch(d->sysno)	{
	case SYS_OPEN:
		res = __handle_driver_ret_open(allt, d->caller->owner, (struct thread_fd_open*)d->data, ret);
		break;
	case JOB_UNMAP_MMU:
		res = __handle_driver_ret_unmap(allt, d->caller->owner, curr->owner, (struct driver_job_unmap*)d->data, ret);
		break;
	default:
		logw("Unsupported sysno for driver wakeup: %x\n", d->sysno);
		res = -GENERAL_FAULT;
		break;
	}
	kfree(d);
	return res;
}
static inline struct driver_job* allocate_driver_job(int sysno, struct thread* t, struct process* p, void* data)	{
	TZALLOC(ret, struct driver_job);
	if(PTR_IS_ERR(ret))	return ret;
	ret->sysno = sysno;
	ret->caller = t;
	ret->driver = p;
	ret->data = data;
	return ret;
}
static int _add_udriver_job(struct threads* allt, int sysno, void* data, struct thread* drv)	{
	struct thread* curr = current_thread();
//	struct process* p = NULL;
//	if(fs->user)	p = cuse_get_process(fs);

	struct driver_job* j = allocate_driver_job(sysno, curr, drv->owner, data);
	if(PTR_IS_ERR(j))	{
		return -MEMALLOC;
	}
	llist_insert(allt->texitjobs, j, drv->id);
	return OK;
}

static int _add_driver_job(struct threads* allt, int sysno, void* data)	{
	struct thread* curr = current_thread();
//	struct process* p = NULL;
//	if(fs->user)	p = cuse_get_process(fs);

	struct driver_job* j = allocate_driver_job(sysno, curr, NULL, data);
	if(PTR_IS_ERR(j))	{
		return -MEMALLOC;
	}
	llist_insert(allt->lowhalfjobs, j, curr->id);
	//llist_insert(allt->driverjobs, j, t->id);
	return OK;
}

static inline struct kern_user_struct* alloc_root_struct(void)	{
	TZALLOC(ret, struct kern_user_struct);
	if(PTR_IS_ERR(ret))	return ret;
	return ret;
}
static inline struct kern_user_struct* fork_user_struct(struct kern_user_struct* s)	{
	mutex_acquire(&s->lock);
	s->refcount += 1;
	mutex_release(&s->lock);
	return s;
}
static inline struct kern_user_struct* deref_user_struct(struct kern_user_struct* s)	{
	int res;
	mutex_acquire(&s->lock);
	s->refcount -= 1;
	res = s->refcount;
	if(res <= 0)	{
		kfree(s);
		return NULL;
	}
	mutex_release(&s->lock);
	return s;
}

// TODO: Use memory constants defined in arch
static int process_init(struct process* proc)	{
	//proc->user_pgd = cpu_get_user_pgd();
	proc->user_pgd = vmmap_alloc_page(PROT_RW, VMMAP_FLAG_ZERO);
//	switch_upgd(proc->user_pgd);
//	osdata.upgd = proc->user_pgd;
//	write_sysreg_ttbr0(osdata.upgd);

	proc->ubrk.numpages = (MB*8) / PAGE_SIZE;
	proc->ubrk.mappedpages = 0;
	proc->ubrk.addr = (void*)(8 * GB);

	proc->fds = llist_alloc();
	ASSERT_FALSE(PTR_IS_ERR(proc->fds), "Unable to allocate opened fds")

	proc->fileids = bm_create(CONFIG_MAX_FILENO_PROC/8);
	ASSERT_FALSE(PTR_IS_ERR(proc->fileids), "Unable to allocate bitmap");

	proc->memregions = llist_alloc();
	ASSERT_FALSE(PTR_IS_ERR(proc->memregions), "Unable to allocate memregion list");

	proc->userslab = NULL;

	proc->keepalive = false;

	proc->mmapped = llist_alloc();
	ASSERT_FALSE(PTR_IS_ERR(proc->mmapped), "Unable to allocate mmapped list");

	mutex_clear(&proc->lock);
	mutex_clear(&proc->ubrk.lock);
	return OK;
}

int _thread_memregion_find_start(struct process* p)	{
	int start = 512, i;

	// The first should always hold the last addr
	struct virtmem* virtm = llist_first(p->memregions, false, NULL);
	if(virtm)	{
		start = (virtm->start + (virtm->pages * PAGE_SIZE)) / PAGE_SIZE;
	}
	return start;
}

int _thread_free_memregion(struct process* p, ptr_t addr, int pages)	{
	struct virtmem* virtm = NULL;
	int i = 0, idx;
	ptr_t end;
	while((virtm = llist_index(p->memregions, i)) != NULL)	{
		end = virtm->start + (PAGE_SIZE * virtm->pages);
		if(addr >= virtm->start && addr < end)	{
			idx = (addr - virtm->start) / PAGE_SIZE;
			bm_clear_nums(virtm->free, idx, pages);
			break;
		}
		i++;
	}
	return OK;
}

int thread_dealloc_memregionss(struct process* p)	{
	struct virtmem* virtm = NULL;

	mutex_acquire(&p->lock);
	while((virtm = llist_first(p->memregions, true, NULL)) != NULL)	{
		mmu_unmap_pages_pgd((ptr_t*)p->user_pgd, virtm->start, virtm->pages);
		bm_delete(virtm->free);
	}
	mutex_release(&p->lock);
	llist_delete(p->memregions);
	return OK;
}

struct virtmem* _thread_alloc_memregion(struct process* p, int pages)	{
	ALIGN_UP_POW2(pages, 8);
	TZALLOC(virtm, struct virtmem);
	int start = _thread_memregion_find_start(p);

	mutex_acquire(&p->lock);
	ptr_t addr = mmu_find_free_pages((ptr_t*)p->user_pgd, start, pages);
	mutex_release(&p->lock);
	ASSERT(addr);

	virtm->start = addr;
	virtm->pages = pages;
	virtm->free = bm_create(pages / 8);
	return virtm;
}

ptr_t _thread_find_user_memregion(struct process* p, int pages)	{
	struct virtmem* virtm = NULL;
	int i = 0;
	signed long res;
	while((virtm = llist_index(p->memregions, i)) != NULL)	{
		res = bm_get_first_num(virtm->free, pages);
		if(res >= 0)	{
			return (virtm->start + ((ptr_t)res * PAGE_SIZE));
		}
		i++;
	}

	// If we can't find any, we should allocate a new region and try again
	logi("Unable to find memregion for %i pages\n", pages);
	int apages = pages;
	ALIGN_UP_POW2(apages, 512);
	struct virtmem* vm = _thread_alloc_memregion(p, apages);
	llist_insert(p->memregions, vm, vm->start);
	return _thread_find_user_memregion(p, pages);
}

int _thread_destroy_userslab(struct process* p)	{
	struct userslab* slab = p->userslab;
	if(PTR_IS_ERR(slab))	return OK;

	bm_delete(slab->free);
	kfree(slab);
	return OK;
}
struct userslab* _thread_alloc_userslab(struct process* p, int pages, int slabsz)	{
	TZALLOC(slab, struct userslab);
	ptr_t addr;

	addr = _thread_find_user_memregion(p, pages);
	slab->start = addr;
	slab->slabsz = slabsz;
	slab->slabs = (PAGE_SIZE * pages) / slabsz;
	slab->free = bm_create(slab->slabs / 8);
	return slab;
}

ptr_t _thread_alloc_slabs(struct process* p, int bytes)	{
	int numslabs, res;
	struct userslab* slab = p->userslab;
	if(slab == NULL)	{
		slab = _thread_alloc_userslab(p, PROC_SLAB_NUM_PAGES, PROC_SLAB_SIZE);
		p->userslab = slab;
	}

	ALIGN_UP_POW2(bytes, PROC_SLAB_SIZE);
	numslabs = bytes / PROC_SLAB_SIZE;
	res = bm_get_first_num(slab->free, numslabs);
	ASSERT(res >= 0);


	// Need to ensure that page(s) are mapped in
	ptr_t vaddr = slab->start + ((ptr_t)res * slab->slabsz);
	ptr_t start = vaddr, end = vaddr + bytes;
	ALIGN_DOWN_POW2(start, PAGE_SIZE);
	ALIGN_UP_POW2(end, PAGE_SIZE);

	mutex_acquire(&p->lock);
	for(; start < end; start += PAGE_SIZE)	{
		if(mmu_va_to_pa_pgd((ptr_t*)p->user_pgd, start, NULL) == 0)	{
			mmu_map_pages_pgd((ptr_t*)p->user_pgd, start, 1, PROT_RW);
		}
	}
	mutex_release(&p->lock);
	return vaddr;
}

int thread_free_slabs(struct process* p, ptr_t addr, int bytes)	{
	ALIGN_UP_POW2(bytes, PROC_SLAB_SIZE);
	struct userslab* slab = p->userslab;
	ASSERT(slab);
	ptr_t off = (addr - slab->start);
	int slabstart = (off / slab->slabsz), numslabs = (bytes / slab->slabsz), i;
	for(i = 0; i < numslabs; i++)	{
		bm_clear(slab->free, (i+slabstart));
	}
}

int init_threads()	{
	struct threads* t = cpu_get_threads();
	struct cpu* c = curr_cpu();
	long bmbytes = CONFIG_MAX_THREADS;
	struct process* p;
	ALIGN_UP_POW2(bmbytes, 8);
	bmbytes /= 8;
	t->freetids = bm_create(bmbytes);

	c->running = NULL;

	t->ready = xifo_alloc(5, 5);

	t->blocked = llist_alloc();
	ASSERT_FALSE(PTR_IS_ERR(t->blocked), "Unable to allocate list");

	t->waittid = llist_alloc();
	ASSERT_FALSE(PTR_IS_ERR(t->waittid), "Unable to allocate list");

	t->texitjobs = llist_alloc();
	ASSERT_FALSE(PTR_IS_ERR(t->texitjobs), "Unable to allocate list");

	t->lowhalfjobs = llist_alloc();
	ASSERT_FALSE(PTR_IS_ERR(t->lowhalfjobs), "Unable to allocate list");
//	t->driverjobs = llist_alloc();
//	ASSERT_FALSE(PTR_IS_ERR(t->driverjobs), "Unable to allocate list");

//	t->userfuncavail = xifo_alloc(2, 2);
//	ASSERT_FALSE(PTR_IS_ERR(t->userfuncavail), "Unable to allocate xifo");

#if defined(CONFIG_MULTI_PROCESS)
	// First allocate bitmap indicating which pids are free
	t->procids = bm_create(128);
	ASSERT_FALSE(PTR_IS_ERR(t->procids), "Unable to allocate bitmap");

	// Allocate container to hold all processes
	t->procs = llist_alloc();
	ASSERT_FALSE(PTR_IS_ERR(t->procs), "Unable to allocate list");

	// Also allocate first process
	p = (struct process*)kmalloc( sizeof(struct process) );
	ASSERT_FALSE(PTR_IS_ERR(p), "Unable to allocate process");

	// Allocate pid and insert in list
	// We throw away the first pid so we start at 1
	pid_unique();
	p->pid = pid_unique();
	p->num_threads = 0;
	llist_insert(t->procs, p, p->pid);
#else
	p = &t->proc;
#endif

	p->user = alloc_root_struct();
	p->user->refcount = 1;

	process_init(p);

	// Copy over initial PGD into process PGD
	//memcpy((void*)p->user_pgd, (void*)osdata.upgd, PAGE_SIZE);
	//osdata.upgd = p->user_pgd;

	t->sleeping = tlist_new();

	t->thread_exit = t->exc_exit = 0;

	t->busyloop = new_thread_kernel(NULL, (ptr_t)arch_busyloop, 0x00, false, false );
	ASSERT_TRUE(t->busyloop != NULL, "Cannot create thread");

	/* Register callback when CPU 0 indicates that other CPUs should wake up and
	 * potentially run some threads.
	 */
	gic_register_cb(SGI_IRQ_SCHEDULE, thread_schedule_cb);

	mutex_clear(&(t->lock));
	return 0;
}

struct thread* new_thread_kernel(struct process* p, ptr_t entry, ptr_t exit, bool user, bool addlist)	{
	TZALLOC(t, struct thread);
	if(PTR_IS_ERR(t))	return t;

	struct threads* allt = cpu_get_threads();

//	struct thread* t = (struct thread*)xalloc( sizeof(struct thread) );

	int ntid = bm_get_first(allt->freetids);
	ASSERT_TRUE(ntid >= 0, "Unable to find free thread ID")

	t->ustack = 0;
	t->kstack = vmmap_alloc_pages(CONFIG_EXCEPTION_STACK_BLOCKS, PROT_RW, VMMAP_FLAG_NONE);
	t->kstack += (PAGE_SIZE * CONFIG_EXCEPTION_STACK_BLOCKS);
	t->pending = NULL;

	memset(&t->tinfo, 0x00, sizeof(struct user_thread_info));
	t->tinfo.id = ntid;

	if(user)	{
		/* Kernel thread can run on multiple cores simultaneously, so they
		 * should not use the stack at all. Since use of a shared stack can
		 * cause subtle problems, we avoid it by simple not allocating a stack
		 * and setting stack pointer to 0.
		 */

		t->ustack = mmu_create_user_stack((ptr_t*)p->user_pgd, CONFIG_THREAD_STACK_BLOCKS);
		t->ustack += (PAGE_SIZE * CONFIG_THREAD_STACK_BLOCKS);
		/*
		mmu_map_pages(
			THREAD_STACK_BOTTOM(ntid),
			CONFIG_THREAD_STACK_BLOCKS,
			PROT_RW
		);
		t->ustack = THREAD_STACK_TOP(ntid);
		*/
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
	logd("Created new kernel, tid: %i\n", t->id);
	return t;
}
/*
static void _copy_stack(ptr_t* pgd, ptr_t to, ptr_t from, size_t sz)	{
	mmu_memcpy(pgd, (void*)(to - sz), (void*)(from - sz), sz);
}
*/
static void _copy_kstack(ptr_t to, ptr_t from, size_t sz)	{
	memcpy((void*)(to - sz), (void*)(from - sz), sz);
}

struct thread* thread_copy_thread(struct process* p, struct thread* _t)	{
	struct threads* allt = cpu_get_threads();
	mutex_acquire(&allt->lock);
	struct thread* t = new_thread_kernel(p, 0, allt->thread_exit, false, false);
	if(!PTR_IS_VALID(t))	goto err;

//	_copy_stack((ptr_t*)p->user_pgd, t->ustack, _t->ustack, CONFIG_THREAD_STACK_BLOCKS * PAGE_SIZE);

	_copy_kstack(t->kstack, _t->kstack, CONFIG_EXCEPTION_STACK_BLOCKS * PAGE_SIZE);
	t->kstack = _t->kstack;
/*
	ptr_t stackoffset = _t->kstack - _t->stackptr;
	t->stackptr = t->kstack - stackoffset;

	arch_update_after_copy((ptr_t*)p->user_pgd, t->kstack, t->ustack, _t->kstack, _t->ustack, t->stackptr, _t->stackptr);
*/
//	arch_thread_set_exit((void*)t->stackptr, allt->thread_exit);
err:
	mutex_release(&allt->lock);
	return t;
}

int thread_add_ready(struct thread* t, bool front, bool lockheld)	{
	struct threads* allt = cpu_get_threads();

	if(!lockheld)	mutex_acquire(&allt->lock);
	if(front)	{
		xifo_push_front(allt->ready, (void*)t);
	}
	else	{
		xifo_push_back(allt->ready, (void*)t);
	}
	if(!lockheld)	mutex_release(&allt->lock);
}

int thread_new_main(void)	{
	struct threads* allt = cpu_get_threads();
	struct thread* t;
	struct process* p;

#if defined(CONFIG_MULTI_PROCESS)
	// Get process, but don't remove it from list
	p = (struct process*)llist_first(allt->procs, false, NULL);
	ASSERT_FALSE(PTR_IS_ERR(p), "Cannot find process");

#else
	p = &(allt->proc);
#endif

	// TODO: Fix address, load from DTB
	struct loaded_exe* exe = elf_load((ptr_t*)p->user_pgd, (void*)(osdata.linear_offset + 0x44000000));
	logi("entry @ 0x%lx\n", exe->entry);

	exe->references = 1;
	struct mem_region* last = &(exe->regions[exe->num_regions - 1]);

	// Get the next memory region where we can store parameter data
	ptr_t nextbase = last->start + last->size;
	ALIGN_UP_POW2(nextbase, PAGE_SIZE);

	// Add region to struct
	int nidx = exe->num_regions;
	exe->num_regions++;

	logi("TODO: exe->regions is never freed\n");
	exe->regions = (struct mem_region*)krealloc(exe->regions, sizeof(struct mem_region) * exe->num_regions);
	exe->regions[nidx].start = nextbase;
	exe->regions[nidx].size = PAGE_SIZE;
	exe->regions[nidx].prot = PROT_RW;

	// Store pointer to exe loaded

	p->exe = exe;

	t = new_thread_kernel(p, exe->entry, allt->thread_exit, true, true);
	t->owner = p;

	mutex_acquire(&p->lock);
	p->num_threads++;
	mutex_release(&p->lock);

	mmu_map_pages_pgd((ptr_t*)p->user_pgd, nextbase, 1, PROT_RW);
//	mmu_map_page(nextbase, PROT_RW);
	mmu_memset((ptr_t*)p->user_pgd, (void*)nextbase, 0x00, PAGE_SIZE);

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

	mmu_strcpy((ptr_t*)p->user_pgd, data, MAIN_EXE_NAME);
	mmu_put_u64((ptr_t*)p->user_pgd, &(argvptrs[0]), (ptr_t)data);
//	argvptrs[0] = (ptr_t)data;
	data += strlen(MAIN_EXE_NAME) + 1;

	for(i = 0; i < numargs; i++)	{
		sep = strchr(argv, ',');
		if(sep == NULL)	len = strlen(argv);
		else			len = (sep - argv);

		mmu_memcpy((ptr_t*)p->user_pgd, data, argv, len);
		mmu_put_u64((ptr_t*)p->user_pgd, &(argvptrs[i+1]), (ptr_t)data);
		//argvptrs[i+1] = (ptr_t)data;
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
	mutex_acquire(&allt->lock);
	struct thread* t = new_thread_kernel(current_proc(), entry, allt->thread_exit, true, true);
	if(PTR_IS_ERR(t))	{
		mutex_release(&allt->lock);
		return PTR_TO_ERRNO(t);
	}
#if defined(CONFIG_MULTI_PROCESS)
	t->owner = current_proc();
#endif
	int i, rcount;

	// Ensure validity on number of arguments passed
	rcount = MIN(count, arch_max_supported_args());
	if(count != rcount)	{
		logw("Attempted to pass more parameters than arch supports %i > %i\n", count, rcount);
	}

	for(i = 0; i < rcount; i++)	{
		arch_thread_set_arg((void*)(t->stackptr), args[i], i);
	}
#if defined(CONFIG_MULTI_PROCESS)
	mutex_acquire(&t->owner->lock);
	t->owner->num_threads++;
	mutex_release(&t->owner->lock);
#endif
	mutex_release(&allt->lock);
	return t->id;
}


int thread_schedule_next(ptr_t unmap)	{
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
		logd("Performing task switch on %i tid: %i\n", c->cpuid, t->id);
		// If one is already running, we push it at the back of the queue
		if(c->running != NULL && c->running != allt->busyloop)	{
			xifo_push_back(allt->ready, c->running);
		}
		c->running = t;
		c->state = RUNNING;
		goto schedule;
	}

schedule:
	mutex_release(&allt->lock);
#if defined(CONFIG_MULTI_PROCESS)
	ptr_t upgd, _upgd = (c->running->owner) ? c->running->owner->user_pgd : 0x00;
	if(_upgd)	upgd = mmu_va_to_pa(_upgd);
	else		upgd = 0;
#else
	ptr_t upgd, _upgd = cpu_get_user_pgd();
	ASSERT(_upgd)
	upgd = mmu_va_to_pa(_upgd);
#endif
	
	struct process* __p = c->running->owner;
	if(__p && __p->thread_user_addr)	{
		mmu_memcpy((ptr_t*)_upgd, (void*)__p->thread_user_addr,
			&(c->running->tinfo), sizeof(struct user_thread_info));
	}

	if(unmap) vmmap_unmap(unmap);
	//switch_upgd(current_proc()->user_pgd);
	arch_schedule((void*)(c->running->stackptr), upgd);

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
	return thread_schedule_next(0);
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
	return thread_schedule_next(0);
}

int thread_yield(void)	{
	/* We will try and schedule something else, but we might return on this same
	 * thread if there is nothing else to execute.
	 */
	return thread_schedule_next(0);
}

#if defined(CONFIG_MULTI_PROCESS)
static void _thread_proc_exit(struct threads* allt, struct process* p)	{
	logi("destroying proc %i\n", p->pid);
	struct process* _p = llist_remove(allt->procs, p->pid);
	struct thread_fd_open* fdo;
	ASSERT_VALID_PTR(_p);
	ASSERT(_p == p);

	// TODO:
	// - If user-driver is in the same thread we are closing, we're going to
	//   run into problems. Disabled until it's fixed.
	thread_close_all(p);
	llist_delete(p->fds);

	bm_delete(p->fileids);

	thread_dealloc_memregionss(p);
	_thread_destroy_userslab(p);
//	llist_delete(p->memregions);

	// Unmap all and kfree all entries
	_munmap_all(p);
	llist_delete(p->mmapped);

	// Unmap all user-space addresses
	mmu_unmap_user((ptr_t*)p->user_pgd);

	
	deref_user_struct(p->user);
	p->exe->references--;

	if(p->exe->references <= 0)	{
		// All processes share the same image file, so we free the exe-object
		// when all processes has finished
		kfree(p->exe->regions);
		kfree(p->exe);
	}

	kfree(p);

	if(llist_empty(allt->procs))	{
		_thread_poweroff(allt);
	}

	thread_schedule_next(0);
}
#endif

int _remap_num_pages(ptr_t addr, int len)	{
	ptr_t start = addr, end = addr + len;
	ALIGN_DOWN_POW2(start, PAGE_SIZE);
	ALIGN_DOWN_POW2(end, PAGE_SIZE);
	return ((end - start) / PAGE_SIZE) + 1;
}
static ptr_t __remap_sys_shared(struct thread* t, struct process* curr, struct process* p, ptr_t addr, int size, bool write)	{
	int pages, i;
	struct threads* allt = cpu_get_threads();
	ptr_t naddr, ret, _tmp = addr, _addr, oa, entry;
	ALIGN_DOWN_POW2(_tmp, PAGE_SIZE);

	pages = _remap_num_pages(addr, size);

	naddr = _thread_find_user_memregion(p, pages);

	ptr_t diff = (addr - _tmp);;
	ret = (naddr + diff);

	mutex_acquire(&p->lock);
	for(i = 0; i < pages; i++)	{
		// This will force a check on the page and remove clone-bits and copy
		// page we need a writable page.
		//mmu_check_page_cloned_pgd((ptr_t*)curr->user_pgd, _tmp + ((ptr_t)i * PAGE_SIZE), true, false, write);
		mmu_check_page_cloned_pgd((ptr_t*)curr->user_pgd, _tmp + ((ptr_t)i * PAGE_SIZE), 
			CHK_CLONE_FLAG_NOPERM | CHK_CLONE_FLAG_COPY);
		oa = mmu_va_to_pa_pgd((ptr_t*)curr->user_pgd, _tmp + ((ptr_t)i * PAGE_SIZE), &entry);
		mmu_map_page_pgd_oa_entry((ptr_t*)p->user_pgd, naddr + ((ptr_t)i * PAGE_SIZE), oa, entry);
		pmm_add_ref(oa);
	}
	mutex_release(&p->lock);

//	mmu_double_map_pages((ptr_t*)curr->user_pgd, (ptr_t*)p->user_pgd, _tmp, naddr, pages);

	// This will ensure that the memory is unmapped on thread_exit
	TZALLOC(job, struct driver_job_unmap);
	job->call_addr = _tmp;
	job->drv_addr = naddr;
	job->pages = pages;
	_add_udriver_job(allt, JOB_UNMAP_MMU, (void*)job, t);

/*
	int pages;
	struct threads* allt = cpu_get_threads();
	ptr_t naddr, ret, _tmp = addr;
	ALIGN_DOWN_POW2(_tmp, PAGE_SIZE);

	pages = _remap_num_pages(addr, size);
	naddr = mmu_create_user_stack((ptr_t*)p->user_pgd, pages);
	
	ptr_t diff = (addr - _tmp);;
	ret = (naddr + diff);

	mmu_double_map_pages((ptr_t*)curr->user_pgd, (ptr_t*)p->user_pgd, _tmp, naddr, pages);

	// This will ensure that the memory is unmapped on thread_exit
	// TODO: Need to only trigger on exit, not wakeup
	_add_udriver_job(allt, JOB_UNMAP_MMU, (void*)(naddr | pages), t);
	*/
	/*
	struct driver_job* j = allocate_driver_job(JOB_UNMAP_MMU, current_thread(), p, (void*)(naddr | pages));
	PTR_IS_VALID(j);
	llist_insert(allt->texitjobs, j, t->id);
*/
	return ret;
}

static ptr_t _remap_sys_open(struct thread* t, struct process* curr, struct process* p, const char* s)	{
	int size = strlen_user(s) + 1, pages;
	return __remap_sys_shared(t, curr, p, (ptr_t)s, size, false);
}
static ptr_t _remap_sys_rw(struct thread* t, struct process* curr, struct process* p, ptr_t addr, int size, bool write)	{
	return __remap_sys_shared(t, curr, p, addr, size, write);
}

static ptr_t _remap_vfsopen(struct process* p, struct vfsopen* o)	{
	ptr_t addr = _thread_alloc_slabs(p, sizeof(struct vfsopen));
	mmu_memcpy((ptr_t*)p->user_pgd, (void*)addr, o, sizeof(struct vfsopen));
	kfree(o);
	return addr;
}

int thread_create_driver_thread(struct thread_fd_open* fdo, ptr_t entry, int sysno, int num, ...)	{
    struct vfsopen* o = fdo->open;
    struct fs_struct* fs = fdo->fs;
    struct process* p = cuse_get_process(fs), * curr = current_proc();
    struct thread* t;
    struct threads* allt = cpu_get_threads();
    va_list ap;
	ptr_t allargs[8], naddr;
    int i;
    ptr_t arg;

	PTR_IS_VALID(p);

    t = new_thread_kernel(p, entry, allt->exc_exit, true, false);
    if(PTR_IS_ERR(t))   return PTR_TO_ERRNO(t);
	t->owner = p;
	p->num_threads++;

#if defined(CONFIG_KCOV)
	// We want to track the caller kcov
	struct kcov* k = get_current_kcov();
	if(PTR_IS_VALID(k))	t->tinfo.caller_kcov = k->data;
#endif

    // Add the necessary arguments
    arch_thread_set_arg((void*)(t->stackptr), (ptr_t)o, 0); 
    va_start(ap, num);
    for(i = 1; i <= num; i++)   {
        arg = va_arg(ap, ptr_t);
        arch_thread_set_arg((void*)(t->stackptr), arg, i);
		allargs[i-1] = arg;
    }   
    va_end(ap);

	if(sysno == SYS_OPEN)	{
		if(p != curr)	{
			ptr_t _vfso = _remap_vfsopen(p, o);
			fdo->open = (struct vfsopen*)_vfso;
    		arch_thread_set_arg((void*)(t->stackptr), _vfso, 0); 

			naddr = _remap_sys_open(t, curr, p, (const char*)allargs[0]);
			arch_thread_set_arg((void*)(t->stackptr), naddr, 1);
			_add_udriver_job(allt, SYS_OPEN, (void*)fdo, t);
		}
	}
	else if(sysno == SYS_WRITE || sysno == SYS_READ)	{
		if(p != curr)	{
			naddr = _remap_sys_rw(t, curr, p, allargs[0], allargs[1], (sysno == SYS_READ));
			arch_thread_set_arg((void*)(t->stackptr), naddr, 1);
		}
	}
	else if(sysno == SYS_CLOSE) {
		// TODO: Create job for close
	}

	/*if(entry == (ptr_t)fs->open)	{
		_add_driver_job(allt, t, SYS_OPEN, fs, (void*)fdo);
	}
	else if(entry == (ptr_t)fs->read || entry == (ptr_t)fs->write ||
		entry == (ptr_t)fs->fcntl || entry == (ptr_t)fs->fstat ||
		entry == (ptr_t)fs->getc || entry == (ptr_t)fs->putc ||
		entry == (ptr_t)fs->lseek) {
	}*/
	else	{
		logw("Unsupported function-type for blocked %lx\n", entry);
	}

    // Add to front of ready-list
    thread_add_ready(t, true, true);

	thread_wait_tid(t->id, false, true);

	return -BLOCK_THREAD_ID;
}

int thread_exit(ptr_t ret)	{
	struct threads* allt = cpu_get_threads();
	struct cpu* c = curr_cpu();
	struct thread* t = c->running;
	struct driver_job* d;
	int tid = t->id;
	ptr_t kstack = 0;

	logd("Destroying thread %i\n", t->id);
	mutex_acquire(&allt->lock);

	//while((d = llist_remove(allt->driverjobs, t->id)) != NULL)	{
	while((d = llist_remove(allt->texitjobs, t->id)) != NULL)	{
		_handle_driver_ret(allt, t, d, true, ret);
	}

#if defined(CONFIG_MULTI_PROCESS)
	struct process* owner = t->owner;
	ASSERT_VALID_PTR(owner);
	owner->num_threads--;

	bool procexit = false;
	
	// owner may be null in two instances
	// 1. This exit is from an exception-thread
	// 2. Exit is from kernel thread
	if(owner)	{
		procexit = (owner->num_threads <= 0 && !(owner->keepalive));
	}
#endif

	bm_clear(allt->freetids, t->id);


	kstack = t->kstack - PAGE_SIZE;
	mmu_unmap_pages(
		t->ustack - (PAGE_SIZE * CONFIG_THREAD_STACK_BLOCKS),
		CONFIG_THREAD_STACK_BLOCKS
	);

	c->running = NULL;
	kfree(t);


	while( (t = (struct thread*)llist_remove(allt->waittid, tid)) != NULL)	{
		logd("Thread %i can wakeup\n", t->id);
		arch_thread_set_return((void*)(t->stackptr), ret);
		xifo_push_back(allt->ready, t);
	}

#if defined(CONFIG_MULTI_PROCESS)
	if(procexit)	{
		_thread_proc_exit(allt, owner);
	}
#endif


#if defined(CONFIG_EXIT_WHEN_NO_THREADS)
	// Check if there are any threads which can do something
	if(!xifo_count(allt->ready) && tlist_empty(allt->sleeping) && llist_empty(allt->blocked) && llist_empty(allt->waittid))
		_thread_poweroff(allt);
#endif

	mutex_release(&allt->lock);

	// This is the stack we are currently running on
//	vmmap_unmap(kstack);
	return thread_schedule_next(kstack);
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
	return thread_schedule_next(0);
}

static int _handle_retcode(int res)	{
	struct cpu* c = curr_cpu();
	switch(-res) {
		case BLOCK_THREAD:
			block_current();
			break;
		case BLOCK_THREAD_ID:
			c->running = NULL;
			thread_schedule_next(0);
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

static int _set_thread_user_addr(struct process* p, struct user_thread_info* info)	{
	if(ADDR_USER(info))	{
		struct thread* t = current_thread();
		p->thread_user_addr = info;
		mmu_memcpy((ptr_t*)p->user_pgd, info, &(t->tinfo), sizeof(struct user_thread_info));
		return OK;
	}
	return -USER_FAULT;
}

int process_configure(ptr_t cmd, ptr_t arg)	{
	int ret = OK;
	struct threads* allt = cpu_get_threads();
	struct thread* t = current_thread();
	struct process* p = t->owner;

	mutex_acquire(&p->lock);
	switch(cmd)	{
	case PROC_KEEPALIVE:
		p->keepalive = (bool)arg;
		break;
	case PROC_STORE_THREAD_INFO:
		ret = _set_thread_user_addr(p, (struct user_thread_info*)arg);
		break;
	default:
		ret = -USER_FAULT;
		break;
	}
	mutex_release(&p->lock);
	return ret;
}

static inline bool open_flags_valid(int flags)	{
	bool res;
	res = ((flags & OPEN_FLAG_WRITE) || (flags & OPEN_FLAG_READ));
	if(!res)	{
		logw("Flag %x is not valid\n", flags);
	}
	return res;
}

static inline int _check_permission(access_t perm)	{
	int ret = 0;
	if(perm & ACL_EXEC)		ret |= OPEN_FLAG_EXEC;
	if(perm & ACL_WRITE)	ret |= OPEN_FLAG_WRITE;
	if(perm & ACL_READ)		ret |= OPEN_FLAG_READ;
	if(perm & ACL_CTRL)		ret |= OPEN_FLAG_CTRL;
	return ret;
}
static inline bool check_permission(struct user_id* user, struct user_id* owner, access_t perm, int flags)	{
	int allowed = 0;
	if(user->uid == USERID_ROOT || user->uid == owner->uid)	{
		allowed |= _check_permission(ACL_OWNER_VAL(perm));
	}
	if(user->gid == USERID_ROOT || user->gid == owner->gid)	{
		allowed |= _check_permission(ACL_GROUP_VAL(perm));
	}
	allowed |= _check_permission(ACL_WORLD_VAL(perm));

	// All flags must be allowed for access to be allowed
	return ((allowed & flags) == flags);
}

ptr_t thread_mmap_mem(void* addr, size_t length, enum MEMPROT prot, int flags, bool ins)	{
	struct process* p = current_proc();
	int pages;
	ptr_t ret = 0;
	if(addr == NULL)	{
		ALIGN_UP_POW2(length, PAGE_SIZE);
		pages = length / PAGE_SIZE;
		mutex_acquire(&p->lock);
		ret = mmu_find_available_space((ptr_t*)p->user_pgd, pages, prot, true);
		mutex_release(&p->lock);
	}
	else	{
		ptr_t naddr = GET_ALIGNED_DOWN_POW2((ptr_t)addr, PAGE_SIZE);
		ptr_t nend = GET_ALIGNED_UP_POW2((ptr_t)addr + length, PAGE_SIZE);
		pages = (nend - naddr) / PAGE_SIZE;

		if(mmu_addr_mapped(naddr, (nend - naddr), MMU_ALL_UNMAPPED))	{
			mutex_acquire(&p->lock);
			mmu_map_pages_pgd((ptr_t*)p->user_pgd, naddr, pages, prot);
			mutex_release(&p->lock);
			ret = naddr;
		}
		else	{
			return thread_mmap_mem(NULL, length, prot, flags, ins);
		}
	}
	// TODO: Should allow mapping at NULL-address
	if(ret > 0 && ins)	{
		struct mmapped* ins = kmalloc( sizeof(struct mmapped) );
		ASSERT_VALID_PTR(ins);
		ins->start = ret;
		ins->pages = pages;
		ins->flags = flags;
		llist_insert(p->mmapped, ins, ins->start);
	}
	return ret;
}

static enum MEMPROT _mmap_to_memprot(int _prot)	{
	enum MEMPROT prot = PROT_NONE;
	if(_prot == (MAP_PROT_READ|MAP_PROT_WRITE|MAP_PROT_EXEC))	prot = PROT_RWX;
	else if(_prot == (MAP_PROT_READ|MAP_PROT_WRITE))			prot = PROT_RW;
	else if(_prot == (MAP_PROT_EXEC))							prot = PROT_RX;
	else if(_prot == (MAP_PROT_READ))							prot = PROT_RO;
	else if(_prot == (MAP_PROT_WRITE))						prot = PROT_RW;
	return prot;
}

ptr_t thread_mmap(void* addr, size_t length, int _prot, int flags, int fd)	{
	struct thread_fd_open* fdo;
	ptr_t ret;
	struct process* p = current_proc();
	ASSERT_TRUE(p, "p == NULL");
	enum MEMPROT prot;

	if(addr != NULL)	{
		if(!ADDR_USER_MEM(addr, length))	{
			logw("addr belongs to kernel mode %p - 0x%x\n", addr, length);
			return -USER_FAULT;
		}
		if(!ALIGNED_ON_POW2((ptr_t)addr, PAGE_SIZE))	{
			logw("mmap address must be aligned on page boundary\n");
			return -USER_FAULT;
		}
	}

	prot = _mmap_to_memprot(_prot);
	if(fd >= 0)	{
		fdo = llist_find(p->fds, fd);
		if(PTR_IS_ERR(fdo))		return -USER_FAULT;
	}

	ret = thread_mmap_mem(addr, length, prot, flags, true);

	if(ret > 0 && fd >= 0)	{
		int res;
		res = vfs_mmap(fdo, (void*)ret, length);
		if(res < 0)	_handle_retcode(res);
	}
	return ret;
}


static int _munmap_entry(struct process* p, struct mmapped* mm)	{
	mmu_unmap_pages_pgd((ptr_t*)p->user_pgd, mm->start, mm->pages);
	kfree(mm);
	return OK;
}

int thread_munmap(void* addr)	{
	struct mmapped* mm;
	struct process* p = current_proc();

	mm = llist_remove(p->mmapped, (long)addr);
	if(!PTR_IS_ERR(mm))	{
		return _munmap_entry(p, mm);
	}
	return -USER_FAULT;
}

static int _munmap_all(struct process* p)	{
	struct mmapped* mm = NULL;
	while((mm = llist_first(p->mmapped, true, NULL)) != NULL)	{
		_munmap_entry(p, mm);
	}
}


int thread_open(const char* name, int flags, int mode)	{
	int res = OK, nfd;
	char* kname, *fname, *uname;
	struct fs_struct* fs = NULL;
	struct vfsopen* o;
	access_t acc;
	struct threads* allt = cpu_get_threads();
	struct process* p = current_proc();
	struct user_id* user, *owner;

	// Check if flag combination is valid. This is coarse check, the driver may
	// have additional requirements.
	if(!open_flags_valid(flags))	return -USER_FAULT;

	TZALLOC_ERR(fdo, struct thread_fd_open);

	kname = strdup_user(name);
	if(PTR_IS_ERR(kname))	{
		res = -USER_FAULT;
		goto err1;
	}

	fname = kname;
	fs = vfs_find_open(&kname);
	uname = (char*)(name + (kname - fname));
	free_user(fname);
	if(PTR_IS_ERR(fs))	{
		res = -1;
		goto err1;
	}
	user = &(p->user->real);
	owner = &(fs->owner);

	if(!(check_permission(user, owner, fs->perm, flags)))	{
		res = -NO_ACCESS;
		goto err1;
	}

	nfd = fileid_unique();

	o = vfs_alloc_open(current_tid(), nfd, fs);
	if(PTR_IS_ERR(o))	{
		res = -MEMALLOC;
		goto err2;
	}

	// Copy in user structure so drivers can perform additional access control
	// This is mostly needed when the driver is a file system with additional
	// files protected by access control.
	memcpy(&(o->caller), user, sizeof(struct user_id));

	fdo->fs = fs;
	fdo->open = o;
	fdo->open_flags = flags;
	ASSERT_TRUE(p, "p == NULL");

	res = vfs_open(fdo, (const char*)uname, flags, mode);
	if(res < 0)	{
		if(res == -BLOCK_THREAD)	{
			logi("TODO: Need to add this to texitjobs if user-mode driver");
			int _res = _add_driver_job(allt, SYS_OPEN, (void*)fdo);
			if(_res != OK)	{
				res = _res;
				goto err3;
			}
		}
		_handle_retcode(res);

		goto err3;
	}
	else {
		llist_insert(p->fds, fdo, nfd);
	}

	return nfd;
// TODO: Double check error checking and free, also need to free nfd
err3:
//	llist_remove(p->fds, nfd);
	_thread_free_vfsopen(fdo);
err2:
	fileid_free(nfd);
err1:
	kfree(fdo);
	return res;
}

int thread_fcntl(int fd, ptr_t cmd, ptr_t arg)	{
	int res = OK;
	struct vfsopen* o;
	struct process* p = current_proc();
	struct threads* allt = cpu_get_threads();
	struct thread_fd_open* fdo;

	ASSERT_TRUE(p, "p == NULL");
	fdo = llist_find(p->fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;
	if(!(fdo->open_flags & OPEN_FLAG_CTRL))	return -NO_ACCESS;

	res = vfs_fcntl(fdo, cmd, arg);
	if(res < 0)	_handle_retcode(res);
	return res;
}
int _thread_close(struct process* p, struct thread_fd_open* fdo, int fd, bool exit)	{
	int res = OK;
	struct fs_struct* fs = fdo->fs;

	// If user-mode thread is running inside the process we are exiting, we
	// should not call close as it will fail
	if(!fs->user || cuse_get_process(fs) != p)	{
		// TODO: Need to handle this properly
		//  - Problem is that we must delay the free
		if(!exit)	{
			res = vfs_close(fdo);
			if(res < 0)	{
				if(!exit)
					_handle_retcode(res);
			}
		}
	}

	// TODO:
	// - Might not return here
	// - Thread might be blocked
	// - Should still free resources
	//fileid_free(fdo->open->fd);
	bm_clear(p->fileids, fd);
	_thread_free_vfsopen(fdo);
	kfree(fdo);

	return res;
}
int thread_close(int fd)	{
	int res = OK;
	struct vfsopen* o;
	struct process* p = current_proc();
	//struct threads* allt = cpu_get_threads();
	struct thread_fd_open* fdo;

	ASSERT_TRUE(p, "p == NULL");
	fdo = llist_remove(p->fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;

	return _thread_close(p, fdo, fd, false);
}
int thread_close_all(struct process* p)	{
	struct thread_fd_open* fdo;
	long fd;

	fdo = llist_first(p->fds, true, &fd);
	while(!PTR_IS_ERR(fdo))	{
		_thread_close(p, fdo, (int)fd, true);
		fdo = llist_first(p->fds, true, &fd);
	}
	return 0;
}
struct vfsopen* thread_find_fd(int fd)	{
	struct threads* allt = cpu_get_threads();
	struct process* p = current_proc();
	ASSERT_TRUE(p, "p == NULL");
	return llist_find(p->fds, fd);
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
	struct process* p = current_proc();
	struct threads* allt = cpu_get_threads();
	struct cpu* c = curr_cpu();

	// Ensure fd is real
	ASSERT_TRUE(p, "p == NULL");
	fdo = llist_find(p->fds, fd);
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
		kfree(iov);
		kfree(rwv);
	}
	return ret;
err1:
	kfree(iov);
	return ret;
}
int thread_fstat(int fd, struct stat* statbuf)	{
	int res = OK;
	struct thread_fd_open* fdo;
	struct process* p = current_proc();
	struct threads* allt = cpu_get_threads();

	if(!ADDR_USER_MEM(statbuf, sizeof(struct stat)))	{
		logi("Expected user-mode buffer\n");
		return -USER_FAULT;
	}

	ASSERT_TRUE(p, "p == NULL");
	fdo = llist_find(p->fds, fd);
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
	struct process* p = current_proc();
	struct threads* allt = cpu_get_threads();

	if(!ADDR_USER_MEM(buf, count))	{
		logw("Tried to write from kernel addr: %p (%x)\n", buf, count);
		return -USER_FAULT;
	}

	ASSERT_TRUE(p, "p == NULL");
	fdo = llist_find(p->fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;
	if(!(fdo->open_flags & OPEN_FLAG_WRITE))	return -NO_ACCESS;

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
	struct process* p = current_proc();
	struct threads* allt = cpu_get_threads();
	char* b = (char*)buf;

	if(!ADDR_USER_MEM(buf, count))	{
		logw("Tried to read from kernel addr: %p (%x)\n", buf, count);
		return -USER_FAULT;
	}

	ASSERT_TRUE(p, "p == NULL");
	fdo = llist_find(p->fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;
	if(!(fdo->open_flags & OPEN_FLAG_READ))	return -NO_ACCESS;

	res = vfs_read(fdo, buf, count);

	if(res < 0)	_handle_retcode(res);
	return res;
}

int thread_lseek(int fd, off_t offset, int whence)	{
	int res = OK;
	struct vfsopen* o;
	struct thread_fd_open* fdo;
	struct threads* allt = cpu_get_threads();
	struct process* p = current_proc();

	ASSERT_TRUE(p, "p == NULL");
	fdo = llist_find(p->fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;

	res = vfs_lseek(fdo, offset, whence);

	if(res < 0)	_handle_retcode(res);

	return res;
}

int _thread_dup(struct thread_fd_open* _fdo)	{
	int res;
	struct threads* allt = cpu_get_threads();
	struct process* p = current_proc();
	TZALLOC_ERR(fdo, struct thread_fd_open);
	if(ADDR_USER(_fdo->open))	PANIC("Duplicating fd for user-mode driver not supported");

//	TZALLOC_ERR(o, struct vfsopen);
	// TODO: Need to handle vfsopen in user-mode
	logi("TODO: Need to check if vfsopen is in user-mode\n");
	struct vfsopen* o = (struct vfsopen*)kmalloc( sizeof(struct vfsopen) );
	if(PTR_IS_ERR(o))	{
		res = -MEMALLOC;
		goto err1;
	}
	o->tid = current_tid();
	o->fd = fileid_unique();
	o->data = _fdo->open->data;
	o->offset = _fdo->open->offset;
	fdo->open = o;
	fdo->fs = _fdo->fs;
	fdo->open_flags = _fdo->open_flags;

	ASSERT_TRUE(p, "p == NULL");
	llist_insert(p->fds, fdo, o->fd);
	return o->fd;
err1:
	kfree(fdo);
	return res;
}

int thread_dup(int fd)	{
	int res = OK;
	struct vfsopen* o;
	struct thread_fd_open* fdo;
	struct process* p = current_proc();
	struct threads* allt = cpu_get_threads();

	ASSERT_TRUE(p, "p == NULL");
	fdo = llist_find(p->fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;

	res = _thread_dup(fdo);
	if(res < 0)	_handle_retcode(res);
	return res;
}
/*
struct thread_fd_open* _copy_fd(struct thread_fd_open* fdo, struct thread* t)	{
	struct thread_fd_open* ret = (struct thread_fd_open*)malloc( sizeof(struct thread_fd_open) );
	if(ADDR_USER(fdo->open))	{
		PANIC("Duplicating fd for user-mode driver not supported");
		ret->open = fdo->open;
	}
	else	{
		struct vfsopen* o = (struct vfsopen*)malloc( sizeof(struct vfsopen*) );
		o->tid = t->id;
		o->fd = fdo->open-fd;

		ret->open = o;
	}

}
*/

int thread_copy_fds(struct process* from, struct process* to, struct thread* t)	{
	int i = 0, res = OK;
	struct thread_fd_open* fdo = llist_index(from->fds, i++);
	struct thread_fd_open* nfdo;
	struct vfsopen* o;
	while(fdo)	{
		if(ADDR_USER(fdo->open))	PANIC("Duplicating fd for user-mode driver not supported");

		nfdo = (struct thread_fd_open*)kmalloc( sizeof(struct thread_fd_open) );
		o = (struct vfsopen*)kmalloc( sizeof(struct vfsopen) );
		logi("TODO: Need to check if vfsopen is in user-mode\n");

		if(PTR_IS_ERR(o))	{
			res = -GENERAL_FAULT;
			break;
		}
		o->tid = t->id;
		o->fd = fdo->open->fd;
		bm_set(to->fileids, o->fd, o->fd + 1);
		o->data = fdo->open->data;
		o->offset = fdo->open->offset;
		nfdo->open = o;
		nfdo->fs = fdo->fs;
		nfdo->open_flags = fdo->open_flags;

		llist_insert(to->fds, nfdo, o->fd);
	
		fdo = llist_index(from->fds, i++);
	}
	return res;
}

int thread_getchar(int fd)	{
	int res = OK;
	struct vfsopen* o;
	struct thread_fd_open* fdo;
	struct process* p = current_proc();
	struct threads* allt = cpu_get_threads();

	ASSERT_TRUE(p, "p == NULL");
	fdo = llist_find(p->fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;
	if(!(fdo->open_flags & OPEN_FLAG_READ))	return -NO_ACCESS;

	res = vfs_getchar(fdo);

	if(res < 0)	_handle_retcode(res);
	return res;
}

int thread_putchar(int fd, int c)	{
	int res = OK;
	struct vfsopen* o;
	struct thread_fd_open* fdo;
	struct process* p = current_proc();
	struct threads* allt = cpu_get_threads();

	ASSERT_TRUE(p, "p == NULL");
	fdo = llist_find(p->fds, fd);
	if(PTR_IS_ERR(fdo))		return -USER_FAULT;
	if(!(fdo->open_flags & OPEN_FLAG_WRITE))	return -NO_ACCESS;

	res = vfs_putchar(fdo, c);
	if(res < 0)	{
		// TODO: Need to unmap here if driver failed
		_handle_retcode(res);
	}
	return res;
}

int _copy_mmapped(struct process* p, struct process* old)	{
	struct mmapped* mm = NULL;
	int i = 0;
	while((mm = llist_index(old->mmapped, i)) != NULL)	{
		if(FLAG_SET(mm->flags, MAP_NON_CLONED))	{
			mmu_copy_cloned_pages(mm->start, mm->pages, (ptr_t*)old->user_pgd, (ptr_t*)p->user_pgd);
		}
		llist_insert(p->mmapped, mm, mm->start);
		i++;
	}

	return OK;
}
/*
static int _unclone_mmapped(struct process* old, struct process* new)	{
	struct mmapped* mm;
	int i = 0;
	while((mm = llist_index(old->mmapped, i)) != NULL)	{
	}
	return OK;
}
*/
int thread_fork(void)	{
#if defined(CONFIG_MULTI_PROCESS)
	int res = -GENERAL_FAULT;
	struct threads* allt = cpu_get_threads();

	struct process* old = current_proc();
	struct thread* t, * curr = current_thread();
	if(PTR_IS_ERR(old))	goto err0;
	TZALLOC_ERR(p, struct process);

	res = process_init(p);
	if(res)	goto err1;

	p->user = fork_user_struct(old->user);
	p->pid = pid_unique();
	p->num_threads = 1;
	p->thread_user_addr = old->thread_user_addr;
	p->keepalive = old->keepalive;
	p->exe = old->exe;
	p->exe->references++;

	t = thread_copy_thread(p, current_thread());
	ASSERT_VALID_PTR(t);
	t->owner = p;

	mutex_acquire(&allt->lock);
	res = thread_copy_fds(old, p, t);
	if(res)	goto err1;


	t->retval = 0;
	arch_thread_set_arg((void*)(t->stackptr), 0, 0);
	xifo_push_back(allt->ready, t);
	
	// Need to unmap newly created ustack from current pgd
	/*
	ptr_t ustack = t->ustack - (CONFIG_THREAD_STACK_BLOCKS * PAGE_SIZE);
	mmu_unmap_pages(ustack, CONFIG_THREAD_STACK_BLOCKS);
	*/
	res = mmu_clone_fork((ptr_t*)p->user_pgd);
	if(res)	goto err1;

	// Clone all the mmapped regions so that child also can unmap them
	_copy_mmapped(p, old);

	//mmu_map_pages_pgd((ptr_t*)p->user_pgd, ustack, CONFIG_THREAD_STACK_BLOCKS, PROT_RW);

	llist_insert(allt->procs, p, p->pid);
	mutex_release(&allt->lock);

	// TODO:
	// 1. Clone PGD as RO with COW
	//   - Need reference count in pmm
	// 2. Clone file descriptors
	// 3. Create thread
	//   - Replicate stack as from caller
	//   - A simple memcpy should do, I think
	//   - This will set appropriate return address
	// 4. Set return register on both:
	//   - 0 on child
	//   - pid of child on parent

	return p->pid;
	//return thread_schedule_next(0);
err1:
	kfree(p);
err0:
	mutex_release(&allt->lock);
	return res;
#else
	return -UNSUPPORTED_FUNC;
#endif
}

int thread_get_tid(void)	{
	return curr_cpu()->running->id;
}

int thread_wait_tid(int tid, bool sched, bool lockheld)	{
	struct threads* allt = cpu_get_threads();
	struct cpu* c = curr_cpu();
	struct thread* t;
	int res = OK;
	if(!lockheld)	mutex_acquire(&allt->lock);

	// If tid has not been allocated, there is nothing to wait for
	if(bm_index_free(allt->freetids, tid))	{
		goto done;
	}

	t = c->running;
	// We must schedule something new
	if(sched)	{
		c->running = NULL;
	}

	/*
	* Insert in list and sort by tid we are waiting on. Because of the way this
	* list is organized, a thread cannot wait on multiple other threads, but
	* multiple threads can wait on the same thread. This makes sense as the
	* problem of waiting on multiple threads can easily be solved in use more.
	*/
	res = llist_insert(allt->waittid, t, tid);

	// Release the lock and schedule something else
	if(!lockheld)	mutex_release(&allt->lock);
	if(sched)	return thread_schedule_next(0);
	return OK;

done:
	mutex_release(&allt->lock);
	return res;
}
int thread_wakeup(int tid, ptr_t res)	{
	struct threads* allt = cpu_get_threads();
	struct thread* t;
	struct cpu* c = curr_cpu();
	struct driver_job* d;
	int ret = OK;

	mutex_acquire(&allt->lock);


	t = llist_remove(allt->blocked, tid);
	if(PTR_IS_ERR(t))	{
		BUG("Tried to wakeup thread which is not blocked\n");
		ret = -GENERAL_FAULT;
		goto done;
	}
	//while((d = llist_remove(allt->driverjobs, tid)) != NULL)	{
	while((d = llist_remove(allt->lowhalfjobs, tid)) != NULL)	{
		_handle_driver_ret(allt, t, d, false, res);
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
			kfree(rem->iov);
			kfree(rem);
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
int thread_schedule_cb(int irqno)	{
	return thread_schedule_next(0);
}

int thread_setuser(struct user_id* user)	{
#if defined(CONFIG_SUPPORT_USERS)
	struct process* p = current_proc();
	struct user_id id, *cid = &(p->user->real);
	if(memcpy_from_user(&id, user, sizeof(struct user_id)))	return -USER_FAULT;

	if(cid == USERID_ROOT)	{
		memcpy(cid, &id, sizeof(struct user_id));
		return OK;
	}
	return -NO_ACCESS;
#else
	return -UNSUPPORTED_FUNC;
#endif
}
int thread_getuser(struct user_id* user)	{
#if defined(CONFIG_SUPPORT_USERS)
	struct process* p = current_proc();
	if(memcpy_from_user(&(p->user), user, sizeof(struct user_id)))	return -USER_FAULT;

	return OK;
#else
	return -UNSUPPORTED_FUNC;
#endif
}
int thread_set_filter(sysfilter_t filter)	{
#if defined(CONFIG_SUPPORT_SYSCALL_FILTER)
	struct process* p = current_proc();
	// This ensures that user can only reduce privileges
	filter |= p->user->filter;
	p->user->filter = filter;
	return OK;
#else
	return -UNSUPPORTED_FUNC;
#endif
}
sysfilter_t thread_get_filter(void)	{
#if defined(CONFIG_SUPPORT_SYSCALL_FILTER)
	struct process* p = current_proc();
	return p->user->filter;
#else
	return -UNSUPPORTED_FUNC;
#endif
}

bool thread_access_valid(int sysno)	{
#if defined(CONFIG_SUPPORT_SYSCALL_FILTER)
	ASSERT(sysno < (sizeof(sysfilter_t) * 8));
	struct process* p = current_proc();
	return ((1 << sysno) & p->user->filter) == 0;
#else
	return true;
#endif
}

/*
int thread_proc_keepalive(void)	{
	struct process* p = current_proc();
	p->keepalive = true;
	return OK;
}
*/
