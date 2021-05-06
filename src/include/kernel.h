#ifndef __XSPOS_H
#define __XSPOS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// C-lib types
#include <fcntl.h>

#include "types.h"
#include "arch.h"
#include "log.h"
#include "sizes.h"
#include "lib.h"
#include "drivers.h"
#include "vfs.h"
#include "kasan.h"


#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#define READ_ONCE(x) ({ typeof(x) ___x = ACCESS_ONCE(x); ___x; })
#define WRITE_ONCE(x, val) do { ACCESS_ONCE(x) = (val); } while (0)
#define barrier() __asm__ __volatile__("": : :"memory")


#define __noreturn __attribute__((noreturn))

#define THREAD_STACK_BOTTOM(tid) \
	(ARM64_VA_THREAD_STACKS_START + (PAGE_SIZE * (CONFIG_THREAD_STACK_BLOCKS * ntid)))
#define THREAD_STACK_TOP(tid) \
	(THREAD_STACK_BOTTOM(tid) + (CONFIG_THREAD_STACK_BLOCKS * PAGE_SIZE))

// kstart.c
extern struct os_data osdata;

void panic(const char*, const char*, int);


typedef int (*kputc_t)(char);
typedef int (*kgetc_t)(void);
typedef int (*kputs_t)(const char*);
typedef int (*kputc_t)(char);
typedef int (*printf_t)(const char*, ...);


#define __UNIQUE_ID(prefix,line) prefix##line
#define _UNIQUE_ID(prefix,line) __UNIQUE_ID(prefix,line)

typedef uint32_t ipv4_t;
typedef uint16_t tid_t;
typedef uint64_t ptr_t;

#define VMMAP_FLAG_NONE        (0)
#define VMMAP_FLAG_LAZY_ALLOC  (1 << 0)
#define VMMAP_FLAG_PHYS_CONTIG (1 << 1)
#define VMMAP_FLAG_ZERO        (1 << 2)
#define VMMAP_FLAG_KASAN_NOMARK (1 << 3)

// TODO: Not in use yet, but might be needed in the future
//#define VMMAP_FLAG_DEVICE (1 << 2)

struct thread;
struct bm;
struct dtb_node;


enum FILENO {
	FILENO_DRV_START = 0xff,
	FILENO_DRV_RNG,
	FILENO_DRV_STOP,
};

enum dtb_type {
	UNKNOWN = 0,
	EMPTY,
	STRING,
	NUMBER,
	INTEGERS,
};

struct mem_region {
	ptr_t start, size;
	enum MEMPROT prot;
};

struct loaded_exe {
	int num_regions;
	struct mem_region* regions;
	ptr_t entry;
	int references;
};

struct NetConfig {
	ipv4_t addr, gw, dhcpaddr;
	ipv4_t dnsserver[2];
	ipv4_t netmask;
	uint8_t mac[6];
};

struct dtb_property {
	char* name;
	int valsize;
	void* data;
	enum dtb_type type;
	union {
		char* string;
		uint32_t* ints;
		uint32_t num;
//		struct dtbreg reg;
	} val;
};

struct dtb_node {
	char* name;
	// All entries on this node in an array
	int numprops;
	struct dtb_property* props;

	// Array of all childs
	int numchilds, maxchilds;
	struct dtb_node** childs;
	struct dtb_node* parent;
};


struct pmm {
	uint8_t* bitmap;
	ptr_t start, end;
	size_t pages;
	mutex_t lock;
};

struct sbrk {
	void* addr;
	size_t curroffset, numpages, mappedpages;
	mutex_t lock;
};

struct virtmem {
	ptr_t start;
	size_t pages;
	struct bm* free;
};
struct mmapped {
	ptr_t start;
	int pages;
	int flags;
};

// The size of each slab entry, it's possible to allocate larger elements, one
// just has to allocate multiple slabs.
#define PROC_SLAB_SIZE (32)
#define PROC_SLAB_NUM_PAGES (2)
struct userslab {
	ptr_t start;
	int slabsz, slabs;
	struct bm* free;
};

struct process {
	/** 
	* Lock should be held briefly and only when doing the following:
	* - Acquiring a unique file id (done when using `fileid_unique`)
	* - Mapping in user memory
	* - Writing to individual variables which are not list, queues, bitmap, etc.
	* - Configuring values in process
	*/
	mutex_t lock;
#if defined(CONFIG_MULTI_PROCESS)
	int pid;
	int num_threads;
#endif
	struct kern_user_struct* user;
	struct sbrk ubrk;
	ptr_t user_pgd;
	struct loaded_exe* exe;
	struct llist* fds;
	struct bm* fileids;
	struct userslab* userslab;
	struct llist* memregions;
	struct llist* mmapped;
	bool keepalive;
	struct user_thread_info* thread_user_addr;
};

struct thread_fd_open {
	struct fs_struct* fs;
	struct vfsopen* open;
	int open_flags;
};


struct driver_job_unmap {
	ptr_t call_addr, drv_addr;
	int pages;
};

struct driver_job {
	int sysno;
	struct thread* caller;
	/**
	* If this is a user-mode 
	*/
	struct process* driver;
	/**
	* Different data stored on different syscalls:
	* open: struct thread_fd_open
	* read: struct thread_fd_open
	* write: struct thread_fd_open
	*/
	void* data;
};

struct tlist;


/**
* Information we store about a thread.
* TODO: Unsure if we will need a lock on this object
*  - Only modified on CPU running or on different CPUs when blocked
*/
struct thread {
	tid_t id;
	ptr_t ustack;
	ptr_t kstack;
	ptr_t stackptr;

	ptr_t retval;

	// This is blocking, so there can only be one pending
	struct readwritev* pending;

	/*
	* Any signals pending to the thread.
	*/
	//struct XIFO* sigpending;
	struct process* owner;
#if defined(CONFIG_KCOV)
	struct kcov* kcov;
#endif

	struct user_thread_info tinfo;
};

/**
* All the information associated with all running threads.
*/
struct threads {
	/**
	* Thread identifiers (TID) which are free to use.
	*/
	struct bm* freetids;

	/**
	* Any exceptions in user-mode which are pending execution.
	*
	* This can be signals and user-mode implementations of drivers.
	*/
	//struct XIFO* userpending;

	/**
	* Allocated objects and stacks which can be used if a new user-
	* function should be called.
	*
	* These are used as lightweight threads, which are meant to be short-
	* lived.
	*/
//	struct XIFO* userfuncavail;

	/**
	* Kernel thread which we can always execute on one or more CPUs.
	* We have only one thread, but may call it on multiple CPUs, so this thread
	* cannot be dependent on memory values which are shared writable among the
	* different threads, such as the stack.
	*/
	struct thread* busyloop;

	/**
	* Threads waiting to run, this is ordered in a simple first-in-first-out
	* fashion. No prioritization is performed.
	*/
	struct XIFO* ready;

	/**
	* Threads which are sleeping and should wakeup at some timing event in the
	* future.
	*/
	struct tlist* sleeping;

	/**
	* Threads which are blocked waiting on some driver.
	*/
	struct llist* blocked;

	/**
	* Threads waiting on another thread to finish
	*/
	struct llist* waittid;

	/**
	* If a job is blocked by the driver and we might need to update data
	* depending on success / failure, then we need to store some information
	* about what to on interrupt from lower half.
	*/
	//struct llist* driverjobs;

	struct llist* texitjobs;
	struct llist* lowhalfjobs;

	//struct llist* fd_fs_mapping;

	/**
	* Information associated with a process / address space.
	*
	* If the system is modified in the future to support multiple processes,
	* most of the information that needs to changed is stored in this struct.
	*/
#if defined(CONFIG_MULTI_PROCESS)
	struct llist* procs;
	struct bm* procids;
#else
	struct process proc;
#endif

	/** Lock which determines if any CPU is working on threads. */
	mutex_t lock;

	ptr_t thread_exit;
	ptr_t exc_exit;
};

#if CONFIG_COLLECT_STATS > 0
struct stats {
	struct {
		ptr_t pagescount, pagestaken;
	} memory;
};
#endif


struct vmmap {
	// Which pages are free and which are taken
	struct bm bm;

	ptr_t vaddrstart;

	// Number of blocks we control
	ptr_t blocks;
};

enum cpu_state {
	DEFAULT = 0,
	RUNNING,
	BUSYLOOP,
};

#if defined(CONFIG_RCU)
struct rcu_item_wait_free {
	void* addr;
	rcu_status_t status;
};
struct rcu_wait_free {
	int numwaiting, maxwaiting;
	struct rcu_item_wait_free* waiting;
};
#endif

/**
* Information about one CPU.
*/
struct cpu {
	/** CPU is as reported by architecture-defined function */
	int cpuid;

	/**
	* The thread currently running on this CPU.
	*/
	struct thread* running;

	/** Compatible string from DTB */
	char* compatible;

	/** Lock which indicates whether this CPU has finished booting */
	mutex_t readylock;

	/** Current state of the CPU */
	enum cpu_state state;

#if defined(CONFIG_RCU)
	rcu_t in_rcu;
	struct rcu_wait_free waitfree;
#endif
};

typedef int (*cpu_on_t)(int,ptr_t);
typedef void (*poweroff_t)(void);

/**
* Information about all CPUs on the system.
*/
struct cpus {
	/**
	* Array of all CPU cores.
	*
	* Maximum number of cores is defined before compiling by configuring
	* :c:type:`CONFIG_MAX_CPUS`.
	*/
	struct cpu cpus[CONFIG_MAX_CPUS];

	/** Number of CPUs available. */
	int numcpus;

	/**
	* Function pointer to reset CPU.
	*
	* Appropriate driver should fill in this function.
	*/
	cpu_on_t cpu_on;

	/** Function pointer to power off computer */
	poweroff_t poweroff;
};



/**
* Global object which contains most data about the running kernel.
*/
struct os_data {
	/**
	* Pointer to dtb data we received from bootloader.
	*
	* Note:
	*	This should be removed, as we only use dtbroot after initialization.
	*/
	void* dtb;
	struct dtb_node* dtbroot;
	kputs_t kputs;
	kputc_t kputc;

	kgetc_t kgetc;
	printf_t printk;


	ptr_t kernel_start,
	kernel_end;

	ptr_t kpgd;
	ptr_t upgd;

	ptr_t linear_offset;

	struct threads threads;

	// TODO: Physical memory
	struct pmm pmm;
	
	struct vmmap vmmap;
	
	struct sbrk kernbrk;
#if CONFIG_COLLECT_STATS > 0
	struct stats stats;
#endif

	struct cpus cpus;

	struct NetConfig network;

	struct fs_component root;

	mutex_t loglock;
};

static inline struct threads* cpu_get_threads() { return &(osdata.threads); }

#if defined(CONFIG_MULTI_PROCESS)
static inline struct process* current_proc()	{
	struct thread* t = osdata.cpus.cpus[cpu_id()].running;
//	ASSERT_VALID_PTR(t);
//	ASSERT_VALID_PTR(t->owner);
	return (t) ? t->owner : NULL;
}
static inline pid_t current_pid()	{
	return osdata.cpus.cpus[cpu_id()].running->owner->pid;
}
static inline pid_t pid_unique()	{
	struct threads* allt = cpu_get_threads();
	int r = bm_get_first(allt->procids);
	return r;
}
static inline void set_thread_owner(struct thread* t)	{
	t->owner = current_proc();
	ASSERT_VALID_PTR(t->owner);
	t->owner->num_threads++;
}
#else
static inline struct process* current_proc()	{
	struct threads* allt = cpu_get_threads();
	return &(allt->proc);
}
static inline pid_t current_pid()	{
	return 0;
}
static inline void set_thread_owner(struct thread* t) { }
#endif


static inline int fileid_unique(void)	{
	struct process* p = current_proc();
	mutex_acquire(&p->lock);
	int r = bm_get_first(p->fileids);
	mutex_release(&p->lock);
	return r;
}
static inline void fileid_free(int id)	{
	struct process* p = current_proc();
	bm_clear(p->fileids, id);
}



// --------------------- Various stats functions ----------------------------- //
#if CONFIG_COLLECT_STATS > 0
static inline void stat_set_phys_pages(ptr_t p) { osdata.stats.memory.pagescount = p; }
static inline void stat_add_taken_pages(int c) { osdata.stats.memory.pagestaken += c; }
static inline void stat_inc_taken_page() { osdata.stats.memory.pagestaken++; }
static inline void stat_dec_taken_page() { osdata.stats.memory.pagestaken--; }
#else
static inline void stat_set_phys_pages(ptr_t _p) { }
static inline void stat_add_taken_pages(int _c) { }
static inline void stat_inc_taken_page() { }
static inline void stat_dec_taken_page() { }
#endif

static inline mutex_t* cpu_loglock() { return &(osdata.loglock); }
static inline struct dtb_node* cpu_get_parsed_dtb() { return osdata.dtbroot; }
static inline struct pmm* cpu_get_pmm() { return &(osdata.pmm); }
static inline struct sbrk* cpu_get_kernbrk() { return &(osdata.kernbrk); }
static inline void* cpu_get_dtb() { return osdata.dtb; }
static inline ptr_t cpu_get_pgd() { return osdata.kpgd; }
//static inline ptr_t cpu_get_user_pgd() { return osdata.upgd; }
//static inline void cpu_set_user_pgd(ptr_t o) { osdata.upgd = o; }
static inline void cpu_set_user_pgd(ptr_t o) { current_proc()->user_pgd = o; }
static inline ptr_t cpu_get_user_pgd() { return current_proc()->user_pgd; }
static inline ptr_t* thread_get_user_pgd(struct thread* t) { return (ptr_t*)(t->owner->user_pgd); }
static inline ptr_t cpu_linear_offset() { return osdata.linear_offset; }
static inline struct vmmap* cpu_get_vmmap() { return &(osdata.vmmap); }

static inline struct cpu* curr_cpu() { return &(osdata.cpus.cpus[cpu_id()]); }


static inline int current_tid(void) {
	return osdata.cpus.cpus[cpu_id()].running->id;
}
static inline struct thread* current_thread(void)	{
	return osdata.cpus.cpus[cpu_id()].running;
}

#if defined(CONFIG_KCOV) && !defined(UMODE)
static inline struct kcov* get_current_kcov(void) {
	struct thread* t = current_thread();
	return (t) ? t->kcov : NULL;
}
static inline struct kcov* set_current_kcov(struct kcov* kcov) {
	struct thread* t = current_thread();
	if(t) t->kcov = kcov;
}
#endif

static inline int cpus_busyloop(void)	{
	int i, ret = 0;
	for(i = 0; i < osdata.cpus.numcpus; i++)	{
		if(osdata.cpus.cpus[i].state == BUSYLOOP)	{
			ret++;
		}
	}
	return ret;
}
static inline int cpu_find_busyloop(void)	{
	int i;
	for(i = 0; i < osdata.cpus.numcpus; i++)	{
		if(osdata.cpus.cpus[i].state == BUSYLOOP)	{
			return i;
		}
	}
	return -1;

}

static inline uint16_t reverse_bits_16(uint16_t v)	{
	uint16_t r = 0;
	r |= (v >> 8) & 0xff;
	r |= (v << 8) & 0xff00;
	return r;
}

static inline uint32_t reverse_bits_32(uint32_t v)	{
	uint32_t r = 0;
	r = (v & 0xff) << 24;
	r |= (v & 0xff00) << 8;
	r |= (v & 0xff0000) >> 8;
	r |= (v & 0xff000000) >> 24;
	return r;
}

static inline uint16_t cpu_u16_to_be(uint16_t v)	{
#if defined(ARCH_LITTLE_ENDIAN)
	return reverse_bits_16(v);
#elif defined(ARCH_BIG_ENDIAN)
	return v;
#else
	#error "Must define big or little endian arch"
#endif
}

static inline uint16_t be_u16_to_cpu(uint16_t v)	{
#if defined(ARCH_LITTLE_ENDIAN)
	return reverse_bits_16(v);
#elif defined(ARCH_BIG_ENDIAN)
	return v;
#else
	#error "Must define big or little endian arch"
#endif
}


static inline uint32_t be_u32_to_be(void* data)	{
	return *((uint32_t*)data);
}


static inline uint32_t be_u32_to_le(void* data)	{
	uint8_t* d = (uint8_t*)data;
	uint32_t r = (uint32_t)(d[0]) << 24 | (uint32_t)(d[1]) << 16 | (uint32_t)(d[2]) << 8 | (uint32_t)(d[3]);
	return r;
}

static inline uint32_t be_u32_to_cpu(void* data)	{
#if defined(ARCH_LITTLE_ENDIAN)
	return be_u32_to_le(data);
#elif defined(ARCH_BIG_ENDIAN)
	return be_u32_to_be(data);
#else
	#error "Must define big or little endian arch"
#endif
}

static inline uint32_t be_u32bits_to_be(uint32_t data)	{
	return data;
}

static inline uint32_t be_u32bits_to_le(uint32_t data)	{
	uint32_t ret = 0;
	ret |= (data & 0xff) << 24;
	ret |= ((data & 0xff00) >> 8) << 16;
	ret |= ((data & 0xff0000) >> 16) << 8;
	ret |= ((data & 0xff000000) >> 24);
	return ret;
}

static inline uint32_t be_u32bits_to_cpu(uint32_t entry)	{
#if defined(ARCH_LITTLE_ENDIAN)
	return reverse_bits_32(entry);
#elif defined(ARCH_BIG_ENDIAN)
	return entry;
#else
	#error "Must define big or little endian arch"
#endif
}

static inline uint32_t cpu_u32_to_be(uint32_t v)	{
#if defined(ARCH_LITTLE_ENDIAN)
	return reverse_bits_32(v);
#elif defined(ARCH_BIG_ENDIAN)
	return v;
#else
	#error "Must define big or little endian arch"
#endif

}

/*
#define ALIGN_UP_POW2(num,val) { if(num == 0)	num = val; if((num % val) != 0)	{ num |= (val - 1); num++; } }
#define ALIGN_DOWN_POW2(num,val) { if(num != 0 && (num % val) != 0) { num &= ~(val-1); } }
*/



#define DMAR8(addr, res) res = *((volatile uint8_t*)(addr))
#define DMAR16(addr, res) res = *((volatile uint16_t*)(addr))
#define DMAR32(addr, res) res = *((volatile uint32_t*)(addr))
#define DMAR64(addr, res) res = *((volatile uint64_t*)(addr))

#define DMAW8(addr, val) *((volatile uint8_t*)(addr)) = val;
#define DMAW16(addr, val) *((volatile uint16_t*)(addr)) = val;
#define DMAW32(addr, val) *((volatile uint32_t*)(addr)) = val;
#define DMAW64(addr, val) *((volatile uint64_t*)(addr)) = val;

// ---------------------- dtb.c --------------------- //
uint32_t dtb_translate_ref(void* ref);
void* dtb_get_ref(const char* node, const char* prop, int skip, int* cells_sz, int* cells_addr);

void dtb_destroy(struct dtb_node* root);
void dtb_second_pass(struct dtb_node* root);
struct dtb_node* dtb_parse_data(void* dtb);
struct dtb_node* dtb_find_name(const char* n, bool exact, int skip);
uint32_t* dtb_get_ints(struct dtb_node* node, const char* name, int* count);
const char* dtb_get_string(struct dtb_node* node, const char* name);
int dtb_get_as_reg(struct dtb_node* node, int skip, ptr_t* outaddr, ptr_t* outlen);
uint32_t dtb_get_int(struct dtb_node* node, const char* name);
int dtb_get_interrupts(struct dtb_node* node, uint32_t* type, uint32_t* nr, uint32_t* flags);
void dtb_dump_compatible(struct dtb_node* n);
bool dtb_is_compatible(struct dtb_node* n, const char* c);
int get_memory_dtb(ptr_t* outaddr, ptr_t* outlen);

// ----------------------- pmm.c ---------------------- //
int pmm_init();
ptr_t pmm_alloc(int pages);
int pmm_mark_mem(ptr_t start, ptr_t end);
int pmm_free(ptr_t page);
int pmm_add_ref(ptr_t page);
int pmm_ref(ptr_t page);

int uart_early_putc(char c);
int uart_early_getc(void);
int uart_early_write(const char* str);

// --------------------- vmmap.c -------------------------- //

int init_vmmap(void);
ptr_t vmmap_alloc_pages(int pages, enum MEMPROT prot, ptr_t flags);
ptr_t vmmap_alloc_page(enum MEMPROT prot, ptr_t flags);

int vmmap_map_page(ptr_t vaddr);
int vmmap_map_pages(ptr_t vaddr, int pages);
void vmmap_unmap(ptr_t vaddr);
void vmmap_unmap_pages(ptr_t vaddr, int pages);

// ---------------------- thread.c ------------------------ //
int init_threads();
struct thread* new_thread_kernel(struct process*, ptr_t, ptr_t, bool user, bool addlist);

ptr_t thread_mmap_mem(void* addr, size_t length, enum MEMPROT prot, int flags, bool ins);
//int thread_proc_keepalive(void);
int thread_create_driver_thread(struct thread_fd_open* fdo, ptr_t entry, int sysno, int num, ...);
int thread_new_main(void);
int mmu_create_linear(ptr_t start, ptr_t end);
int thread_downtick(void);
int thread_write(int fd, const void* buf, size_t count);
int thread_wait_tid(int tid, bool sched, bool lockheld);
int thread_get_tid(void);
int thread_tick_sleep(int ticks);
int thread_ms_sleep(ptr_t ms);
int thread_sleep(ptr_t seconds);
int thread_schedule_next(ptr_t);
int thread_exit(ptr_t ret);
int thread_ready(void);
int thread_add_ready(struct thread* t, bool front, bool lockheld);
int thread_read(int fd, void* buf, size_t count);
int thread_wakeup(int tid, ptr_t res);
int thread_yield(void);
int thread_open(const char* name, int flags, int mode);
int thread_munmap(void* addr);
ptr_t thread_mmap(void* addr, size_t length, int prot, int flags, int fd);
int thread_fcntl(int fd, ptr_t cmd, ptr_t arg);
int thread_read(int fd, void* buf, size_t count);
int thread_close(int fd);
int thread_dup(int fd);
int thread_getchar(int fd);
int thread_putchar(int fd, int c);
int thread_lseek(int fd, off_t offset, int whence);
int thread_configure(ptr_t cmd, ptr_t arg);
int process_configure(ptr_t cmd, ptr_t arg);
int thread_fstat(int fd, struct stat* statbuf);
int thread_fork(void);
struct vfsopen* thread_find_fd(int fd);
int thread_close_all(struct process* p);
ptr_t thread_get_upgd(struct thread* t);
bool thread_access_valid(int sysno);
int thread_set_filter(sysfilter_t filter);
sysfilter_t thread_get_filter(void);
int thread_getuser(struct user_id* user);
int thread_setuser(struct user_id* user);

#define VFS_JOB_READ  1
#define VFS_JOB_WRITE 2
struct readwritev {
	struct iovec* iov;
	struct vfsopen* open;
	int iovcnt;
	int current;
	int job;
	size_t retval;
};

typedef int (*vjob_perform)(struct vfsopen*,void*,size_t);

// -------------------------- elf-load.c --------------------- //
struct loaded_exe* elf_load(ptr_t*, void* addr);


// -------------------------- power.c ------------------------- //
void kern_poweroff(bool force);

// -------------------------- clibintegration.c --------------- //

void* __sbrk(int increment, bool user, struct sbrk* brk);
void* _usbrk(int increment);
void* _sbrk(int increment);
int _isatty(int fd);
ssize_t _write(int fd, const void* buf, size_t count);
ssize_t _read(int fd, void* buf, size_t count);
off_t _lseek(int fd, off_t offset, int whence);
int _fstat(int fd, struct stat *statbuf);
int _close(int fd);
double __trunctfdf2(long double a);



// ----------------------- cmdline.c -------------------------- //
char* cmdarg_value(const char* key);


// ------------------------ vfs.c ----------------------------- //
int device_register(struct fs_struct* dev);
int device_unregister(struct fs_struct* dev);
bool vfs_functions_valid(struct fs_struct* fs, bool user);

int uart_early_init();


// ---------------------- signal.c ----------------------------- //
/*
struct sigstack {
	void *ss_sp;
	size_t ss_size;
	int ss_flags;
};
typedef struct sigstack stack_t;
struct siginfo {
	int si_signo;
	int si_code;
	int si_errno;
};
typedef struct siginfo siginfo_t;
//typedef int sigset_t;
struct sigaction {
	void (*sa_handler)(int);
	void (*sa_sigaction)(int, siginfo_t *, void *);
	struct sigset sa_mask;
	int sa_flags;
	void (*sa_restorer)(void);
};

union sigval {
	int sival_int;
	void* sival_ptr;
};
*/

void memory_error(ptr_t addr, ptr_t ip, bool user, bool instr, bool write);

struct iovec* copy_iovec_from_user(const struct iovec* iov, int iovcnt);
struct readwritev* create_kernel_iov(const struct iovec* iov, int iovcnt, int job);
bool iovec_validate_addrs(const struct iovec* iov, int iovcnt);

#if defined(CONFIG_DRIVER_USERID_AUTO_INCREMENT)
extern int last_driver_uid;
#endif
static inline uid_t driver_uid(void)	{
#if defined(CONFIG_DRIVER_USERID_AUTO_INCREMENT)
	return last_driver_uid++;
#else
	return USERID_ROOT;
#endif
}
static inline gid_t driver_gid(void)	{
	return USERID_ADM;
}


void call_inits(ptr_t start, ptr_t stop);

struct process* cuse_get_process(struct fs_struct* fs);

#if defined(CONFIG_KASAN)
void kasan_init(void);
void kasan_mark_valid(ptr_t addr, ptr_t len);
//void bugprintf(const char* fmt, ...);
void kasan_free(void* addr);
void kasan_malloc(void* addr, size_t size);
void kasan_print_allocated(void);
void kasan_never_freed(void* addr);
#endif

int kern_write(char* buf, size_t count);

#endif
