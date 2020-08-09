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

#define __noreturn __attribute__((noreturn))

#define STDIN  0
#define STDOUT 1
#define STDERR 2



#define THREAD_STACK_BOTTOM(tid) \
	(ARM64_VA_THREAD_STACKS_START + (PAGE_SIZE * (CONFIG_THREAD_STACK_BLOCKS * ntid)))
#define THREAD_STACK_TOP(tid) \
	(THREAD_STACK_BOTTOM(tid) + (CONFIG_THREAD_STACK_BLOCKS * PAGE_SIZE))

#define FLAG_SET(val,flag) ((val & (flag)) == (flag))

// kstart.c
extern struct os_data osdata;

void panic(const char*, const char*, int);
#define PANIC(msg) panic(msg, __FILE__, __LINE__)

#define MIN(a,b) ((a < b) ? a : b)
#define MAX(a,b) ((a > b) ? a : b)


/*
typedef void* (*net_type_init_t)(size_t*);
typedef void* (*net_type_optset_t)(void*,size_t*,ptr_t,ptr_t);
typedef int (*net_type_finalize_t)(void*,size_t,size_t);
typedef int (*net_type_transport_t)(struct vecbuf*,uint16_t,uint16_t);
typedef int (*net_type_net_t)(struct vecbuf*,char*,char*);
typedef int (*net_type_link_t)(void*,size_t,struct vecbuf*);
*/

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

struct NetConfig {
	ipv4_t addr, gw, dhcpaddr;
	ipv4_t dnsserver[2];
	ipv4_t netmask;
	uint8_t mac[6];
};

/*
struct network_cb {
	net_type_init_t init;
	net_type_optset_t optset;
	net_type_finalize_t finalize;
};*/

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
	volatile uint8_t lock;
};

struct sbrk {
	void* addr;
	size_t curroffset, numpages, mappedpages;
	volatile uint8_t lock;
};

struct process {
	struct sbrk ubrk;
	ptr_t user_pgd;
};

struct tlist;


/**
* Information we store about a thread.
*/
struct thread {
	tid_t id;
	ptr_t ustack;
	ptr_t kstack;
	ptr_t stackptr;
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
	* Information associated with a process / address space.
	* 
	* If the system is modified in the future to support multiple processes,
	* most of the information that needs to changed is stored in this struct.
	*/
	struct process proc;

	/** Lock which determines if any CPU is working on threads. */
	volatile uint8_t lock;
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

	// The 
	ptr_t vaddrstart;

	// Number of blocks we control
	ptr_t blocks;
};

enum cpu_state {
	DEFAULT = 0,
	RUNNING,
	BUSYLOOP,
};


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
	volatile uint8_t readylock;

	/** Current state of the CPU */
	enum cpu_state state;
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

	struct bm* fileids;

	volatile uint8_t loglock;
};


static inline int fileid_unique(void)	{
	int r = bm_get_first(osdata.fileids);
	if(r < 0)	return r;

	return r;
}
static inline void fileid_free(int id)	{
	bm_clear(osdata.fileids, id - 3);
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

static inline volatile uint8_t* cpu_loglock() { return &(osdata.loglock); }
static inline struct dtb_node* cpu_get_parsed_dtb() { return osdata.dtbroot; }
static inline struct pmm* cpu_get_pmm() { return &(osdata.pmm); }
static inline struct sbrk* cpu_get_kernbrk() { return &(osdata.kernbrk); }
static inline void* cpu_get_dtb() { return osdata.dtb; }
static inline ptr_t cpu_get_pgd() { return osdata.kpgd; }
static inline ptr_t cpu_get_user_pgd() { return osdata.upgd; }
static inline struct threads* cpu_get_threads() { return &(osdata.threads); }
static inline ptr_t cpu_linear_offset() { return osdata.linear_offset; }
static inline struct vmmap* cpu_get_vmmap() { return &(osdata.vmmap); }

static inline struct cpu* curr_cpu() { return &(osdata.cpus.cpus[cpu_id()]); }

static inline int current_tid(void) {
	return osdata.cpus.cpus[cpu_id()].running->id;
}

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


#define ALIGN_UP_POW2(num,val) { if(num == 0)	num = val; if((num % val) != 0)	{ num |= (val - 1); num++; } }
#define ALIGN_DOWN_POW2(num,val) { if(num != 0 && (num % val) != 0) { num &= ~(val-1); } }


#define ASSERT_TRUE(cond,msg) if( !(cond) ) { PANIC(msg); }
#define ASSERT_FALSE(cond,msg) if( (cond) ) { PANIC(msg); }


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

void dtb_second_pass(struct dtb_node* root);
struct dtb_node* dtb_parse_data(void* dtb);
struct dtb_node* dtb_find_name(const char* n, bool exact, int skip);
uint32_t* dtb_get_ints(struct dtb_node* node, const char* name, int* count);
const char* dtb_get_string(struct dtb_node* node, const char* name);
int dtb_get_as_reg(struct dtb_node* node, ptr_t* outaddr, ptr_t* outlen);
uint32_t dtb_get_int(struct dtb_node* node, const char* name);
int dtb_get_interrupts(struct dtb_node* node, uint32_t* type, uint32_t* nr, uint32_t* flags);

// ----------------------- pmm.c ---------------------- //
int pmm_init();
ptr_t pmm_alloc(int pages);
int pmm_mark_mem(ptr_t start, ptr_t end);
void pmm_free(ptr_t page);


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

// ---------------------- thread.c ------------------------ //
int init_threads();
struct thread* new_thread_kernel(ptr_t, bool user, bool addlist);

int thread_new_main(ptr_t entry);
int mmu_create_linear(ptr_t start, ptr_t end);
int thread_downtick(void);
int thread_tick_sleep(int ticks);
int thread_ms_sleep(ptr_t ms);
int thread_sleep(ptr_t seconds);
int thread_schedule_next(void);
int thread_exit(ptr_t ret);
int thread_ready(void);
int thread_read(int fd, void* buf, size_t count);
int thread_wakeup(int tid, ptr_t res);
int thread_yield(void);
int thread_open(const char* name, int flags, int mode);
int thread_read(int fd, void* buf, size_t count);
int thread_close(int fd);
int thread_dup(int fd);

// -------------------------- elf-load.c --------------------- //
ptr_t elf_load(void* addr);


// -------------------------- power.c ------------------------- //
void poweroff(void);

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


/**
* todo: Should have a separate subfs for devices under /dev/
*/
static inline int device_register(struct fs_struct* dev)	{
	struct fs_component* d = &(osdata.root);
	if(d->currdevs >= d->maxdevs)	{
		d->maxdevs += 10;
		d->subfs = (struct fs_struct**)realloc(d->subfs, sizeof(void*) * d->maxdevs);
		ASSERT_TRUE(d->subfs != NULL, "Unable to allocate space for devices");
	}
	d->subfs[d->currdevs++] = dev;
	return OK;
}

int uart_early_init();

#endif
