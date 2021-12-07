#ifndef __LIB_H
#define __LIB_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "types.h"
#include "acl.h"
#include "vfs.h"

#define CONFIG_USER_THREAD_INFO 1


#define STDIN  0
#define STDOUT 1
#define STDERR 2


#define __force_inline __attribute__((always_inline))
#define __noreturn __attribute__((noreturn))
#define __unusedvar __attribute__((unused))

#define FLAG_SET(val,flag) ((val & flag) == flag)

//#define GET_ALIGNED_UP_POW2(num,val) (num + (val-1) & ((1<<val)-1))

#define GET_ALIGNED_UP_POW2(num,val) ((num + (val-1)) & ~(val-1))
#define GET_ALIGNED_DOWN_POW2(num,val) (num & (~((val-1))))
#define IS_ALIGNED_POW2(val) ((val & (val - 1)) == 0)
#define ALIGN_UP_POW2(num,val) { if(num == 0)	num = val; if((num % val) != 0)	{ num |= (val - 1); num++; } }
#define ALIGN_DOWN_POW2(num,val) { if(num != 0 && (num % val) != 0) { num &= ~(val-1); } }
#define ALIGNED_ON_POW2(num,align) ((num & (align-1)) == 0)

#define PTR_ALIGNED1(va) (true)
#define PTR_ALIGNED2(va) (GET_ALIGNED_DOWN_POW2(va, 2) == va)
#define PTR_ALIGNED4(va) (GET_ALIGNED_DOWN_POW2(va, 4) == va)
#define PTR_ALIGNED8(va) (GET_ALIGNED_DOWN_POW2(va, 8) == va)

#define PTR_ALIGNED(va) PTR_ALIGNED8(va)

#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#define MAX(a,b) (((a) > (b)) ? (a) : (b))

#define ALIGNED_PAGE(num) (GET_ALIGNED_DOWN_POW2(num, PAGE_SIZE) == num)
#define IS_ALIGNED_ON(num,align) (GET_ALIGNED_DOWN_POW2(num,align) == num)
#define GET_ALIGNED_PAGE_UP(num) GET_ALIGNED_UP_POW2(num, PAGE_SIZE)
#define GET_ALIGNED_PAGE_DOWN(num) GET_ALIGNED_DOWN_POW2(num, PAGE_SIZE)

/** Hold mutex after open */
#define MUTEX_FLAG_HOLD (1 << 0)

#define MUTEX_RELEASE 0
#define MUTEX_ACQUIRE 1


#define SEMAPHORE_WAIT   1
#define SEMAPHORE_SIGNAL 0


// ----------------------- Various enums --------------------- //

/**
* On error, the return value is alwas negative. In other words, it should be the
* negative equivalent to what is listed in the enum.
*/
enum RETURN {
	/** Successful result */
	OK = 0,

	/**
	* Unspecified fault, generally used when it's not necessary to specify what
	* the error was. I.e. only one error is possible.
	*/
	GENERAL_FAULT,

	/** It was not possible to allocate memory. */
	MEMALLOC,

	/** The function performed no change. */
	NOCHANGE,

	/** HW error or surprising result from HW */
	HW_ERROR,


	/**
	* Used by drivers to indicate that the request is blocked by hardware and
	* the thread manager should put the thread into a blocking state.
	*
	* The driver which returned BLOCK_THREAD is responsible for waking up the thread.
	*/
	BLOCK_THREAD,
	BLOCK_THREAD_ID,


	SPACE_FULL,

	SPACE_EMPTY,

	USER_FAULT,

	USER_WAKEUP,

	UNSUPPORTED_FUNC,

	NO_ACCESS,
	ERROR_LAST,
};

#define ERR_ADDR_PTR(num) (void*)(num)
#define PTR_IS_ERR(ptr)   (((void*)ptr > (void*)(-ERROR_LAST)) || ((void*)ptr == NULL))
#define PTR_IS_VALID(ptr) (!PTR_IS_ERR(ptr))
#define PTR_TO_ERRNO(ptr) (ptr == NULL) ? -GENERAL_FAULT : (int)((ptr_t)(ptr))

#define OPT_DATALINK_BIT  (1 << 25)
#define OPT_NETWORK_BIT   (2 << 25)
#define OPT_TRANSPORT_BIT (4 << 25)
#define OPT_FLAG_MASK     ((1 << 25)-1)

#define OPT_DST                   1
#define OPT_SRC                   2
#define OPT_PAYLOAD_LEN           3
#define OPT_PAYLOAD_NEXT_PROTOCOL 4


enum NET_DOMAIN {
	AF_INET = 0,
	AF_STOP,
};

enum NET_TYPE {
	SOCK_DGRAM = 0,
	SOCK_STOP,
	SOCK_STREAM,
};

enum JOB_TYPE {
	JOB_NONE = 0,
	JOB_OPEN,
	JOB_READ,
	JOB_WRITE,
	JOB_FCNTL,
};

// ----------------------- Various structs ------------------- //
struct bm {
	void* bm;
	unsigned long bytes;
	mutex_t lock;
};

struct vec_item {
	void* item;
	long key;
};
struct Vec {
	mutex_t lock;
	int citems, aitems;
	struct vec_item* items;
};
struct Vec* vec_init(size_t items);
int vec_insert(struct Vec* vec, void* ins, long key);
void* vec_find(struct Vec* vec, long key);
void* vec_remove(struct Vec* vec, long key);
void* vec_remove_last(struct Vec* vec);
void* vec_index(struct Vec* vec, int idx);
int vec_modkey(struct Vec* vec, int idx, long key);
int vec_destroy(struct Vec* vec);

struct XIFO {
	void** items;
	size_t max, first, last, increment;
	mutex_t lock;
};

#define __no_ubsan __attribute__((no_sanitize("undefined")))
#define __no_asan __attribute__((no_sanitize("address")))
#define __utext __attribute__((__section__(".user.text")))
#define __udata __attribute__((__section__(".user.data")))


// -------------------- Inlined functions ---------------------- //
/*
static inline void* xalloc(size_t sz) {
	void* ret;
	if((ret = kmalloc(sz)) == NULL)	{
		printf("Unable to allocate memory\n");
		while(1);
	}
	return ret;
}*/


// -------------------------- bitmap.c ----------------------- //
int bm_create_fixed(struct bm* bm, ptr_t addr, size_t bytes);
struct bm* bm_create(unsigned long bytes);
signed long bm_get_first(struct bm* bm);
void bm_clear(struct bm* bm, size_t idx);
void bm_set(struct bm* bm, size_t from, size_t to);
signed long bm_get_first_num(struct bm* bm, size_t num);
bool bm_index_free(struct bm* bm, size_t idx);
bool bm_index_taken(struct bm* bm, size_t idx);
void bm_delete(struct bm* bm);
void bm_clear_nums(struct bm* bm, size_t idx, int count);

// ------------------------ xifo.c ---------------------------- //
int xifo_init(struct XIFO* xifo, size_t max, size_t increment);
struct XIFO* xifo_alloc(size_t max, size_t increment);
int xifo_push_back(struct XIFO* xifo, void* v);
int xifo_push_front(struct XIFO* xifo, void* v);
void* xifo_pop_back(struct XIFO* xifo);
void* xifo_pop_front(struct XIFO* xifo);
void* xifo_peep_front(struct XIFO* xifo);
void* xifo_peep_back(struct XIFO* xifo);
size_t xifo_count(struct XIFO* xifo);
void* xifo_search(struct XIFO* xifo, void* val, bool (*search)(void*,void*));
void* xifo_item(struct XIFO* xifo, size_t idx);
void xifo_delete(struct XIFO* xifo);

#define XIFO_LOCK(xifo)   mutex_acquire(&xifo->lock);
#define XIFO_UNLOCK(xifo) mutex_release(&xifo->lock);
//#define for_xifo(xifo,i) for(i = xifo->first; i < xifo->last; i++)


// ------------------------ string.c --------------------- //

int char_in_string(const char* s, char c);


// ------------------------------ tlist.c -------------------- //

struct tlist* tlist_new(void);
void* tlist_downtick(struct tlist* t);
void* tlist_more_zero(struct tlist* t);
int tlist_add(struct tlist* t, void* data, int64_t ticks);
int tlist_empty(struct tlist* list);
void tlist_delete(struct tlist* tl);
int tlist_remove(struct tlist* t, void* remove);

// ----------------------------- spinlock.c ------------------- //

int mutex_acquire(volatile uint8_t* lock);
int mutex_try_acquire(volatile uint8_t* lock);
int mutex_release(volatile uint8_t* lock);
int mutex_clear(volatile uint8_t* lock);
bool mutex_held(mutex_t lock);



// -------------------------- llist.c ------------------------ //

struct llist_item {
	long key;
	void* data;
	struct llist_item* next;
};

struct llist {
	struct llist_item* head;
	int count;
	mutex_t lock;
};


struct llist* llist_alloc(void);
int llist_insert(struct llist* list, void* item, long key);
void* llist_remove(struct llist* list, long key);
void* llist_find(struct llist* list, long key);
void* llist_first(struct llist* list, bool remove, long* key);
void llist_delete(struct llist* list);
bool llist_empty(struct llist* list);
void* llist_index(struct llist* list, int idx);

// -------------------- ringbuf.c ----------------------------- //

struct ringbuf {
	void* start;
	size_t maxlen;
	size_t cidx, lidx;
	volatile uint8_t lock;
	bool full;
};

struct ringbuf* ringbuf_alloc(size_t sz);
int ringbuf_read(struct ringbuf* rb, void* to, size_t size);
int ringbuf_write(struct ringbuf* rb, void* from, size_t size);
void ringbuf_delete(struct ringbuf* rb);

// ----------------------- semaphore.c ------------------------ //

struct semaphore {
	mutex_t lock;
	int sem;
};

int sem_init(struct semaphore* sem, int count);
struct semaphore* sem_new(int count);
int sem_signal(struct semaphore* sem);
int sem_try_wait(struct semaphore* sem);
int sem_wait(struct semaphore* sem);
int sem_free(struct semaphore* sem);


// --------------------------- msgqueue.c -------------------------- //
struct mq;
struct mq* mq_new(size_t max);
int mq_init(struct mq* mq, size_t max);
int mq_send(struct mq* mq, void* msg);
void* mq_try_recv(struct mq* mq);
void* mq_recv(struct mq* mq);



// ------------------------ Syscalls ------------------------------- //
int yield(void);
int tsleep(int ticks);
int msleep(uint64_t ms);
int new_thread(uint64_t entry, int count, ...);
int exit_thread(int);
//int proc_keepalive(void);
int dup(int oldfd);
int get_char(int fd);
int put_char(int fd, int c);
int wait_tid(int tid);
int wait_pid(int pid);
int get_tid(void);
int getpid(void);
int is_mapped(ptr_t);
int conf_thread(ptr_t,ptr_t);
int conf_process(ptr_t,ptr_t);
int poweroff(void);
void* mmap(void* addr, size_t length, int prot, int flags, int fd);
void* _mmap(void* addr, size_t length, int prot, int flags, int fd);
int munmap(void* addr);
int _munmap(void* addr);
//int afstat(int fd, void* statbuf);
//int fcntl(int fd, ptr_t cmd, ptr_t arg);
/*
size_t lseek(int fd, size_t offset, int whence);
int read(int fd, void* buf, size_t max);
int write(int fd, void* buf, size_t max);
int close(int fd);
*/


struct kcov_data {
	uint32_t maxcount, currcount;
	ptr_t entries[0];
};

struct kcov {
    bool enabled;
	uint32_t allocated;
    struct kcov_data* data;
};


/**
* Get a comma-separated list if enabled CPU-features
*/
int cpu_feaures_enabled(char*,size_t);


// LWIP provides its own implementation of iovec
#if !defined(LWIP_USER)
struct iovec {
	void  *iov_base;
	size_t iov_len;
};
#else
struct iovec;
#endif

/*
ssize_t vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags);
ssize_t splice(int fd_in, off_t *off_in, int fd_out, off_t *off_out, size_t len, unsigned int flags);
*/
ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
/*
ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt, off_t offset, int flags);
*/


#define THREAD_CONF_THREAD_EXIT 1
#define THREAD_CONF_EXC_EXIT    2

#define PROC_KEEPALIVE         (100)
#define PROC_STORE_THREAD_INFO (101)
#define PROC_CREATE_BUSYLOOP   (102)


#define CONSOLE_FCNTL_MODE (1)

enum CHARDEV_MODE {
	CHAR_MODE_BYTE = 0,
	CHAR_MODE_LINE,
	CHAR_MODE_LINE_ECHO,
	CHAR_MODE_BINARY,
	CHAR_MODE_LAST,
};


/**
* fcntl-values which should be used by drivers to indicate type of argument.
* When driver is in user-mode, this value is used to remap addresses. If the
* value is a ptr, the physical memory page will be mapped into the driver
* process space as well.
* 
* If the user-mode driver doesn't use this interface, the driver must ensure
* their own memory remapping.
*/

#define FCNTL_PTR_OFFSET (30)
#define FCNTL_PTR_VALUE  (1 << FCNTL_PTR_OFFSET)

#define FCNTL_DIR_OFFSET (29)
#define FCNTL_IN_VALUE  (1 << FCNTL_DIR_OFFSET)
#define FCNTL_OUT_VALUE (0 << FCNTL_DIR_OFFSET)

#define FCNTL_NUM_OFFSET   (23)
#define FCNTL_MAGIC_OFFSET (16)
#define FCNTL_SIZE_OFFSET  (0)
#define _FCNTL_MAX_SIZE    (1 << (FCNTL_MAGIC_OFFSET-FCNTL_SIZE_OFFSET))

#define _FCNTL_ID(ptr,dir,magic,size,num) \
	(ptr << FCNTL_PTR_OFFSET) | \
	(dir << FCNTL_DIR_OFFSET) | \
	(magic << FCNTL_MAGIC_OFFSET) | \
	(size << FCNTL_SIZE_OFFSET) | \
	(num << FCNTL_NUM_OFFSET)

#define FCNTL_ID_PTR_IN(num,magic,size)  _FCNTL_ID(1,1,magic,size,num)
#define FCNTL_ID_PTR_OUT(num,magic,size) _FCNTL_ID(1,0,magic,size,num)
#define FCNTL_ID_IN(num,magic,size)      _FCNTL_ID(0,1,magic,size,num)
#define FCNTL_ID_OUT(num,magic,size)     _FCNTL_IF(0,0,magic,size,num)
#define FCNTL_ID(num,magic)              _FCNTL_ID(0,0,magic,0,num)


#define IPC_MAGIC 'i'
#define IPC_FREE  FCNTL_ID(1, IPC_MAGIC)
#define IPC_ALLOC FCNTL_ID(2, IPC_MAGIC)


#define CUSE_MAGIC  'c'
#define CUSE_SET_FS_OPS     FCNTL_ID_PTR_IN(1, CUSE_MAGIC, sizeof(struct fs_struct))
#define CUSE_REGISTER       FCNTL_ID(2, CUSE_MAGIC)
#define CUSE_UNREGISTER     FCNTL_ID(3, CUSE_MAGIC)
#define CUSE_DETACH         FCNTL_ID(4, CUSE_MAGIC)
#define CUSE_SET_FUNC_EMPTY FCNTL_ID_IN(5, CUSE_MAGIC, sizeof(int))
#define CUSE_MOUNT          FCNTL_ID_PTR_IN(6, CUSE_MAGIC, 0)
#define CUSE_SVC_DONE       FCNTL_ID_IN(7, CUSE_MAGIC, sizeof(int))


#define FCNTL_SHARED_MAGIC 'f'
#define FCNTL_CMD_NON_BLOCK FCNTL_ID(1, FCNTL_SHARED_MAGIC)


#define F_VIRTIO_MAGIC 'v'
#define FCNTL_VIRTIO_SET_CID      FCNTL_ID_IN(1, F_VIRTIO_MAGIC, sizeof(uint32_t))
#define FCNTL_VIRTIO_SET_DST_PORT FCNTL_ID_IN(2, F_VIRTIO_MAGIC, sizeof(uint32_t))
#define FCNTL_VIRTIO_SET_TARGET   FCNTL_ID_IN(3, F_VIRTIO_MAGIC, sizeof(uint64_t))
#define FCNTL_VIRTIO_CONNECT      FCNTL_ID(4, F_VIRTIO_MAGIC)
#define FCNTL_VIRTIO_LISTEN       FCNTL_ID(5, F_VIRTIO_MAGIC)
#define FCNTL_VIRTIO_SET_SRC_PORT FCNTL_ID_IN(6, F_VIRTIO_MAGIC, sizeof(uint32_t))

#define F_KCOV_MAGIC 'k'
#define FCNTL_KCOV_INIT    FCNTL_ID(1, F_KCOV_MAGIC)
#define FCNTL_KCOV_ENABLE  FCNTL_ID(2, F_KCOV_MAGIC)
#define FCNTL_KCOV_DISABLE FCNTL_ID(3, F_KCOV_MAGIC)
#define FCNTL_KCOV_RESET   FCNTL_ID(4, F_KCOV_MAGIC)


#define F_VCONSOLE_MAGIC 'v'
#define FCNTL_VCONSOLE_INIT FCNTL_ID(1, F_VCONSOLE_MAGIC)

#define OPEN_FLAG_READ  (1 << 0)
#define OPEN_FLAG_WRITE (1 << 1)
#define OPEN_FLAG_CREAT (1 << 2)
#define OPEN_FLAG_DIR   (1 << 3)
#define OPEN_FLAG_TRUNC (1 << 4)
#define OPEN_FLAG_CTRL  (1 << 5)
#define OPEN_FLAG_EXEC  (1 << 6)

#define OPEN_FLAG_RW    (OPEN_FLAG_READ | OPEN_FLAG_WRITE)


// These are user only

struct fs_struct;
int init_dev_null(bool detach);
int cuse_mount(struct fs_struct* fs, const char* mnt, bool detach);
int seek_read(int fd, void* buf, size_t len, size_t off);
int seek_write(int fd, void* buf, size_t len, size_t off);
int init_proc(bool detach);
int init_ustart(const char* mnt, int blockfd);


struct user_thread_info {
	tid_t id;
#if defined(CONFIG_KCOV)
	struct kcov_data* caller_kcov;
#endif
};

#if defined(CONFIG_KCOV) && defined(UMODE)
# if CONFIG_USER_THREAD_INFO
extern struct user_thread_info threadinfo;
# endif
__always_inline static inline struct kcov_data* get_current_kcov(void) {
# if CONFIG_USER_THREAD_INFO
	return threadinfo.caller_kcov;
# else
	return NULL;
# endif
}
#endif

#if defined(UMODE)
# define ASSERT_TRUE(cond,msg) 
# define ASSERT(cond) 
# define ASSERT_FALSE(cond,msg)
# define ASSERT_VALID_PTR(ptr)
# define BUG_ASSERT ASSERT
#else
void panic(const char*, const char*, int);
# define PANIC(msg) panic(msg, __FILE__, __LINE__)
# define BUG(msg) panic(msg, __FILE__, __LINE__);
# define ASSERT_TRUE(cond,msg) if( !(cond) ) { PANIC(msg); }
# define ASSERT(cond) ASSERT_TRUE(cond, "")
# define ASSERT_FALSE(cond,msg) if( (cond) ) { PANIC(msg); }
# define ASSERT_VALID_PTR(ptr) ASSERT_FALSE(PTR_IS_ERR(ptr), "ptr invalid")
# define BUG_ASSERT ASSERT
# define ASSERT_USER(u) \
	BUG_ASSERT(PTR_IS_VALID(u)) \
	BUG_ASSERT(ADDR_USER(u))

# define ASSERT_USER_MEM(u,len) \
   BUG_ASSERT(PTR_IS_VALID(u)) \
   BUG_ASSERT(ADDR_USER(u)) \
   BUG_ASSERT(ADDR_USER((ptr_t)u + len))

# define ASSERT_KERNEL(k) \
   BUG_ASSERT(PTR_IS_VALID(k)) \
   BUG_ASSERT(ADDR_KERNEL(k))

# define ASSERT_KERNEL_MEM(k,len) \
   BUG_ASSERT(ADDR_KERNEL(k)) \
   BUG_ASSERT(ADDR_KERNEL((ptr_t)k + len))

# define ADDR_USER_MEM(k,len) (ADDR_USER(k) && ADDR_USER((ptr_t)k + len) )
#endif


#if defined(UMODE)
# define bugprintf printf
#else
# define bugprintf printf
#endif

#define MAP_PROT_NONE  (0)
#define MAP_PROT_READ  (1 << 0)
#define MAP_PROT_WRITE (1 << 1)
#define MAP_PROT_EXEC  (1 << 2)

/**
* Avoid copying the memory region on fork
*/
#define MAP_NON_CLONED (1 << 0)

/**
* Reserve virtual memory, but do not allocate physical pages.
*
* - A read from uninitialized memory will trigger an exception and potentially
*   shut down the program.
* - A write will cause the memory to be mapped in before the write is executed.
*/
#define MAP_LAZY_ALLOC (1 << 1)

/**
* Allocate memory shared between user- and kernel-mode
*/
#define MAP_ALLOC_SHARED (1 << 2)

#if defined(CONFIG_KASAN)
#include "kasan.h"
void kasan_malloc(void* addr, size_t size);
void kasan_free(void* addr);
#endif

__force_inline static inline void* kmalloc(size_t size)	{
#if defined(CONFIG_KASAN)
	int rz_after = KASAN_REDZONE_AFTER + (8 - (size % 8));
	void* ret = malloc(size + KASAN_REDZONE_BEFORE + rz_after);
	kasan_malloc(ret, size);
	return (ret + KASAN_REDZONE_BEFORE);
#else
	return malloc(size);
#endif
}

/*
* TODO: For this to work, we need to store rz_before in kasan-entry
__force_inline static inline void* kcalloc(size_t nmemb, size_t size)	{
# if defined(CONFIG_KASAN)
	int rz_after = size * 2;
	int rz_before = rz_after;

	void* ret = calloc(nmemb + rz_before + rz_after, size);
	kasan_malloc(ret + rz_before);
# else
	return calloc(nmemb, size);
# endif
}
*/
__force_inline static inline void kfree(void* addr)	{
	if(addr == NULL)	return;

#ifndef UMODE
	if(PTR_IS_ERR(addr))	{
		//loge("free pointer: %p\n", addr);
		PANIC("free pointer is invalid\n");
	}
#endif
#if defined(CONFIG_KASAN)
	// kasan is responsible for free-ing the data
	kasan_free(addr);
#else
	free(addr);
#endif
}
__force_inline static inline void* krealloc(void* addr, size_t size)	{
	if(addr == NULL)	return kmalloc(size);

#if defined(CONFIG_KASAN)
	void* naddr;
	int osize = kasan_alloc_size(addr);
	if(osize <= 0)	{
		printf("Unable to find allocated address\n");
		return realloc(addr, size);
	}
	naddr = kmalloc(size);
	if(PTR_IS_ERR(naddr))	return naddr;

	memcpy(naddr, addr, osize);
	kfree(addr);
	return naddr;
#else
	return realloc(addr, size);
#endif
}

#define TMALLOC(name,type) \
	type* name = (type*)kmalloc( sizeof(type) );
#define TZALLOC(name,type) \
	TMALLOC(name,type) \
	if(!PTR_IS_ERR(name)) {\
		memset(name, 0x00, sizeof(*name)); \
	}

#define TMALLOC_ERR(name,type) \
	type* name = (type*)kmalloc( sizeof(type) ); \
	if(name == NULL)	{ return -(MEMALLOC); }
#define TZALLOC_ERR(name,type) \
	TMALLOC_ERR(name,type) \
	memset(name, 0x00, sizeof(*name));


#endif
