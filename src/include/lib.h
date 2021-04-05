#ifndef __LIB_H
#define __LIB_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"


#define STDIN  0
#define STDOUT 1
#define STDERR 2

#define FLAG_SET(val,flag) ((val & (flag)) == (flag))

#define IS_ALIGNED_POW2(val) ((val & (val - 1)) == 0)
#define ALIGN_UP_POW2(num,val) { if(num == 0)	num = val; if((num % val) != 0)	{ num |= (val - 1); num++; } }
#define ALIGN_DOWN_POW2(num,val) { if(num != 0 && (num % val) != 0) { num &= ~(val-1); } }

#define MIN(a,b) ((a < b) ? a : b)
#define MAX(a,b) ((a > b) ? a : b)

#define TMALLOC(name,type) \
	type* name = (type*)malloc( sizeof(type) );
#define TZALLOC(name,type) \
	TMALLOC(name,type) \
	if(!PTR_IS_ERR(name)) {\
		memset(name, 0x00, sizeof(*name)); \
	}

#define TMALLOC_ERR(name,type) \
	type* name = (type*)malloc( sizeof(type) ); \
	if(name == NULL)	{ return -(MEMALLOC); }
#define TZALLOC_ERR(name,type) \
	TMALLOC_ERR(name,type) \
	memset(name, 0x00, sizeof(*name));

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


	SPACE_FULL,

	SPACE_EMPTY,

	USER_FAULT,

	USER_WAKEUP,

	UNSUPPORTED_FUNC,
	ERROR_LAST,
};

#define ERR_ADDR_PTR(num) (void*)(num)
#define PTR_IS_ERR(ptr)   (((void*)ptr > (void*)(-ERROR_LAST)) || (ptr == NULL))
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

// ----------------------- Various structs ------------------- //
struct bm {
	void* bm;
	unsigned long bytes;
	mutex_t lock;
};


struct XIFO {
	void** items;
	size_t max, first, last, increment;
	mutex_t lock;
};


#define __utext __attribute__((__section__(".user.text")))
#define __udata __attribute__((__section__(".user.data")))


// -------------------- Inlined functions ---------------------- //

static inline void* xalloc(size_t sz) {
	void* ret;
	if((ret = malloc(sz)) == NULL)	{
		printf("Unable to allocate memory\n");
		while(1);
	}
	return ret;
}


// -------------------------- bitmap.c ----------------------- //
int bm_create_fixed(struct bm* bm, ptr_t addr, unsigned long bytes);
struct bm* bm_create(unsigned long bytes);
signed long bm_get_first(struct bm* bm);
void bm_clear(struct bm* bm, long idx);
void bm_set(struct bm* bm, int from, int to);
signed long bm_get_first_num(struct bm* bm, int num);
bool bm_index_free(struct bm* bm, int idx);
bool bm_index_taken(struct bm* bm, int idx);


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


// ----------------------------- spinlock.c ------------------- //

int mutex_acquire(volatile uint8_t* lock);
int mutex_try_acquire(volatile uint8_t* lock);
int mutex_release(volatile uint8_t* lock);
int mutex_clear(volatile uint8_t* lock);




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



// -------------------- ringbuf.c ----------------------------- //

struct ringbuf {
	void* start;
	size_t maxlen;
	size_t cidx, lidx;
	volatile uint8_t lock;
	bool full;
};

struct ringbuf* ringbuf_alloc(size_t sz);
int ringbuf_read(struct ringbuf* rb, void* to, int size);
int ringbuf_write(struct ringbuf* rb, void* from, int size);

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
int dup(int oldfd);
int get_char(int fd);
int put_char(int fd, int c);
int wait_tid(int tid);
int get_tid(void);
int conf_thread(ptr_t,ptr_t);
int poweroff(void);
//int afstat(int fd, void* statbuf);
//int fcntl(int fd, ptr_t cmd, ptr_t arg);
/*
size_t lseek(int fd, size_t offset, int whence);
int read(int fd, void* buf, size_t max);
int write(int fd, void* buf, size_t max);
int close(int fd);
*/


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


#define CUSE_SET_FS_OPS 1
#define CUSE_REGISTER   2
#define CUSE_UNREGISTER 3
#define CUSE_DETACH     4
#define CUSE_SET_FUNC_EMPTY 5
#define CUSE_MOUNT      6


#define CONSOLE_FCNTL_MODE (1)

enum CHARDEV_MODE {
    CHAR_MODE_BYTE = 0,
    CHAR_MODE_LINE,
    CHAR_MODE_LINE_ECHO,
};


// These are user only
struct fs_struct;
int init_dev_null(bool detach);
int cuse_mount(struct fs_struct* fs, const char* mnt, bool detach);
int seek_read(int fd, void* buf, size_t len, size_t off);
int seek_write(int fd, void* buf, size_t len, size_t off);
int init_proc(bool detach);
int init_ustart(const char* mnt, int blockfd);

#endif
