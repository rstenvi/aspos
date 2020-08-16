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
	* The which returned BLOCK_THREAD is responsible for waking up the thread.
	*/
	BLOCK_THREAD,


	SPACE_FULL,

	SPACE_EMPTY,

	USER_FAULT,

	USER_WAKEUP,
};

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

#define ERR_ADDR_PTR(num) (void*)(num)

#define PTR_IS_ERR(ptr) (((void*)ptr == (void*)-1) || (ptr == NULL))

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



// ------------------------ xifo.c ---------------------------- //
int xifo_init(struct XIFO* xifo, size_t max, size_t increment);
struct XIFO* xifo_alloc(size_t max, size_t increment);
int xifo_push_back(struct XIFO* xifo, void* v);
int xifo_push_front(struct XIFO* xifo, void* v);
void* xifo_pop_back(struct XIFO* xifo);
void* xifo_pop_front(struct XIFO* xifo);
size_t xifo_count(struct XIFO* xifo);

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
	void* data;
	size_t len;
	size_t nextfree;
	volatile uint8_t lock;
};

struct ringbuf* ringbuf_alloc(size_t sz);
void* ringbuf_get_data(struct ringbuf* rb, size_t len);


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





// ------------------------ Syscalls ------------------------------- //
int yield(void);
int tsleep(int ticks);
int msleep(uint64_t ms);
int new_thread(uint64_t entry, int count, ...);
int dup(int oldfd);
int get_char(int fd);
int put_char(int fd, int c);

// ---------------------------- network.c -------------------------- //



#endif
