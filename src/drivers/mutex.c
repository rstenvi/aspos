/**
* Mutex implementation for user-mode where the process will be put to sleep if
* another process is holding the mutex.
*
* The mutexes are anonymous and accessed via a file descriptor.
*/

#include "kernel.h"
#include "vfs.h"
#include "lib.h"

int mutex_putchar(struct vfsopen* o, int c);
int mutex_open(struct vfsopen* n, const char* name, int flags, int mode);

struct mutex_user {
	mutex_t metalock;
	mutex_t lock;
	int holding;

	int numwaiting, maxwaiting;
	int* waiting;
};

static struct fs_struct mutexuser = {
	.name = "mutex",
	.open = mutex_open,
	.putc = mutex_putchar,
	.perm = ACL_PERM(ACL_WRITE, ACL_WRITE, ACL_WRITE),
};

int mutex_open(struct vfsopen* n, const char* name, int flags, int mode)	{
	int ret = OK;
	struct mutex_user* u = (struct mutex_user*)kmalloc( sizeof(struct mutex_user) );
	if(PTR_IS_ERR(u))	{
		ret = -MEMALLOC;
		goto fail0;
	}

	mutex_clear(&u->metalock);
	mutex_clear(&u->lock);

	u->waiting = NULL;
	u->numwaiting = u->maxwaiting = 0;

	if(FLAG_SET(flags, MUTEX_FLAG_HOLD))	{
		mutex_acquire(&u->lock);
		u->holding = current_tid();
	}

	n->data = (void*)u;
	return n->fd;


fail1:
	kfree(u);
fail0:
	return ret;
}

#define ACQUIRE(c) (c!=0)
#define RELEASE(c) (c==0)

static int mutex_add_waiting(struct mutex_user* u, int tid)	{
	if(u->numwaiting == u->maxwaiting)	{
		u->maxwaiting += 4;
		u->waiting = (int*)krealloc(u->waiting, u->maxwaiting * sizeof(int));
		if(PTR_IS_ERR(u->waiting))	return -MEMALLOC;
	}
	u->waiting[u->numwaiting++] = tid;
	return OK;
}

static int mutex_wakeup_last(struct mutex_user* u)	{
	if(u->numwaiting > 0)	{
		// At this point we assume that the mutex has just been free'd and
		// therefore there isn't any problem in doing busy waiting when
		// acquiring the mutex

		// Get the tid we are waking up and set that tid to holding
		int tid = u->waiting[--(u->numwaiting)];
		u->holding = tid;
		mutex_acquire(&u->lock);

		// Return OK to indicate that thread has acquired the mutex
		thread_wakeup(tid, OK);
	}
	return OK;
}

int mutex_putchar(struct vfsopen* o, int c)	{
	struct mutex_user* u = (struct mutex_user*)o->data;
	int res = OK;

	// Busy waiting on metalock
	mutex_acquire(&u->metalock);
	
	if(ACQUIRE(c)) {
		if(mutex_try_acquire(&u->lock) != OK)	{
			res = mutex_add_waiting(u, current_tid());
			if(res == OK)	res = -BLOCK_THREAD;
		}
	}
	else if(RELEASE(c)) {
		mutex_release(&u->lock);

		// Wakeup if anyone is waiting for it
		res = mutex_wakeup_last(u);
	}
	mutex_release(&u->metalock);
	return res;
}

int init_mutex(void)	{
	device_register(&mutexuser);
}

driver_init(init_mutex);
