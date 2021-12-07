#include "kernel.h"
#include "vfs.h"

int semaphore_putchar(struct vfsopen* o, int c);
int semaphore_open(struct vfsopen* n, const char* name, int flags, int mode);
int semaphore_close(struct vfsopen* n);

struct semaphore_user {
	int semcount;
	mutex_t metalock;
	struct semaphore sem;
	int holding;

	int numwaiting, maxwaiting;
	int* waiting;
};

static struct fs_struct semaphoreuser = {
	.name = "semaphore",
	.open = semaphore_open,
	.putc = semaphore_putchar,
	.close = semaphore_close,
	.perm = ACL_PERM(ACL_WRITE, ACL_WRITE, ACL_WRITE),
};
int semaphore_close(struct vfsopen* n)	{
	GET_VFS_DATA(n, struct semaphore_user, u);
	if(PTR_IS_VALID(u))	{
		if(PTR_IS_VALID(u->waiting))	{
			kfree(u->waiting);
		}
		kfree(u);
	}
	return OK;
}

int semaphore_open(struct vfsopen* n, const char* name, int flags, int mode)	{
	int ret = OK;
	TZALLOC(u, struct semaphore_user);
	if(PTR_IS_ERR(u))	{
		ret = -MEMALLOC;
		goto fail0;
	}

	// Use mode as initial count
	sem_init(&(u->sem), mode);

	mutex_clear(&(u->metalock));

	u->waiting = NULL;
	u->numwaiting = u->maxwaiting = 0;
	n->data = (void*)u;
	return n->fd;
fail0:
	return ret;
}

#define SEM_WAIT(c) (c!=0)
#define SEM_SIGNAL(c) (c==0)

static int semaphore_add_waiting(struct semaphore_user* u, int tid)	{
	if(u->numwaiting == u->maxwaiting)	{
		u->maxwaiting += 4;
		u->waiting = (int*)krealloc(u->waiting, u->maxwaiting * sizeof(int));
		if(PTR_IS_ERR(u->waiting))	return -MEMALLOC;
	}
	u->waiting[u->numwaiting++] = tid;
	return OK;
}

static int semaphore_wakeup_last(struct semaphore_user* u)	{
	int res;
	if(u->numwaiting > 0)	{
		int tid = u->waiting[u->numwaiting - 1];

		// Try and wait, if we have a free resource we wake it up
		res = sem_try_wait(&u->sem);
		if(res >= 0)	{
			u->numwaiting--;
			thread_wakeup(tid, res);
		}
	}
	return OK;
}

int semaphore_putchar(struct vfsopen* o, int c)	{
	struct semaphore_user* u = (struct semaphore_user*)o->data;
	int res = OK;

	// We still need a global lock, despite the semaphore having a separate
	// lock. Otherwise we might wait and block and then at the same time get a
	// signal on a different CPU. If there are no more signals, the waiting
	// thread will never wakeup.
	mutex_acquire(&(u->metalock));
	if(SEM_WAIT(c)) {
		res = sem_try_wait(&(u->sem));
		if(res < 0)	{
			if((res = semaphore_add_waiting(u, current_tid())) == OK)	{
				res = -BLOCK_THREAD;
			}
		}
	}
	else if(SEM_SIGNAL(c)) {
		sem_signal(&(u->sem));
		semaphore_wakeup_last(u);
	}
	mutex_release(&(u->metalock));
	return res;
}

int init_semaphore(void)	{
	return device_register(&semaphoreuser);
}

driver_init(init_semaphore);
