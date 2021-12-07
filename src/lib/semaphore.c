#include "lib.h"

int sem_init(struct semaphore* sem, int count)	{
	sem->sem = count;
	mutex_clear(&(sem->lock));
	return OK;
}

struct semaphore* sem_new(int count)	{
	TMALLOC(n, struct semaphore);
	if(PTR_IS_ERR(n))	return ERR_ADDR_PTR(-MEMALLOC);

	sem_init(n, count);

	return n;
}

int sem_signal(struct semaphore* sem)	{
	mutex_acquire( &(sem->lock) );
	sem->sem++;
	mutex_release( &(sem->lock) );
	return OK;
}

int sem_try_wait(struct semaphore* sem)	{
	int res = -1;
	mutex_acquire( &(sem->lock) );
	if(sem->sem > 0)	res = --(sem->sem);
	mutex_release( &(sem->lock) );

	return res;
}

int sem_wait(struct semaphore* sem)	{
	int res;
	while( (res = sem_try_wait(sem)) < 0)	{
		// Should try and save some resources here
	}
	return OK;
}

int sem_free(struct semaphore* sem)	{
	kfree(sem);
	return OK;
}
