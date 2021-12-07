/**
* @file clibintegration.c
* @descrption Interface which newlib uses
*/

#include "kernel.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/times.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <stdio.h>


void* __sbrk(int increment, bool user, struct sbrk* brk)	{
	void* ret = (void*)-1;
	mutex_acquire(&brk->lock);
	if(brk->addr == NULL)	{
		if(!user) PANIC("_sbrk called before being initialized\n");
		goto done;
	}

	if(increment == 0)	{
		ret = (void*)(brk->addr + brk->curroffset);
	}
	else if(increment < 0)	{
		// TODO: Should also free up some memory here UBSAN: value overflow (~) | clibintegration.c:30:25
		if((brk->curroffset + increment) >= 0)	{
			brk->curroffset += increment;
			ret = (void*)(brk->addr + brk->curroffset);
		}
		else	{
			logw("Tried to decrement brk with more than allocated size\n");
			goto done;
		}
	} else {
		long tmp = (long)(brk->curroffset) + (long)increment;
		if(tmp >= INT_MAX)	{
			logw("Tried to increment larger than INT_MAX\n");
			goto done;
		}

		else if(tmp <= (brk->mappedpages* PAGE_SIZE))	{
			ret = (void*)(brk->addr + brk->curroffset);
			brk->curroffset += increment;
			goto done;
		}

		// Inside reserved memory, but not mapped in
		else if( tmp < (brk->numpages * PAGE_SIZE))	{
			// Find number of pages we must allocate
			ptr_t missing = ( brk->curroffset + increment) - (brk->mappedpages * PAGE_SIZE);
			ALIGN_UP_POW2(missing, PAGE_SIZE);
			missing /= PAGE_SIZE;

			if(user)	{
				mmu_map_pages(
					(ptr_t)(brk->addr) + (PAGE_SIZE * brk->mappedpages),
					missing,
					PROT_RW
				);
			}
			else	{
				ptr_t naddr = (ptr_t)brk->addr + (PAGE_SIZE * brk->mappedpages);
				vmmap_map_pages(naddr, missing);
			}
			ptr_t rret = (ptr_t)(brk->addr) + brk->curroffset;
			brk->curroffset += increment;
			brk->mappedpages += missing;
			ret = (void*)(rret);
			goto done;
		}
		else	{
			char* mode = (user) ? "user" : "kernel";
			logw("%s attempted to allocate more memory than reserved\n", mode);
			goto done;
		}
	}
done:
	mutex_release(&brk->lock);
	return ret;
}

void* _usbrk(int increment)	{
	struct process* p = current_proc();
	struct sbrk* brk = &(p->ubrk);
	return __sbrk(increment, true, brk);
}

void* _sbrk(int increment) {
	struct sbrk* brk = cpu_get_kernbrk();
	return __sbrk(increment, false, brk);
}

int _isatty(int fd)	{
	return (fd <= 2);
}


ssize_t _write(int fd, const void* buf, size_t count)	{
	if(fd == STDOUT || fd == STDERR)	{
		kern_write((const char*)buf, count);
	} else {
		PANIC("Unsupported write\n");
	}
	return count;
}


ssize_t _read(int fd, void* buf, size_t count)	{
	PANIC("_read");
	size_t i = 0;
	if(fd <= 2)	{
		for(i = 0; i < count; i++)	{
			if(fd == STDIN)	{
//				tmp[i] = (char)(osdata.kgetc());
			}
		}
	}
	return i;
}

off_t _lseek(int fd, off_t offset, int whence)	{
	PANIC("Not implemented");

	return -1;
}

int _stat(const char *pathname, struct stat *statbuf)	{
	PANIC("stat not supported");
	return 0;
}
int _fstat(int fd, struct stat *statbuf)	{
	// TODO: Must support this for all possible file descriptors
	if(!ADDR_USER(statbuf))	{
		if(fd <= 2)	{
			struct stat kstat = {0};
			kstat.st_nlink = 1;
			kstat.st_blksize = 1;
			memcpy(statbuf, &kstat, sizeof(kstat));
			return 0;
		}
		else	PANIC("fd too high\n");
	}
	return 1;
}

int _close(int fd)	{
	PANIC("Not implemented");
	return -1;
}
long __trunctfdf2(double a) {
	PANIC("Not implemented");
	return 0;
}
