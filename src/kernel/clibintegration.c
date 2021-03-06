/**
* @file clibintegration.c
* @descrption Interface which newlib uses
*/

#include "kernel.h"

#include <sys/stat.h>
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
		// TODO: Should also free up some memory here
		brk->curroffset -= increment;
		ret = (void*)(brk->addr + brk->curroffset);
	}

	// Check if we have mapped in page
	else if((brk->curroffset + increment) <= (brk->mappedpages * PAGE_SIZE))	{
		brk->curroffset += increment;
		ret = (void*)(brk->addr + brk->curroffset - increment);
		goto done;
	}

	// Inside reserved memory, but not mapped in
	else if( (brk->curroffset + increment) < (brk->numpages * PAGE_SIZE))	{
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
done:
	mutex_release(&brk->lock);
	return ret;
}

void* _usbrk(int increment)	{
	struct process* p = current_proc();
	struct sbrk* brk = &(p->ubrk);
	//struct sbrk* brk = &(osdata.threads.proc.ubrk);
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
	size_t i;
	const char* b = (const char*)buf;
	if(fd == STDOUT || fd == STDERR)	{
		kern_write((const char*)buf, count);
	}
	/*
	for(i = 0; i < count; i++)	{
		if(fd == STDOUT || fd == STDERR)	{
//			osdata.kputc(b[i]);
		}
	}
	*/
	return count;
}


ssize_t _read(int fd, void* buf, size_t count)	{
	PANIC("_read");
	size_t i = 0;
	char* tmp = (char*)buf;
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
double __trunctfdf2(long double a) {
	PANIC("Not implemented");
}
/*
void* memset(void* s, int c, size_t n)	{
	size_t i;
	for(i = 0; i < n; i++)	{
		*((uint8_t*)(s + i)) = c;
	}
	return s;
}
*/
