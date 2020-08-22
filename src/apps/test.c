#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#include "aspos.h"

void second_main(int n)	{
	printf("Second main got: %i\n", n);
}
void third_main(void)	{
	printf("Third main\n");
	while(1);
}

void hexdump(unsigned char* arr, int bytes)	{
	int i;
	printf("hexdump");
	for(i = 0; i < bytes; i++)	{
		if((i % 16) == 0)	printf("\n%04x; ", i);
		printf("%02x ", arr[i]);
	}
	printf("\n");
}

int xopen(const char* s, int flags, int mode)	{
	int res;
	res = open(s, flags, mode);
	if(res < 0)	{
		printf("Unable to open '%s' return: %i\n", s, res);
		exit(1);
	}
	return res;
}

int xread(int fd, void* buf, int count)	{
	int res;
	res = read(fd, buf, count);
	if(res < 0)	{
		printf("Unable to read from fd %i return is %i\n", fd, res);
		exit(1);
	}
	return res;
}

void dump_random(int count)	{
	char* buf;
	int fd, res;

	printf("Reading %i bytes of random data\n", count);
	buf = (char*)malloc(count);
	if(buf == NULL)	{
		printf("Unable to allocate %i bytes of data\n");
		exit(1);
	}
	printf("Allocated data\n");

	fd = xopen("/dev/random", 0, 0);
	printf("Opened fd %i and starting read\n", fd);
	printf("Read can be slow if new data must be generated\n");
	res = xread(fd, buf, count);
	printf("read %i bytes\n", res);
	hexdump(buf, count);
	close(fd);
}

void _mutex_thread(int fd)	{
	int i, tid;
	tid = get_tid();
	printf("Working on mutex %i on tid %i\n", fd, tid);
	for(i = 0; i < 5; i++)	{
		put_char(fd, MUTEX_ACQUIRE);
		printf("Acquired mutex %i\n", tid);
		msleep(1000);
		put_char(fd, MUTEX_RELEASE);
		printf("Released mutex %i\n", tid);
	}
}

void test_mutex(void)	{
	int fd, ntid1, ntid2;
	printf("Testing mutex driver\n");

	fd = xopen("/dev/mutex", 0, 0);
	printf("Opened mutes @ %i\n", fd);

	ntid1 = new_thread( (uint64_t) _mutex_thread, 1, fd);
	printf("New thread: %i\n", ntid1);

	ntid2 = new_thread( (uint64_t) _mutex_thread, 1, fd);
	printf("New thread: %i\n", ntid2);

	printf("Waiting on tid: %i\n", ntid1);
	wait_tid(ntid1);

	printf("Waiting on tid: %i\n", ntid2);
	wait_tid(ntid2);

	printf("Threads have finished\n");
	msleep(100);
}

void _semaphore_thread(int fd, int count)	{
	int res, tid, acquired = 0, i, ms = 500;
	tid = get_tid();

	for(i = 0; i < count; i++)	{
		res = put_char(fd, SEMAPHORE_WAIT);
		if(res >= 0)	{
			printf("Acquired resouorce on thread %i | %i resources left\n", tid, res);
			acquired++;
		}
		ms = random() % 500;
		printf("Sleeping for %i ms\n", ms);
		msleep(ms);
	}

	// Release all resources again
	for(i = 0; i < acquired; i++)	{
		printf("Releasing resource %i on thread %i\n", i, tid);
		put_char(fd, SEMAPHORE_SIGNAL);
		msleep(500);
	}
}

void test_semaphore(void)	{
	int fd, tid1, tid2;
	printf("Testing semaphore driver\n");
	#define NUM_RESOURCES 5

	fd = xopen("/dev/semaphore", 0, NUM_RESOURCES);
	printf("Opened semaphore @ %i\n", fd);

	tid1 = new_thread( (uint64_t) _semaphore_thread, 2, fd, 3);
	printf("New thread: %i\n", tid1);

	tid2 = new_thread( (uint64_t) _semaphore_thread, 2, fd, 2);
	printf("New thread: %i\n", tid2);

	printf("Waiting on tid: %i\n", tid1);
	wait_tid(tid1);

	printf("Waiting on tid: %i\n", tid2);
	wait_tid(tid2);

	printf("Threads have finished\n");
	msleep(100);

}

void write_block(void)	{
	char buf[16];
	memset(buf, 0x42, 16);
	int res, fd;
	fd = open("/block", 0, 0);
	if(fd > 0)	{
		res = write(fd, buf, 16);
		printf("write = %i\n", res);
		close(fd);
	}
}
void read_block(void)	{
	char buf[16];
	memset(buf, 0x00, 16);
	int res, fd;
	fd = open("/block", 0, 0);
	if(fd > 0)	{
		lseek(fd, 1, SEEK_SET);
		res = read(fd, buf, 16);
		printf("read = %i | buf[0] = 0x%x\n", res, buf[0]);
		close(fd);
	}
}

void read_stdin(void)	{
	char buf[16];
	int res;
	memset(buf, 0x00, 16);

	res = read(0, buf, 16);
	printf("res = %i | buf: %s\n", res, buf);
}

void print_usage()	{
	printf("Place argmument by specifying 'USERARG=cmd' in userconfig.mk\n");
	printf("Possible arguments: mutex|semaphore|sleep|random\n");
}

int main(int argc, char* argv[])	{
	int i;
	printf("Entering user mode\n");
	if(argc <= 1)	{
		printf("Did not receive any argument\n");
		print_usage();
		exit(1);
	}

	printf("Arguments to user mode\n");
	for(i = 0; i < argc; i++)	{
		printf("argv[%i] = %s\n", i, argv[i]);
	}

	if(!strcmp(argv[1], "sleep"))	{
		int msecs = (argc <= 2) ? 5000 : atoi(argv[2]);
		printf("Sleeping for %i milliseconds\n", msecs);
		msleep(msecs);
	}
	else if(!strcmp(argv[1], "random"))	{
		int count = (argc <= 2) ? 64 : atoi(argv[2]);
		dump_random(count);
	}
	else if(!strcmp(argv[1], "mutex"))	{
		test_mutex();
	}
	else if(!strcmp(argv[1], "semaphore"))	{
		test_semaphore();
	}
	else	{
		printf("'%s' is not a valid command\n", argv[1]);
		print_usage();
		exit(1);
	}

	printf("Leaving...\n");
	return 0;
}
