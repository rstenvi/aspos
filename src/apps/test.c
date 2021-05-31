#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>

#include "ubsan.h"
#include "kasan.h"
#include "lib.h"
#include "picol.h"
#include "cmd.h"
#include "memory.h"

static int _exec_picol(struct picolInterp* interp, const char* n)	{
	int pcode;
	pcode = picolEval(interp, (char*)n);
	if(pcode != PICOL_OK)	{
		printf("pcode = %i\n", pcode);
	}
	return pcode;
}


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

#define ROOT_BLOCK_DEV "/dev/block"
int create_rootfs(void) {
    int blockfd, res;
    blockfd = open(ROOT_BLOCK_DEV, OPEN_FLAG_RW, 0);
    if(blockfd < 0) {
        printf("Unable to find block device at '%s'\n", ROOT_BLOCK_DEV);
        return -1;
    }

    res = init_ustart("/", blockfd);
    if(res != 0)    {
        printf("init_ustart: %i\n", res);
    }
    return res;
}
void picol_test_rootfs(void)   {
    struct picolInterp interp;
    picolInitInterp(&interp);
    picolRegisterCoreCommands(&interp);
    // TODO: Existing puts is not really versatile enough, should change it
    picolRegisterCommand(&interp, "echo", picolCommandPuts, NULL);
    picolRegisterCommand(&interp, "cat", picol_cat, NULL);
    picolRegisterCommand(&interp, "poweroff", picol_poweroff, NULL);
    picolRegisterCommand(&interp, "exit", picol_poweroff, NULL);

	if(_exec_picol(&interp, "cat /root/test.txt"))	return;
	return;
}
void picol_test2(void)	{
#define CAT_FILE "/root/test.txt"
	create_rootfs();
	printf("Reading '%s'\n", CAT_FILE);
	cmd_cat(CAT_FILE, STDOUT);
	cmd_cat("/root/", STDOUT);
//	picol_test_rootfs();
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

void* xzalloc(int bytes)	{
	void* ret;

	ret = kmalloc(bytes);
	if(ret == NULL)	{
		printf("Unable to allocate %i bytes of memory\n");
		exit(1);
	}

	memset(ret, 0x00, bytes);
	return ret;
}

void dump_random(int count)	{
	char* buf;
	int fd, res;

	printf("Reading %i bytes of random data\n", count);
	buf = (char*)kmalloc(count);
	if(buf == NULL)	{
		printf("Unable to allocate %i bytes of data\n");
		exit(1);
	}
	printf("Allocated data\n");

	fd = xopen("/dev/random", OPEN_FLAG_READ, 0);
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

int test_umem(void)	{
	int fd;
	int res;
	fd = open("/dev/umem", OPEN_FLAG_RW);
	if(fd < 0)	{
		printf("Unable to open /dev/umem\n");
		return fd;
	}

	res = seek_read(fd, NULL, sizeof(int), (size_t)&fd);
	if(res != sizeof(int))	{
		printf("Expected %i but got %i\n", sizeof(int), res);
		goto err1;
	}

	res = seek_read(fd, NULL, sizeof(int), 0xdead);
	if(res > 0)	{
		printf("Was able to read from dead pointer: %i\n", res);
		goto err1;
	}
err1:
	close(fd);
	return 0;
}

int test_lmem(void)	{
	void* mem;
	uint8_t* m;

	mem = _mmap(NULL, 128, MAP_PROT_READ|MAP_PROT_WRITE, MAP_LAZY_ALLOC, -1);
	if(PTR_IS_ERR(mem))	{
		printf("Unable to allocate memory, returned %p\n", mem);
	}
	m = mem;

	m[42] = 0x42;

	m[0] = 0;

	return *m;
}

void test_mutex(void)	{
	int fd, ntid1, ntid2;
	printf("Testing mutex driver\n");

	fd = xopen("/dev/mutex", OPEN_FLAG_WRITE, 0);
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

	fd = xopen("/dev/semaphore", OPEN_FLAG_WRITE, NUM_RESOURCES);
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

void test_devnull(void)	{
	int fd, res;
	fd = open("/dev/null", OPEN_FLAG_RW, 0);
	if(fd < 0)	{
		printf("Unable to open /dev/null\n");
		return;
	}
	res = write(fd, "1234", 4);
	printf("Wrote %d bytes to /dev/null\n", res);
}
void test_proc(void)	{
#define MAX_BUF 128
	int fdproc, fd, ret;
	char buf[MAX_BUF];

	// Run proc-driver in different process
	if(!fork())	{
		fdproc = init_proc(false);
		if(fdproc < 0)	{
			printf("Unable to mount /proc error: %i\n", fdproc);
			return;
		}
		// The process should be kept alive even if all threads exit
		conf_process(PROC_KEEPALIVE, true);
//		proc_keepalive();
		exit_thread(0);
	}
	// This is parent
	msleep(100);
	fd = open("/proc/version", OPEN_FLAG_READ, 0);
	if(fd < 0)	{
		printf("Unable to open /proc/version: %i\n", fd);
		return;
	}
	ret = read(fd, buf, MAX_BUF);
	if(ret > 0)	{
		printf("version: '%s'\n", buf);
	}
}

void write_block(void)	{
	char buf[16];
	memset(buf, 0x42, 16);
	int res, fd;
	fd = open("/dev/block", OPEN_FLAG_RW, 0);
	if(fd > 0)	{
		res = write(fd, buf, 16);
		printf("write = %i\n", res);
		close(fd);
	}
}

void test_picol()	{
	struct picolInterp interp;
	picolInitInterp(&interp);
	picolRegisterCoreCommands(&interp);
	// TODO: Existing puts is not really versatile enough, should change it
	picolRegisterCommand(&interp, "echo", picolCommandPuts, NULL);
	picolRegisterCommand(&interp, "cat", picol_cat, NULL);
	picolRegisterCommand(&interp, "poweroff", picol_poweroff, NULL);
	picolRegisterCommand(&interp, "exit", picol_poweroff, NULL);
	if(_exec_picol(&interp, "set test 42"))		return;
	if(_exec_picol(&interp, "echo Hello"))	return;
	if(_exec_picol(&interp, "cat /test.txt"))	return;
	printf("picol: Passed all tests\n");

	fcntl(STDIN, CONSOLE_FCNTL_MODE, CHAR_MODE_LINE_ECHO);
	picol_loop("aspos$ ", &interp, STDIN, STDOUT);
}

void test_read_block(int bytes, int offset)	{
	char* buf;
	int res, fd;

	buf = (char*)xzalloc(bytes);
	fd = xopen("/dev/block", OPEN_FLAG_RW, 0);
	lseek(fd, offset, SEEK_SET);
	res = xread(fd, buf, bytes);
	hexdump(buf, bytes);
	close(fd);
}

void test_dataabort(void)	{
	int* a = (int*)0xdeadbeef;
	int b = *a;
	printf("*a = %x\n", b);
}
int aa(void)	{ return 42; }

int test_vconsole(void)	{
	int fd, res;
	char buf[64];
	fd = open("/dev/vconsole", OPEN_FLAG_READ | OPEN_FLAG_CTRL);
	if(fd < 0)	return fd;

	res = fcntl(fd, FCNTL_VCONSOLE_INIT);
	if(res < 0)	return res;

	close(fd);

	fd = open("/dev/vconsole-1", OPEN_FLAG_READ | OPEN_FLAG_WRITE);
	if(fd < 0)	return fd;

	res = write(fd, "Hello\n", 6);
	if(res < 0)	return res;

	res = read(fd, buf, 64);
	if(res < 0)	return res;
	printf("read '%s'\n", buf);

	close(fd);

	return 0;
}
int test_kasan(void)	{
	int fd, res;
	fd = open("/dev/kasan-test", OPEN_FLAG_READ | OPEN_FLAG_CTRL);
	if(fd < 0)	return fd;

	res = fcntl(fd, FCNTL_KASAN_ALL_TESTS);
	if(res < 0)	goto err1;

err1:
	close(fd);
	return res;
}

int test_kasan_user(void)	{
	printf("Testing user mode kasan\n\n");
	int* a = kmalloc(10 * sizeof(int));
	kfree(a);
	return READ_ONCE(a[0]);
}

int test_ubsan_user(void)	{
	printf("Starting user mode ubsan tests\n");
	int a = INT_MAX;
	a++;

	printf("\n\n");
	return 0;
}

int test_ubsan(void)	{
	printf("Starting kernel mode ubsan tests\n");
	int fd, res;
	fd = open("/dev/ubsan-test", OPEN_FLAG_READ | OPEN_FLAG_CTRL);
	if(fd < 0)	return fd;

	res = fcntl(fd, FCNTL_UBSAN_ALL_TESTS);
	if(res < 0)	goto err1;

	printf("\n\n");
err1:
	close(fd);
	return res;
}

int test_socket(void)	{
#define BUF_MAX (32)
	char buf[BUF_MAX];
	int res, i;
	int fd = open("/dev/socket", OPEN_FLAG_RW | OPEN_FLAG_CTRL, 0);
	if(fd < 0)	return fd;

//	res = fcntl(fd, FCNTL_VIRTIO_SET_SRC_PORT, 9999);
	res = fcntl(fd, FCNTL_VIRTIO_SET_TARGET, (2 | (9999UL << 32)));
	if(res < 0)	return res;
//	res = fcntl(fd, FCNTL_VIRTIO_LISTEN);
//	if(res < 0)	return res;
	res = fcntl(fd, FCNTL_VIRTIO_CONNECT);
	if(res < 0)	return res;
	for(i = 0; i < 10; i++)	{
		memset(buf, 0x00, BUF_MAX);
		res = write(fd, "Hello", 5);
		if(res < 0)	return res;
		printf("Wrote %i bytes\n", res);

		res = read(fd, buf, BUF_MAX);
		if(res < 0)	return res;
		printf("Read '%s' from remote host\n");
	}

	msleep(100);
	close(fd);


//	res = write(fd, "Hello", 5);
//	if(res < 0)	return res;
/*
*/
/*
//	res = fcntl(fd, FCNTL_VIRTIO_SET_TARGET, (2 | (9999UL << 32)));
//	if(res < 0)	return res;
	res = write(fd, "Hello", 5);
	if(res < 0)	return res;
//	res = write(fd, "Hello", 5);
//	if(res < 0)	return res;
	res = read(fd, buf, BUF_MAX);
	if(res < 0)	return res;
	printf("Read '%s' from remote host\n");
	*/
	msleep(3000);
	return 0;
}
#define KCOV_MAX_ENTRIES (1000)
#define ALLOC_BUFFER     (4096 * 256)

int _kcov_pre(void)	{
	int fd, res;
	fd = open("/dev/kcov", OPEN_FLAG_READ|OPEN_FLAG_CTRL);
	if(fd < 0)	return fd;

	res = fcntl(fd, FCNTL_KCOV_INIT);
	if(res < 0)	return res;

	return fd;
}
void* _kcov_mmap(int fd, bool enable)	{
	void* addr;
	int res;
	addr = mmap(NULL, ALLOC_BUFFER, MAP_PROT_READ|MAP_PROT_WRITE, MAP_NON_CLONED, fd);

	if(enable)	{
		res = fcntl(fd, FCNTL_KCOV_ENABLE);
		if(res < 0)	return NULL;
	}

	return addr;
}
int _kcov_dump(void* addr)	{
	int i;
	struct kcov_data* data = (struct kcov_data*)addr;
	printf("Read %i entries\n", data->currcount);
	for(i = 0; i < data->currcount; i++)	{
		printf("0x%lx\n", data->entries[i]);
	}
	WRITE_ONCE(data->currcount, 0);
}
int test_kcov(void)	{
	int fd, res, i;
	void* addr;

	fd = _kcov_pre();

	addr = _kcov_mmap(fd, true);
	if(!addr)	goto err1;


	for(i = 0; i < 2; i++)	{
		res = fcntl(fd, FCNTL_KCOV_ENABLE);
		if(res < 0)	goto err1;

		yield();

		res = fcntl(fd, FCNTL_KCOV_DISABLE);
		if(res < 0)	goto err1;

		_kcov_dump(addr);
	}

	munmap(addr);
	close(fd);
err1:
	return res;
}

int test_kcov2(void)	{
	int fd, fdv, fdproc, res, ret;
	void* addr;
	char buf[MAX_BUF];

	// Run proc-driver in different process
	if(!fork())	{
		fdproc = init_proc(false);
		if(fdproc < 0)	{
			printf("Unable to mount /proc error: %i\n", fdproc);
			return -1;
		}
		// The process should be kept alive even if all threads exit
		conf_process(PROC_KEEPALIVE, true);
		exit_thread(0);
	}

	msleep(100);
	// This is parent
	fdv = open("/proc/version", OPEN_FLAG_READ, 0);
	if(fdv < 0)	{
		printf("Unable to open /proc/version: %i\n", fdv);
		return -1;
	}

	fd = _kcov_pre();

	addr = _kcov_mmap(fd, false);

	if(!addr)	goto err1;

	res = fcntl(fd, FCNTL_KCOV_ENABLE);
	if(res < 0)	goto err1;

	ret = read(fdv, buf, MAX_BUF);

	res = fcntl(fd, FCNTL_KCOV_DISABLE);
	if(res < 0)	goto err1;

	if(ret > 0)	{
		printf("version: '%s'\n", buf);
	}

	_kcov_dump(addr);

	munmap(addr);
	close(fd);
err1:
	return res;

}

int test_fork(void)	{
	int val = 42;
	int pid;
	pid = fork();
	if(pid == 0)	{
	//	write(STDOUT, "Child\n", 6);
		//exit_thread(0);
		printf("Child: %i\n", val);
		msleep(10000);
//		write(STDOUT, "Child\n", 6);
	}
	else	{
		wait_pid(pid);
		val++;
		// With a delay here, the second proc which finishes
		// will return to incorrect place
		// Might be a problem with how the MMU is unmapped
		//msleep(2000);
		printf("Parent created %i | val: %i\n", pid, val);
	}
	return 0;
}

int read_stdin(void)	{
	char buf[16];
	int res;
	memset(buf, 0x00, 16);

	res = read(0, buf, 16);
	printf("res = %i | buf: %s\n", res, buf);
	return res;
}

void print_usage()	{
	printf("Place argmument by specifying 'USERARG=cmd' in userconfig.mk\n");
	printf("Possible arguments: mutex|semaphore|sleep|random|rblock\n");
}

int main(int argc, char* argv[])	{
	int i, res = 0;
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
	else if(!strcmp(argv[1], "rblock"))	{
		test_read_block(64, 0);
		test_read_block(64, 2);
	}
	else if(!strcmp(argv[1], "devnull"))	{
		test_devnull();
	}
	else if(!strcmp(argv[1], "proc"))	{
		test_proc();
	}
	else if(!strcmp(argv[1], "picol"))	{
		test_picol();
	}
	else if(!strcmp(argv[1], "picol2"))	{
		picol_test2();
	}
	else if(!strcmp(argv[1], "dataabort"))	{
		test_dataabort();
	}
	else if(!strcmp(argv[1], "fork"))	{
		test_fork();
	}
	else if(!strcmp(argv[1], "socket"))	{
		test_socket();
	}
	else if(!strcmp(argv[1], "kcov"))	{
		res = test_kcov();
	}
	else if(!strcmp(argv[1], "kcov2"))	{
		res = test_kcov2();
	}
	else if(!strcmp(argv[1], "ubsan"))	{
		res = test_ubsan();
		res = test_ubsan_user();
	}
	else if(!strcmp(argv[1], "kasan"))	{
		res = test_kasan();
	}
	else if(!strcmp(argv[1], "kasanu"))	{
		res = test_kasan_user();
	}
	else if(!strcmp(argv[1], "vconsole"))	{
		res = test_vconsole();
	}
	else if(!strcmp(argv[1], "stdin"))	{
		res = read_stdin();
	}
	else if(!strcmp(argv[1], "umem"))	{
		res = test_umem();
	}
	else if(!strcmp(argv[1], "lmem"))	{
		res = test_lmem();
	}
	else	{
		printf("'%s' is not a valid command\n", argv[1]);
		print_usage();
		exit(1);
	}
	if(res != 0)	{
		printf("Invalid return: %i\n", res);
	}

	//msleep(50000);
	printf("Leaving...\n");
	//_exit(0);
	return 0;
}
