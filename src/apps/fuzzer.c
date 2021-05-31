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
#include "syscalls.h"
#include "memory.h"

#define INPUT_SIMULATED false

#define KCOV_MAX_ENTRIES (1000)
#define ALLOC_BUFFER     (4096 * 256)

struct kcov_user {
	int fd;
	struct kcov_data* data;
};

struct kcov_user kcov;

ptr_t svc(int sysno, ptr_t* args);
int _kcov_pre(void);
void* _kcov_mmap(int fd, bool enable);
int _kcov_dump(void* addr);
int generate_program(struct kcov_user* kcov);
bool _kcov_parse(struct kcov_data* data);


struct syscall {
	ptr_t sysno;
	ptr_t args[8];
};
struct prog_state {
	struct syscall syscall;
};

#define MAX_RES (64)
static ptr_t resources[MAX_RES];
static int numres = 0;

#define BITMAP_SIZE (4096 * 4)
static uint8_t* bitmap = NULL;

static inline uint32_t hash(ptr_t v)	{
	return v % BITMAP_SIZE;
}

static ptr_t special_nums[] = {
	-1,
	// virtio-socket
	FCNTL_VIRTIO_SET_CID, FCNTL_VIRTIO_SET_DST_PORT, FCNTL_VIRTIO_SET_TARGET,
	FCNTL_VIRTIO_CONNECT, FCNTL_VIRTIO_LISTEN, FCNTL_VIRTIO_SET_SRC_PORT,

	// virtio-console
	FCNTL_VCONSOLE_INIT,

	// ubsan and kasan
	FCNTL_UBSAN_ALL_TESTS, FCNTL_UBSAN_DIV_ZERO, FCNTL_KASAN_ALL_TESTS,

	// pl011
	CONSOLE_FCNTL_MODE,
};

#define NUM_SPECIALS (sizeof(special_nums) / sizeof(ptr_t))

#define NUM_FILENAMES (12)
static char filenames[NUM_FILENAMES][20] = {
	"",
	"invpath",
	"/invalid/path",
	"/dev/socket",
	"/dev/random",
	"/dev/umem",
	"/proc/version",
	"/dev/ethernet",
	"/dev/mutex",
	"/dev/semaphore",
	"/dev/ubsan-test",
	"/dev/kasan-test",
};

static char str_syscalls[NUM_SYSCALLS][16] = {
	"open", "close", "read", "write", "sbrk", "isatty", "fstat",
	"exit", "lseek", "poweroff", "sleep_tick", "new_thread", "exit_thread",
	"sleep_ms", "yield", "dup", "getc", "putc", "wait_tid", "get_tid",
	"conf_thread", "fcntl", "fork", "set_user", "get_user",
	"get_filter", "set_filter", "conf_process", "mmap", "munmap", "wait_pid", "getpid"
};
#define AT_INT    (1)
#define AT_STR    (2)
#define AT_BUFIN  (3)
#define AT_BUFOUT (4)
#define AT_RES    (5)
#define AT_LEN    (6)
#define AT_FNAME  (7)
#define anum(idx, type) ((ptr_t)type << (idx * 8))
#define gnum(idx, num)  ((num >> (idx * 8)) & 0xff)
static ptr_t arg_types[NUM_SYSCALLS] = {
	anum(0, AT_FNAME) | anum(1, AT_INT) | anum(2, AT_INT),	// open
	anum(0, AT_RES),	// close
	anum(0, AT_RES) | anum(1, AT_BUFOUT) | anum(2, AT_LEN),	// read
	anum(0, AT_RES) | anum(1, AT_BUFIN) | anum(2, AT_LEN),	// write
	anum(0, AT_INT),	// sbrk
	anum(0, AT_RES),	// isatty
	anum(0, AT_RES) | anum(1, AT_BUFIN),	// fstat
	anum(0, AT_INT),	// exit
	anum(0, AT_RES) | anum(1, AT_INT) | anum(2, AT_INT),	// lseek
	anum(0, AT_INT),	// poweroff
	anum(0, AT_INT),	// sleep_tick
	0,	// new_thread
	anum(0,	AT_INT),	// exit_thread
	anum(0, AT_INT),	// sleep_ms
	0,	// yield
	anum(0, AT_RES),	// dup
	anum(0, AT_RES),	// getc
	anum(0, AT_RES) | anum(1, AT_INT),	// putc
	anum(0, AT_INT),	// wait_tid
	0,	// get_tid
	anum(0, AT_INT) | anum(1, AT_INT), // conf_thread
	anum(0, AT_RES) | anum(1, AT_INT) | anum(2, AT_INT),	// fcntl
	0,	// fork
	anum(0, AT_BUFIN),	// set_user
	anum(0, AT_BUFOUT),	// get_user
	0,	// get_filter
	anum(0, AT_INT),	// set_filter
	anum(0, AT_INT) | anum(1, AT_INT), // conf_process
	anum(0, AT_INT) | anum(1, AT_LEN) | anum(2, AT_INT) | anum(3, AT_INT) | anum(4, AT_RES), // mmap
	anum(0, AT_INT), // munmap
	anum(0, AT_INT),	// wait_pid
	0	// getpid
};

#define BUFFER_SIZE (4096 * 4)
void* tmp_buffer = NULL;
void* currptr;

void _kcov_init(struct kcov_user* kcov)	{
	kcov->fd = _kcov_pre();
	kcov->data = _kcov_mmap(kcov->fd, false);

}

void _kcov_close(struct kcov_user* kcov)	{
	munmap(kcov->data);
	close(kcov->fd);
}

#define NUM_PROCS (2)
uint32_t rand_xors[] = {0xdeadbeef, 0xbeefc0de};
static int curridx;
static uint32_t frand(void)	{
	uint32_t r = rand();
	r ^= rand_xors[curridx];
	return r;
}

void run_fuzzer(int idx)	{
	// We generated a seed already, but to avoid all processes having the same
	// seed, we re-seed by xoring random value with index
	int seed = rand();
	int pid = getpid();
	seed ^= pid;
	srandom(seed);

	_kcov_init(&kcov);
	tmp_buffer = mmap(NULL, BUFFER_SIZE, MAP_PROT_READ|MAP_PROT_WRITE, MAP_NON_CLONED, -1);
	memset(tmp_buffer, 0x00, BUFFER_SIZE);
	currptr = tmp_buffer;

	bitmap = mmap(NULL, BITMAP_SIZE, MAP_PROT_READ|MAP_PROT_WRITE, MAP_NON_CLONED, -1);
	memset(tmp_buffer, 0x00, BITMAP_SIZE);

	while(true)	{
		generate_program(&kcov);
	}
	_kcov_close(&kcov);
}

int main(int argc, char* argv[])	{
	int res, i, pid;
	int childs[NUM_PROCS];

	for(i = 0; i < NUM_PROCS; i++)	{
		pid = fork();
		if(!pid)	{
			run_fuzzer(i);
			exit_thread(1);
		}
		else	{
			childs[i] = pid;
		}
	}

	for(i = 0; i < NUM_PROCS; i++)	{
		wait_pid(childs[i]);
	}

	return 0;
}

int rand_syscall(void)	{	return frand() % NUM_SYSCALLS; }
int rand_under(int max)	{	return frand() % max; }
char* rand_fname(void)	{
	int r = rand_under(NUM_FILENAMES+1);
	if(r == NUM_FILENAMES)	return NULL;
	return filenames[r];
}
ptr_t rand_int(void)	{
	int r = frand();
	if((r % 3) == 0)	{
		int idx = rand_under(NUM_SPECIALS);
		return special_nums[idx];
	}
	ptr_t ret = 0;
	r = frand();
	ret = (ptr_t)r << 32;
	r = frand();
	ret |= r;
	return ret;
}

ptr_t rand_buffer(int sysno, ptr_t* len, bool in)	{
	ptr_t ret = 0;
	ptr_t _len;
	int r = frand();
	if((r % 17) == 0)	{
		*len = 32;
		ret = rand_int();

		// Try with user- or kernel-mode address
		r %= 100;
		if(r < 50)	ret &= 0x0000ffffffffffff;
		else		ret |= 0xffff000000000000;

		return ret;
	}

	switch(sysno)	{
	case SYS_FSTAT:
		_len = sizeof(struct stat);
		break;
	case SYS_SET_USER:
	case SYS_GET_USER:
		_len = sizeof(struct user_id);
		break;
	default:
		_len = frand() % BUFFER_SIZE / 8;
		break;
	}

	*len = _len;

	// If we have used up buffer we start at beginning again
	if(_len + (ptr_t)currptr >= (ptr_t)tmp_buffer + BUFFER_SIZE)	{
		currptr = tmp_buffer;
	}

	ret = (ptr_t)currptr;
	currptr += _len;
	
	if(in && len > 0)	{
		uint8_t* r = (uint8_t*)ret;
		ptr_t i;
		for(i = 0; i < _len; i++)	{
			r[i] = frand() % 0x100;
		}
	}
	return (len > 0) ? ret : 0;
}
ptr_t rand_flag(int bitmax)	{
	ptr_t base = rand_int();
	return (base & ((1 << bitmax+1)-1));
}
ptr_t rand_resource()	{
	if(numres <= 0)	return -1;

	int r = frand() % (numres+1);
	return (r >= numres || r >= MAX_RES) ? -1 : resources[r];
}
int rand_fd()	{
	return rand_resource(resources, numres);
}

int mutate_syscall(ptr_t sysno, ptr_t* args)	{

}

int print_type(uint8_t type, ptr_t arg, bool prev)	{
	char* pr = (prev) ? ", " : "";
	switch(type)	{
		case AT_INT:
			printf("%s0x%lx", pr, arg);
			break;
		case AT_STR:
		case AT_FNAME:
			(arg) ? printf("%s\"%s\"", pr, arg) : printf("%sNULL", pr);
			break;
		case AT_BUFIN:
			printf("%s&(0x%lx)=", pr, arg);
			break;
		case AT_BUFOUT:
			printf("%s&(0x%lx)", pr, arg);
			break;
		case AT_RES:
			printf("%s0x%lx", pr, arg);
			break;
		case AT_LEN:
			printf("%s0x%lx", pr, arg);
			break;
		default:
			return -1;
	}
	return 0;
}
void print_syscall(int sysno, ptr_t* args)	{
	char* sysname = str_syscalls[sysno];
	uint64_t atype = arg_types[sysno];
	uint8_t type;
	int i;

	printf("EXEC: %s(", sysname);
	for(i = 0; i < 8; i++)	{
		type = gnum(i, atype);
		if(print_type(type, args[i], (i > 0)) < 0)	break;
	}
	printf(")\n");
}

ptr_t gen_type(int sysno, int type, ptr_t* state)	{
	ptr_t ret = 0;
	switch(type)	{
	case AT_INT:
		ret = rand_int();
		break;
	case AT_RES:
		ret = rand_resource();
		break;
	case AT_STR:
	case AT_FNAME:
		ret = (ptr_t)rand_fname();
		break;
	case AT_BUFOUT:
		ret = rand_buffer(sysno, state, false);
		break;
	case AT_BUFIN:
		ret = rand_buffer(sysno, state, true);
		break;
	case AT_LEN:
		ret = *state;
		break;
	default:
		break;
	}
	return ret;
}

bool syscall_valid(int sysno)	{
	switch(sysno)	{
	case SYS_EXIT_THREAD:
	case SYS_POWEROFF:
	case SYS_WAITPID:
	case SYS_EXIT:
	case SYS_NEW_THREAD:	// Should enable later
	case SYS_WAIT_TID:
	case SYS_FORK:
	case SYS_MUNMAP:
	case SYS_MMAP:
	case SYS_GET_TID:
		return false;
	}
	return true;
}
void save_resource(ptr_t res)	{
	if(numres >= MAX_RES)	{
		// Just discard everything when we reach max
		numres = 0;
	}
	printf("RES: x%i -> 0x%lx\n", numres, res);
	resources[numres++] = res;
}

ptr_t filter_fd(ptr_t _fd)	{
	// fd = 3 is for kasan file pointer
	int fd = (int)_fd;
	return (fd == STDOUT || fd == STDIN || fd == STDERR || fd == 3 || fd == kcov.fd) ? -1 : fd;
}

#define B_ARG_0 (1 << 0)
#define B_ARG_1 (1 << 1)
#define B_ARG_2 (1 << 2)
#define B_ARG_3 (1 << 3)
#define B_ARG_4 (1 << 4)
#define B_ARG_5 (1 << 5)
#define B_ARG_6 (1 << 6)
#define B_ARG_7 (1 << 7)
int generate_syscall(struct kcov_user* kcov)	{
	ptr_t args[8] = {0};
	int sysno = rand_syscall(), i, res, t;
	uint8_t filled = 0;
	
	if(!syscall_valid(sysno))	return -1;

	ptr_t argts = arg_types[sysno], state = 0;
	for(i = 0; i < 8; i++)	{
		t = (int)gnum((ptr_t)i, argts);
		if(t == 0)	break;
		args[i] = gen_type(sysno, t, &state);
	}

	switch(sysno)	{
	case SYS_OPEN:
		args[1] &= (OPEN_FLAG_EXEC << 1) - 1;
		break;
	
	// Make sure we don't sleep forever
	case SYS_SLEEP_TICK:
	case SYS_SLEEP_MS:
		args[0] &= 0x0f;
		break;

	// Do not close stdout or stdin, but do allow closing stderr
	case SYS_CLOSE:
		args[0] = filter_fd(args[0]);
		break;

	// If we don't simulate input using an external fuzzer, we should not
	// try and read from serial device
	case SYS_WRITE:
	case SYS_PUT_CHAR:
	case SYS_READ:
	case SYS_GET_CHAR:
	case SYS_DUP:
#if INPUT_SIMULATED == false
		args[0] = filter_fd(args[0]);
#endif
		break;
	}
	print_syscall(sysno, args);
/*
	res = fcntl(kcov->fd, FCNTL_KCOV_ENABLE);
	if(res < 0)	goto err1;
*/
	ptr_t ans = svc(sysno, args);
/*
	res = fcntl(kcov->fd, FCNTL_KCOV_DISABLE);
	if(res < 0)	goto err1;

	if(_kcov_parse(kcov->data))	{
		// Should save this as interesting
	}*/

	if((long)ans > 0)	save_resource(ans);

	return 0;
err1:
	return res;
}

int generate_program(struct kcov_user* kcov)	{
	while(generate_syscall(kcov) < 0) { }
}

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
	return 0;
}

bool _kcov_parse(struct kcov_data* data)	{
	int i;
	ptr_t edge = 0;
	uint8_t b;
	bool interest = false;
	for(i = 1; i < data->currcount; i++)	{
		edge = data->entries[i-1] ^ data->entries[i];
		edge = hash(edge);
		b = bitmap[edge]++;
		if(!b)	interest = true;
	}
	// Need to reset so that we're ready for next turn
	WRITE_ONCE(data->currcount, 0);
	return interest;
}
