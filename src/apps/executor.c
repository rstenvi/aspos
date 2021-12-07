
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>

#include "lib.h"
#include "memory.h"
#include "syscalls.h"
#include "kasan.h"

int cfd;

#define SUBTRACT_SYSNO (0)

#define kInMagic 0xbadc0ffeebadface
#define kOutMagic 0xbadf00d

#define instr_eof -1
#define instr_copyin -2
#define instr_copyout -3

#define no_copyout (uint64_t)-1

#define arg_const  0
#define arg_result 1
#define arg_data   2
#define arg_csum   3

#define NUM_THREADS (1)

#define KCOV_SIZE (4096 * 128)

#define ARG_REGION_ADDR (0x20000000)

// Must be kept in sync with executor.cc in Syzkaller
#define ARG_REGION_PER_SIZE (4 << 20)
#define ARG_REGION_SIZE (ARG_REGION_PER_SIZE * NUM_THREADS)
#define OUT_REGION_SIZE (4096 * 64)
#define K_MAX_INPUT (4096 * 16)
//void* out_region;
//void* out_pos;

#define MAX_ARGS (8)

static mutex_t readylock;

struct kcov_user {
	int fd;
	struct kcov_data* data;
};

struct thread_data {
	// Number we add the the addr we get from syzkaller
	int64_t arg_offset;
	void* out_region;
	void* input_data;
//	char input_data[K_MAX_INPUT];
	struct kcov_user kcov;
};
static struct thread_data threads[NUM_THREADS] = {0};

struct call_t {
	const char* name;
	int sys_nr;
};

// TODO: This is retrieved from executor/syscalls.h in syzkaller
static struct call_t syscalls[] = {
    {"_close", 1},
    {"_conf_process", 27},
    {"_conf_process$PROC_KEEPALIVE", 27},
    {"_conf_thread", 20},
    {"_conf_thread$EEXIT", 20},
    {"_conf_thread$TEXIT", 20},
    {"_dup", 15},
    {"_fcntl", 21},
    {"_fcntl$CUSE_DETACH", 21},
    {"_fcntl$CUSE_MOUNT", 21},
    {"_fcntl$CUSE_REGISTER", 21},
    {"_fcntl$CUSE_SET_FS_OPS", 21},
    {"_fcntl$CUSE_SET_FUNC_EMPTY", 21},
    {"_fcntl$CUSE_SVC_DONE", 21},
    {"_fcntl$CUSE_UNREGISTER", 21},
    {"_fcntl$FCNTL_VIRTIO_CONNECT", 21},
    {"_fcntl$FCNTL_VIRTIO_LISTEN", 21},
    {"_fcntl$FCNTL_VIRTIO_SET_CID", 21},
    {"_fcntl$FCNTL_VIRTIO_SET_DST_PORT", 21},
    {"_fcntl$FCNTL_VIRTIO_SET_SRC_PORT", 21},
    {"_fcntl$FCNTL_VIRTIO_SET_TARGET", 21},
    {"_fcntl$KASAN_ALL_TESTS", 21},
    {"_fcntl$NONBLOCK", 21},
    {"_fcntl$UBSAN_ALL_TESTS", 21},
    {"_fstat", 6},
    {"_get_char", 16},
    {"_get_filter", 25},
    {"_get_pid", 31},
    {"_get_tid", 19},
    {"_get_user", 24},
    {"_is_mapped", 32},
    {"_isatty", 5},
    {"_lseek", 8},
    {"_mmap", 28},
    {"_munmap", 29},
    {"_open", 0},
    {"_open$CUSE", 0},
    {"_open$ETHERNET", 0},
    {"_open$KASAN", 0},
    {"_open$MUTEX", 0},
    {"_open$NULL", 0},
    {"_open$RANDOM", 0},
    {"_open$SEMAPHORE", 0},
    {"_open$SOCK", 0},
    {"_open$UBSAN", 0},
    {"_open$proc", 0},
    {"_put_char", 17},
    {"_read", 2},
    {"_sbrk", 4},
    {"_sleep_ms", 13},
    {"_sleep_tick", 10},
    {"_wait_pid", 30},
    {"_wait_tid", 18},
    {"_write", 3},
    {"_yield", 14},
};

//char input_data[K_MAX_INPUT];
//char* input_last = NULL;
int kInPipeFd = STDIN;


//static struct kcov_user kcov;


struct execute_reply {
	uint32_t magic;
	uint32_t done;
	uint32_t status;
};
//struct execute_reply header;
struct call_reply {
	uint32_t call_index;
	uint32_t call_num;
	uint32_t reserrno;
	uint32_t flags;
	uint32_t signal_size;
	uint32_t cover_size;
	uint32_t comps_size;
	// signal/cover/comps follow
	uint32_t signals[0];
//	uint32_t cover[0];
//	uint32_t comp[0];
};

struct execute_req {
	uint64_t magic;
	uint64_t env_flags;
	uint64_t exec_flags;
	uint64_t pid;
	uint64_t fault_call;
	uint64_t fault_nth;
	uint64_t syscall_timeout_ms;
	uint64_t program_timeout_ms;
	uint64_t slowdown_scale;
	uint64_t prog_size;
};

// Is 1000 is syzkaller
#define MAX_COMMANDS (64)
struct result_entry {
	uint64_t arg;
	uint32_t size;
	bool inmem;
	bool executed;
};

static inline uint32_t hash(uint64_t v)	{
	return (uint32_t)(v % (1UL << 32));
}

void failmsg(const char* err, const char* msg, ...)	{
	printf("SYZFAIL: %s\n", err);
// 	if(msg)	{
// 		va_list args;
// 		va_start(args, msg);
// 		vprintf(msg, args);
// 		va_end(args);
// 	}
	printf("\nSYZFAIL end\n");
	exit(1);
}
static inline void check_len(void* curr, void* last, int bytes)	{
	if(curr + bytes > last)	{
		failmsg("len overflow", "pos=%p: last:%p bytes:%i", curr, last, bytes);
	}
}

void fail(const char* err)	{	failmsg(err, NULL); }
uint64_t read_input(uint64_t** input_posp);
int execute_one(struct thread_data*, int cpu);
int receive_execute(struct thread_data*);
void write_answer(uint32_t calli, uint32_t callno, int64_t errno, struct kcov_user* kcov, void**, void*, int);
ptr_t svc(int sysno, ptr_t* args);
static int copyin(void* addr, uint64_t val, int size);

// void __run_thread(struct thread_data* thread)	{
// 	receive_execute(thread);
// 	execute_one(thread);
// 	exit_thread(0);
// }
void _run_thread(struct thread_data* thread)	{
	int res, i;
	void* argregion = _mmap((void*)ARG_REGION_ADDR, ARG_REGION_PER_SIZE, MAP_PROT_READ|MAP_PROT_WRITE, MAP_LAZY_ALLOC/*MAP_NON_CLONED*/, -1);
	if(PTR_IS_ERR(argregion) || argregion != (void*)0x20000000)	{
		failmsg("Unable to mmap argument region", "addr=%p", argregion);
	}
	//memset((void*)ARG_REGION_ADDR, 0x00, ARG_REGION_SIZE);

	void* out_region = _mmap(NULL, OUT_REGION_SIZE, MAP_PROT_READ|MAP_PROT_WRITE, /*MAP_NON_CLONED |*/ MAP_LAZY_ALLOC, -1);
	if(PTR_IS_ERR(out_region))	{
		failmsg("Unable to mmap output region", "out=%p", out_region);
	}
	WRITE_ONCE(*(uint64_t*)out_region, 0);
	thread->out_region = out_region;

	thread->input_data = _mmap(NULL, K_MAX_INPUT, MAP_PROT_READ|MAP_PROT_WRITE, 0, -1);
	if(PTR_IS_ERR(thread->input_data))	{
		failmsg("Unable to mmap input region", "out=%p", thread->input_data);
	}


	thread->kcov.fd = open("/dev/kcov", OPEN_FLAG_READ|OPEN_FLAG_CTRL);
	if(thread->kcov.fd < 0)	failmsg("failed to open kcov", "res=%i", thread->kcov.fd);

	res = fcntl(thread->kcov.fd, FCNTL_KCOV_INIT);
	if(res < 0)	failmsg("failed to init kcov", "res=%i", res);

	thread->kcov.data = mmap(NULL, KCOV_SIZE, MAP_PROT_READ|MAP_PROT_WRITE, 0/*MAP_NON_CLONED*/, thread->kcov.fd);
	if(PTR_IS_ERR(thread->kcov.data))	failmsg("failed to mmap kcov region", "ret=%p", thread->kcov.data);

	printf("executor ready...\n");
	int cpu;
	while(true)	{
		cpu = receive_execute(thread);
		execute_one(thread, cpu);
		for(i = thread->kcov.fd + 1; i < 10; i++)	{
			close(i);
		}
// 		int child = new_thread((ptr_t)__run_thread, 1, (ptr_t)thread);
// 		printf("Waiting for %i\n", child);
// 		wait_tid(child);
	}
}

int main(int argc, char* argv[])	{
	int res = OK, i;
	int tids[NUM_THREADS] = {0};

	printf("Starting executor\n");

	mutex_clear(&readylock);



	// TODO: Running in one thread gives unstable output
	// - Sometimes we get more outputs than given in
	// - Or the call number is wrong
	//_run_thread(&threads[0]);

	for(i = 0; i < NUM_THREADS; i++)	{
// 		threads[i].arg_offset = (i * ARG_REGION_PER_SIZE);
// 		tids[i] = new_thread((uint64_t)_run_thread, 1, &(threads[i]));

		int p = fork();
		if(p)	{
			printf("child: %i\n", p);
			tids[i] = p;
		} else {
			printf("Running parent\n");
			_run_thread(&threads[i]);
			exit(0);
		}
	}

	printf("Waiting for childs\n");
	// Wait for all threads
// 	for(i = 0; i < NUM_THREADS; i++) { wait_tid(tids[i]); }
 	for(i = 0; i < NUM_THREADS; i++) { wait_pid(tids[i]); }


//	msleep(10000000);
	return res;
}

static uint64_t _read_arg_const(uint64_t** input_posp)	{
	uint64_t meta = read_input(input_posp);
	uint64_t val = read_input(input_posp);

	// Syzkaller will sometimes pass us constants as output address, we need to
	// make sure the address is mapped in
	if(val >= ARG_REGION_ADDR && val <= ARG_REGION_ADDR + ARG_REGION_PER_SIZE)	{
		*(uint8_t*)val = 0x0;
	}
	return val;
}
static int _read_arg_const_in(void* addr, uint64_t** input_posp)	{
	uint64_t meta = read_input(input_posp);
	int size = (int)(meta & 0xff);
	uint64_t val = read_input(input_posp);
	//fail("arg const in not implemented");
	copyin(addr, val, size);
	return OK;
}
static int _read_arg_result_in(void* addr, uint64_t** input_posp)	{
	uint64_t meta = read_input(input_posp);
	uint64_t size = read_input(input_posp);
	uint64_t idx = read_input(input_posp);
	uint64_t op_div = read_input(input_posp);
	uint64_t op_add = read_input(input_posp);
	uint64_t arg = read_input(input_posp);
	fail("result in not implemented");

	return OK;
}
static int _read_arg_data(void* addr, uint64_t** input_posp, void* last)	{
	uint64_t i;
	uint64_t size = read_input(input_posp);
	size &= ~(1ull << 63); // readable flag


	// TODO:
	// - Can write extra if buffer is unaligned, but input buffer is aligned so
	// shouldn't be a problem
	check_len(*input_posp, last, size);
	for(i = 0; i < (size + 7) / 8; i++)	{
		uint64_t val = read_input(input_posp);
		*((uint64_t*)(addr) + i) = val;
	}
	return OK;
}
static uint64_t _read_arg_result(uint64_t** input_posp, struct result_entry* results)	{
	uint64_t meta = read_input(input_posp);
	uint64_t idx = read_input(input_posp);
	uint64_t op_div = read_input(input_posp);
	uint64_t op_add = read_input(input_posp);
	uint64_t arg = read_input(input_posp);
	uint64_t rarg = -1;	// TODO: Set from results

	if(idx > MAX_COMMANDS)	{
		failmsg("bad idx in results", "idx=0x%llx", idx);
	}
	if(results[idx].executed)	{
		rarg = results[idx].arg;

		if(op_div)	rarg /= op_div;
		rarg += op_add;
	}

	return rarg;
}

static int _read_instr_copyin(uint64_t** input_posp, void* last, int64_t offset)	{
	char* addr = (char*)(read_input(input_posp) + offset);
	if((ptr_t)addr < ARG_REGION_ADDR || (ptr_t)addr > ARG_REGION_ADDR + ARG_REGION_PER_SIZE)	{
		failmsg("wrong argument address", "addr=%p\n", addr);
	}
	uint64_t typ = read_input(input_posp);
	switch(typ)	{
		case arg_const:
			check_len(*input_posp, last, 16);
			_read_arg_const_in(addr, input_posp);
			break;
		case arg_result:
			check_len(*input_posp, last, 8 * 6);
			_read_arg_result_in(addr, input_posp);
			break;
		case arg_data:
			check_len(*input_posp, last, 8);
			_read_arg_data(addr, input_posp, last);
			break;
		case arg_csum:
		default:
			failmsg("Unsupported input type", "type=%llu", typ);
			break;
	}
	return OK;
}
static int _read_instr_copyout(uint64_t** input_posp, struct result_entry* results)	{
	uint64_t idx = read_input(input_posp);	// Index
	uint64_t addr = read_input(input_posp);	// Addr
	uint64_t sz = read_input(input_posp);	// Size
	if(idx >= MAX_COMMANDS)	{
		failmsg("too high index in copyout", "idx=0x%llx", idx);
	}
	results[idx].arg = addr;
	results[idx].size = sz;
	results[idx].inmem = true;
	results[idx].executed = false;
	return 0;
}
static uint64_t _read_arg(uint64_t** input_posp, struct result_entry* results, void* last)	{
	uint64_t ret = 0;
	uint64_t typ = read_input(input_posp);
	switch(typ)	{
	case arg_const:
		check_len(*input_posp, last, 8 * 2);
		ret = _read_arg_const(input_posp);
		break;
	case arg_result:
		check_len(*input_posp, last, 8 * 6);
		ret = _read_arg_result(input_posp, results);
		break;
	default:
		failmsg("invalid type", "type=0x%llx", typ);
		break;
	}
	return ret;
}
static uint64_t _read_instr_syscall(uint64_t** input_posp, uint64_t* args, struct result_entry* results, void* last)	{
	uint64_t copyout_index = read_input(input_posp);
	uint64_t num_args = read_input(input_posp);
	int i;
	if(num_args > MAX_ARGS)	{
		failmsg("too many arguments", "count=%llu", num_args);
	}
	check_len(*input_posp, last, 8 * num_args);
	for(i = 0; i < (int)num_args; i++)	{
		args[i] = _read_arg(input_posp, results, last);
	}
	return copyout_index;
}
static int _callidx_to_callno(int callno) {
	int entries = sizeof(syscalls) / sizeof(struct call_t);
	if(callno - SUBTRACT_SYSNO < entries)	{
		struct call_t* c = &(syscalls[callno - SUBTRACT_SYSNO]);
		return c->sys_nr;
	}
	return -1;

}
static uint64_t _execute_call(int callno, uint64_t* args, struct kcov_user* kcov)	{
	uint64_t ret = -1;
	int res;

	int sysno = _callidx_to_callno(callno);
	if(sysno >= 0)	{
//	if(callno - SUBTRACT_SYSNO < entries)	{
//		struct call_t* c = &(syscalls[callno - SUBTRACT_SYSNO]);

		res = fcntl(kcov->fd, FCNTL_KCOV_ENABLE);
		if(res < 0)	failmsg("failed to enable kcov", "res=%i", res);

		ret = svc(sysno, args);

		res = fcntl(kcov->fd, FCNTL_KCOV_DISABLE);
		if(res < 0)	failmsg("failed to disable kcov", "res=%i", res);
	}

	return ret;
}
static int copyin(void* addr, uint64_t val, int size)	{
	switch(size)	{
	case 1:
		WRITE_ONCE(*(uint8_t*)addr, (uint8_t)val);
		break;
	case 2:
		WRITE_ONCE(*(uint8_t*)addr, (uint8_t)val);
		break;
	case 4:
		WRITE_ONCE(*(uint8_t*)addr, (uint8_t)val);
		break;
	case 8:
		WRITE_ONCE(*(uint8_t*)addr, (uint8_t)val);
		break;
	default:
		failmsg("unexpected copyin size", "size=%i", size);
		break;
	}
	return 0;
}
static int copyout(void* addr, int size, uint64_t* res)	{
	switch(size)	{
	case 1:
		*res = *(uint8_t*)addr;
		break;
	case 2:
		*res = *(uint16_t*)addr;
		break;
	case 4:
		*res = *(uint32_t*)addr;
		break;
	case 8:
		*res = *(uint64_t*)addr;
		break;
	default:
		failmsg("copyout: bad size", "size=%llu", size);
		break;
	}
	return 0;
}
static int _store_result(uint64_t res, uint64_t idx, struct result_entry* results)	{
	if(idx == no_copyout)	return 0;
	else if(idx >= MAX_COMMANDS)	{
		failmsg("copyout index is larger than allocated", "idx=0x%llx", idx);
	}
	else	{
		ptr_t arg = res;
		results[idx].executed = true;
		if(results[idx].inmem)	{
			void* addr = (void*)results[idx].arg;
			copyout(addr, results[idx].size, &arg);
		}
		results[idx].arg = arg;
	}
	return 0;
}

size_t write_signal(uint32_t* addr, size_t maxsz, struct kcov_user* kcov)	{
	uint32_t count = READ_ONCE(kcov->data->currcount);
	uint32_t i, val;
	uint64_t edge;
	size_t written = 0;
	for(i = 1; i < count; i++)	{
		if(written >= (maxsz-4))	break;

		edge = kcov->data->entries[i-1] ^ kcov->data->entries[i];
		val = hash(edge);
		addr[i-1] = val;
		written += 4;
	}
	WRITE_ONCE(kcov->data->currcount, 0);
	return written;
}


int execute_one(struct thread_data* thread, int cpu)	{
	uint64_t allargs[MAX_ARGS] = {0};
	struct result_entry results[MAX_COMMANDS] = {0};
	uint64_t callres, outidx;
	int calli = 0;

	uint64_t call_num;
	void* input_pos = (uint64_t*)thread->input_data;
	void* last = input_pos + K_MAX_INPUT;

	void* out_region = thread->out_region;
	void* out_pos = out_region;
	void* out_len;

	//out_pos = out_region + 4;	// Num calls (filled later)
//	out_len = out_pos;	// Save space for size
//	out_pos += 4;

	uint32_t calls = 0;
	bool done = false;
	while(!done)	{
		check_len(input_pos, last, 8);
		call_num = read_input((uint64_t**)&input_pos);
		switch(call_num)	{
		case instr_eof:
			done = true;
			break;
		case instr_copyin:
			check_len(input_pos, last, 16);
			_read_instr_copyin((uint64_t**)&input_pos, last, thread->arg_offset);
			break;
		case instr_copyout:
			check_len(input_pos, last, 8 * 3);
			outidx = _read_instr_copyout((uint64_t**)&input_pos, results);
			break;
		default: {
			check_len(input_pos, last, 8 * 2);
			outidx = _read_instr_syscall((uint64_t**)&input_pos, allargs, results, last);
			// Need to execute call
			callres = _execute_call((int)call_num, allargs, &(thread->kcov));
			if((int64_t)callres > 0)	{
				_store_result(callres, outidx, results);
			}
			calls++;
			write_answer(calli, call_num, callres, &(thread->kcov), &out_pos, out_region, cpu);
			calli++;
			break;
		}
		}
	}
//	*(uint32_t*)out_len = calls;
	struct execute_reply* header = (struct execute_reply*)out_pos;
	header->magic = kOutMagic;
	header->done = (cpu << 16) | 1;	// 0 = callReply follows
	header->status = 0;
	out_pos += sizeof(struct execute_reply);

	mutex_acquire(&readylock);
	int n = write(STDOUT, out_region, out_pos - out_region);
	if(n != (out_pos - out_region))	{
		failmsg("unable to write data", "ret=%x", n);
	}
	mutex_release(&readylock);
	printf("\nwrote %i B\n", n);
	return OK;
}

uint64_t read_input(uint64_t** input_posp)	{
	uint64_t* input_pos = *input_posp;

//	if ((char*)input_pos >= input_data + K_MAX_INPUT)
//		failmsg("input command overflows input", "pos=%p: [%p:%p)", input_pos, input_data, input_data + K_MAX_INPUT);
	*input_posp = input_pos + 1;
	return *input_pos;
}

int receive_execute(struct thread_data* thread)  {
	struct execute_req _req;
	struct execute_req* req = &_req;
	int n;

	// Only one can read input at any given point
	mutex_acquire(&readylock);

	n = read(kInPipeFd, req, sizeof(_req));
	if (n != (ssize_t)sizeof(*req))
		failmsg("control pipe read failed", "n=%i != %i", n, sizeof(*req));
	if (req->magic != kInMagic)
		failmsg("bad execute request magic", "magic=0x%llx", req->magic);
	if (req->prog_size > K_MAX_INPUT)
		failmsg("bad execute prog size", "size=0x%llx", req->prog_size);

	if (req->prog_size == 0)
		fail("need_prog: no program");

	ssize_t rv = read(kInPipeFd, thread->input_data, req->prog_size);
	if (rv < 0)
		fail("read failed");

	mutex_release(&readylock);
	return req->pid;
}

void write_answer(uint32_t calli, uint32_t callno, int64_t errno, struct kcov_user* kcov, void** out_posp, void* out_region, int cpu)	{
	int32_t _errno = (int32_t)errno;

	void* out_pos = *out_posp;

	struct execute_reply* header = (struct execute_reply*)out_pos;
	header->magic = kOutMagic;
	header->done = (cpu << 16) | 0;	// 0 = callReply follows
	header->status = 0;
	out_pos += sizeof(struct execute_reply);

//	void* out_pos = *out_posp;
	struct call_reply* reply = (struct call_reply*)out_pos;
	size_t remspace = OUT_REGION_SIZE - (out_pos - out_region);
	if(sizeof(struct call_reply) > remspace)	{
		failmsg("Not enough space to fit struct and signals in output buffer:", "space=%lu", remspace);
	}
	reply->call_index = calli;
	reply->call_num = callno;
	reply->reserrno = _errno;
	reply->flags = 3;
	reply->cover_size = 0;	// TODO: Should support this
	reply->comps_size = 0;	// Not supported

	out_pos += sizeof(struct call_reply);
	remspace = OUT_REGION_SIZE - (out_pos - out_region);

	size_t writ = write_signal(out_pos, remspace, kcov);
	reply->signal_size = writ / sizeof(uint32_t);

	//if(sigs > 0)	{
	//	memcpy(&(reply->signals[numsigs]), sigs, sizeof(uint32_t) * numsigs);
	//}
	out_pos = out_pos + writ;
	*out_posp = out_pos;
}
