#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include "lib.h"
#include "arch.h"
 
extern void _exit(int);
extern int main ();
//#define CONFIG_USER_THREAD_INFO 1

#if CONFIG_USER_THREAD_INFO
struct user_thread_info threadinfo = {0};
#endif

//#define CONFIG_CREATE_THREAD_EXIT 1
//#define CONFIG_CREATE_DEV_NULL    1

#if CONFIG_CREATE_THREAD_EXIT
void _exception_exit(int);
#endif

#if CONFIG_INIT_RANDOM_SEED
static void _seed_random(void);
#endif

void _start(uint64_t argc, uint64_t argv, uint64_t envp) {
	/*
	* Open stdin, stdout and stderr
	* If any gets an unexpected result, we exit
	*/
	int in, out, err;
	in = open("/dev/console", OPEN_FLAG_RW | OPEN_FLAG_CTRL, 0);
	if(in != 0)	_exit(in);

	out = dup(in);
	if(out != 1)	_exit(out);

	err = dup(out);
	if(err != 2)	_exit(err);

#ifdef CONFIG_KASAN
	kasan_init();

	ptr_t stack_end = GET_ALIGNED_PAGE_UP(get_stack());
	ptr_t stack_beg = stack_end - (CONFIG_THREAD_STACK_BLOCKS * PAGE_SIZE);
	kasan_mark_valid(stack_beg, stack_end - stack_beg);

	// TODO:
	// - These could be larger than a page size
	// - Solution is to parse argc and argv to mark those regions as valid
	if(argv != 0)	kasan_mark_valid(argv, PAGE_SIZE);
	if(envp != 0)	kasan_mark_valid(envp, PAGE_SIZE);
#endif

#if CONFIG_USER_THREAD_INFO
	conf_process(PROC_STORE_THREAD_INFO, (ptr_t)(&threadinfo));
#endif

#if CONFIG_INIT_RANDOM_SEED
	_seed_random();
#endif

#if CONFIG_CREATE_THREAD_EXIT
	conf_thread(THREAD_CONF_THREAD_EXIT, (ptr_t)_exception_exit);
	conf_thread(THREAD_CONF_EXC_EXIT, (ptr_t)_exception_exit);
#endif
#if CONFIG_CREATE_DEV_NULL
	int fdnull = init_dev_null(true);
	if(fdnull < 0)	{
		_exit(fdnull);
	}
#endif

    int ex = main(argc, argv, envp);
#ifdef CONFIG_KASAN
	kasan_print_allocated();
#endif
    _exit(ex);
}

#if CONFIG_CREATE_THREAD_EXIT
void _exception_exit(int arg)	{
	exit_thread(arg);
}
#endif

#if CONFIG_INIT_RANDOM_SEED
static void _seed_random(void)	{
	int res;
	unsigned int seed = 0;
	int rand = open("/dev/random", OPEN_FLAG_READ);
	if(rand < 0)	{
		puts("Failed to open random driver\n");
		_exit(rand);
	}
	res = read(rand, &seed, sizeof(unsigned int));
	if(res != sizeof(unsigned int))	{
		puts("Failed to read acquired number of bytes from random driver\n");
		_exit(res);
	}
	printf("SEED: 0x%x\n", seed);
	srandom(seed);
	close(rand);
}
#endif
