#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
 
extern void _exit(int);
extern int main ();

#if CONFIG_INIT_RANDOM_SEED
static void _seed_random(void);
#endif

void _start(uint64_t argc, uint64_t argv, uint64_t envp) {
	/*
	* Open stdin, stdout and stderr
	* If any gets an unexpected result, we exit
	*/
	int in, out, err;
	in = open("/dev/console", 0, 0);
	if(in != 0)	_exit(in);

	out = dup(in);
	if(out != 1)	_exit(out);

	err = dup(out);
	if(err != 2)	_exit(err);

#if CONFIG_INIT_RANDOM_SEED
	_seed_random();
#endif

    int ex = main(argc, argv, envp);
    _exit(ex);
}

#if CONFIG_INIT_RANDOM_SEED
static void _seed_random(void)	{
	int res;
	unsigned int seed;
	int rand = open("/dev/random", 0, 0);
	if(rand < 0)	{
		puts("Failed to open random driver\n");
		_exit(rand);
	}
	res = read(rand, &seed, sizeof(unsigned int));
	if(res != sizeof(unsigned int))	{
		puts("Failed to read acquired number of bytes from random driver\n");
		_exit(res);
	}
	srandom(seed);
}
#endif
