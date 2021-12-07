#include <unistd.h>
#include <fcntl.h>
#include "picol.h"
#include "cmd.h"
#include "lib.h"

#define BUFFER_SIZE (128)

int picol_cat(struct picolInterp *i, int argc, char **argv, void *pd)	{
	int idx, res;
	for(idx = 1; idx < argc; idx++)	{
		res = cmd_cat(argv[idx], STDOUT);
		if(res < 0)	{
			aerror(res, "cat");
		}
	}
	return 0;
}

int picol_poweroff(struct picolInterp *i, int argc, char **argv, void *pd)	{
	poweroff();

	// Shouldn't return here
	return -GENERAL_FAULT;
}

static void normalize_input(char* str, int len)	{
	if(str[len-1] == '\n')	str[len-1] = 0x00;
}

int picol_loop(const char* pre, struct picolInterp* interp, int fdin, int fdout)	{
	char buf[BUFFER_SIZE];
	int res, pcode, len = strlen(pre);
	while(true)	{
		write(fdout, pre, len);
		res = read(fdin, buf, BUFFER_SIZE);
		if(res < 0)	{
			aerror(res, "read input");
			return res;
		}
		if(res >= BUFFER_SIZE)	{
			printf("Input buffer was larger than supported %i", res);
			return -1;
		}
		normalize_input(buf, res);
		pcode = picolEval(interp, buf);
		if(pcode != PICOL_OK)	{
			printf("Unable to parse: '%s' | error: %i\n", buf, pcode);
		}
	}
}
