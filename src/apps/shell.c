#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>

#include "lib.h"
#include "picol.h"

#define ROOT_BLOCK_DEV "/dev/block"
int create_rootfs(void)	{
	printf("Mounting rootfs\n");
	int blockfd, res;
	blockfd = open(ROOT_BLOCK_DEV, OPEN_FLAG_RW, 0);
	if(blockfd < 0)	{
		printf("Unable to find block device at '%s'\n", ROOT_BLOCK_DEV);
		return -1;
	}

	res = init_ustart("/", blockfd);
	if(res != 0)	{
		printf("init_ustart: %i\n", res);
	}
	return res;
}

int shell_help(struct picolInterp *i, int argc, char **argv, void *pd)	{
	printf("Valid commands\n"
	"\techo | cat | poweroff\n"
	);
	return 0;
}

void conf_run_picol(void)	{
	struct picolInterp interp;
	picolInitInterp(&interp);
	picolRegisterCoreCommands(&interp);
	// TODO: Existing puts is not really versatile enough, should change it
	picolRegisterCommand(&interp, "echo", picolCommandPuts, NULL);
	picolRegisterCommand(&interp, "cat", picol_cat, NULL);
	picolRegisterCommand(&interp, "poweroff", picol_poweroff, NULL);
	picolRegisterCommand(&interp, "exit", picol_poweroff, NULL);
	picolRegisterCommand(&interp, "help", shell_help, NULL);
	picolRegisterCommand(&interp, "?", shell_help, NULL);

	fcntl(STDIN, CONSOLE_FCNTL_MODE, CHAR_MODE_LINE_ECHO);
	picol_loop("aspos$ ", &interp, STDIN, STDOUT);
}


int main(int argc, char* argv[])	{
	create_rootfs();
	conf_run_picol();
	return 0;
}
