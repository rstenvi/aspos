
#include <unistd.h>
#include <fcntl.h>
#include "cmd.h"

#define BUFFER_SIZE (128)

void aerror(int errno, const char* msg)	{
	printf("%s: errno: %i\n", msg, errno);
}

int cmd_cat(char* arg, int fdo)	{
	char buf[BUFFER_SIZE];
	int num, total = 0, fd;

	fd = open(arg, OPEN_FLAG_READ, 0);
	if(fd < 0)	return fd;

	do	{
		num = read(fd, buf, BUFFER_SIZE);
		if(num > 0)	{
			write(fdo, buf, num);
			total += num;
		}
	} while(num >= BUFFER_SIZE);
	return total;
}
int cmd_echo(int argc, char* argv[])	{
	int i;
	for(i = 0; i < argc; i++)	{
		write(STDOUT, argv[i], strlen(argv[i]));
		if(i < argc-1)	write(STDOUT, " ", 1);
	}
	write(STDOUT, "\n", 1);
	return OK;
}
