
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

	fd = open(arg, 0, 0);
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

