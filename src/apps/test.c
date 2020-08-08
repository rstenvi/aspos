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

void read_random(void)	{
	char buf[128];
	int res = 22;
	int fd = open("/random", 0, 0);
	if(fd > 0)	{
		res = read(fd, buf, 80);
		printf("read %i bytes | bytes[0] = %x\n", res, buf[0]);
		close(fd);
	}
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

int main(int argc, char* argv[])	{
//	new_thread( (uint64_t) second_main, 1, 42);
//	new_thread( (uint64_t) third_main);
	printf("Hello userworld!\n");

//	read_random();
//	write_block();
	read_block();

	msleep(5000);
	printf("... and goodbye!\n");
	return 0;
}
