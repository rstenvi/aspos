#include "kernel.h"

/**
* Panic implementation which prints an error message and halts execution.
*/
void panic(const char* msg, const char* file, int line) {
	// We always want to reliably print some type of message
	puts(msg);
	puts("\n");

	// We then try and print some details about environment
	printf("Location: %s:%i\n", file, line);
	arch_dump_regs();
	while(1);
}

void memory_error(ptr_t addr, ptr_t ip, bool user, bool instr, bool write)	{
	loge("Memory access: %lx %lx user=%i instr=%i write=%i\n", addr, ip, user, instr, write);
	if(!user)	{
		loge("Kernel access, need to shut down system\n");
		arch_dump_regs();
		kern_poweroff(true);
	}
	else	{
		logw("User access, shutting down thread\n");
		thread_exit(1);
	}
}
/*
void bugprintf(const char* fmt, ...)	{
#define BUG_MAX (256)
	char bug[BUG_MAX];
	int res;
	va_list argptr;
	va_start(argptr, fmt);
	res = snprintf(bug, BUG_MAX, fmt, argptr);
	va_end(argptr);
	if(res > 0 && res < BUG_MAX)	{
		bughandler_write_data(bug, res + 1);
	}
}
*/
