#include <string.h>
#include "lib.h"


int char_in_string(const char* s, char c)	{
	int ret = 0;
	char* curr = NULL;
	curr = strchr(s, c);
	while(curr != NULL)	{
		ret++;
		while( *curr == c ) curr++;
		curr = strchr(curr, c);
	}
	return ret;
}

/*
* If we use KASAN we must override some functions in newlib which allocates
* memory.
*
* Code in newlib is not instrumented, so that code can freely access any memory,
* but as soon as the memory is returned to us, it becomes invalid and will
* trigger a false positive.
*/
#ifdef CONFIG_KASAN
char* strdup(const char* s)   {
	size_t l = strlen(s);
	char* ret = kmalloc(l+1);
	strcpy(ret, s);
	return ret;
}
char* strndup(const char* s, size_t n)	{
	size_t l = MIN(strlen(s), n);
	char* ret = kmalloc(l+1);
	strncpy(ret, s, l);
	ret[l] = 0x0;
	return ret;
}
#endif
