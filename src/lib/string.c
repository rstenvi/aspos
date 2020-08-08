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
