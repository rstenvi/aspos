#include "kernel.h"
#include <string.h>

struct cmdarg {
	char* key;
	char* val;
};

struct cmdargs {
	struct cmdarg* args;
	size_t size;
};

static struct cmdargs cmdargs;


char* cmdarg_value(const char* key)	{
	int i;
	for(i = 0; i < cmdargs.size; i++)	{
		if(strcmp(key, cmdargs.args[i].key) == 0)	{
			return cmdargs.args[i].val;
		}
	}
	return NULL;
}

static int _set_arg(int idx, char* key, char* val)	{
	ASSERT_TRUE(idx < cmdargs.size, "Kernel error");
	cmdargs.args[idx].key = key;
	cmdargs.args[idx].val = val;
	return OK;
}

static int _set_args(const char* t, char c)	{
	char* curr = (char*)t, * prev = (char*)t, * sep;
	int idx = 0;
	curr = strchr(t, c);

	while(curr != NULL)	{
		sep = strchr(prev, '=');
		if(sep < curr)	{
			*sep = 0x00;
			sep++;
		}
		else			sep = NULL;

		_set_arg(idx, prev, sep);

		while( *curr == c ) curr++;
		prev = curr;
		curr = strchr(curr, c);

		idx++;
	}

	sep = strchr(prev, '=');
	if(sep != NULL)	{
		*sep = 0x00;
		sep++;
	}
	_set_arg(idx, prev, sep);
	return idx;
}

int cmdline_init(void)	{
	struct dtb_node* chosen;
	char* line = NULL;
	
	// None of the values are guaranteed to be present
	chosen = dtb_find_name("chosen", true, 0);
	if(chosen == NULL)	return -GENERAL_FAULT;


	line = (char*)dtb_get_string(chosen, "bootargs");
	if(line == NULL)	return -GENERAL_FAULT;

	
	cmdargs.size = char_in_string(line, ' ') + 1;
	cmdargs.args = (struct cmdarg*)kmalloc( cmdargs.size * sizeof(struct cmdarg) );
	if(cmdargs.args == NULL)	{
		cmdargs.size = 0;
		return -MEMALLOC;
	}

	_set_args(line, ' ');
	return OK;
}

early_hw_init(cmdline_init);

int cmdline_exit(void)	{
	kfree(cmdargs.args);
	return 0;
}
poweroff_exit(cmdline_exit);
