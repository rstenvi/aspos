#include "lib.h"

void __sanitizer_cov_trace_pc(void)	{
	ptr_t pc = (ptr_t)__builtin_return_address(0);

	struct kcov_data* data;
	struct kcov* kcov = get_current_kcov();
	if(PTR_IS_ERR(kcov))	return;
	if(!(kcov->enabled))	return;
	if(PTR_IS_ERR(kcov->data))	return;

	data = kcov->data;

	mutex_acquire(&data->lock);
	if(data->currcount < data->maxcount)	{
		data->entries[data->currcount++] = pc;
	}
	mutex_release(&data->lock);
}
