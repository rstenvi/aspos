#include "lib.h"
#include "memory.h"

void __sanitizer_cov_trace_pc(void)	{
	ptr_t pc = (ptr_t)__builtin_return_address(0);

	struct kcov_data* data = get_current_kcov();
	if(PTR_IS_ERR(data) || READ_ONCE(data->maxcount) == 0)	return;

	uint32_t count = atomic_inc_fetch32(&(data->currcount));
	if(count <= data->maxcount)	{
		WRITE_ONCE(data->entries[count-1], pc);
	}
}
