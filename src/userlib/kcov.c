#include "lib.h"
#include "memory.h"

void __sanitizer_cov_trace_pc(void)	{
	ptr_t pc = (ptr_t)__builtin_return_address(0);

	struct kcov_data* data = get_current_kcov();
	if(PTR_IS_ERR(data) || READ_ONCE(data->maxcount) == 0)	return;

	// TODO: What to do if the count overflows
	// - In the current setup, we will start overwriting and report only the
	//   overflowed PCs to the caller
	// - Overflow detection is difficult because several threads may get an
	//   overflowed value. Only the thread which received 0 will understand that
	//   overflow happened
	uint32_t count = atomic_inc_fetch32(&(data->currcount));

	if(data->currcount <= data->maxcount)	{
		data->entries[data->currcount-1] = pc;
	}
}
