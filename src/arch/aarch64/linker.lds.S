#include "aarch64.h"

OUTPUT_ARCH(aarch64)
ENTRY(_start)

SECTIONS {
	REAL_LOAD = IMAGE_LOAD;
	. = IMAGE_LOAD;
	.init.text : {
		*(.init)
		. = ALIGN(ALIGN_SAME_SECTION);
		*(.cpureset)
	}
	.init.bss (NOLOAD) : ALIGN(ARM64_PAGE_SIZE) {
		user_pgd = .; . += ARM64_PAGE_SIZE;
#if ARM64_VA_BITS > 39
		kernel_pgd = .; . += ARM64_PAGE_SIZE;
#endif
		kernel_pud = .; . += ARM64_PAGE_SIZE;
		kernel_pmd = .; . += ARM64_PAGE_SIZE;
/*		kernel_ptd = .; . += ARM64_PAGE_SIZE; */
		KSTACK_INIT_LOW = .; . += ARM64_PAGE_SIZE; KSTACK_INIT_HIGH = .;
	}
	
	IMAGE_INIT_END = .;
	start_vectortables = .;

	. += ARM64_VA_KERNEL_FIRST_ADDR;

	KERNEL_START = .;
	
	.text : AT (ADDR (.text) - ARM64_VA_KERNEL_FIRST_ADDR) ALIGN(ARM64_PAGE_SIZE) {
		KERNEL_TEXT_START = .;
		. = ALIGN(ALIGN_VECTORTABLE); *(.vectortable)
		*(.text*)
		KERNEL_TEXT_STOP = .;
		. = ALIGN(ARM64_PAGE_SIZE);
	}
	.data : AT (ADDR (.data) - ARM64_VA_KERNEL_FIRST_ADDR) ALIGN(ARM64_PAGE_SIZE) {
		KERNEL_DATA_START = .;


		*(.data*)

		KERNEL_DATA_STOP = .;
	}

	. = ALIGN(ALIGN_DIFF_SECTION);

	.rodata : AT(ADDR (.rodata) - ARM64_VA_KERNEL_FIRST_ADDR) ALIGN(ARM64_PAGE_SIZE) {
		KERNEL_RODATA_START = .;
		*(.rodata*)

		. = ALIGN(ALIGN_SAME_SECTION);
		DRVFUNC_START = .;
		*(.kernel.data.drvfunc)
		DRVFUNC_STOP = .;

		. = ALIGN(ALIGN_SAME_SECTION);
		HMEMFUNC_START = .;
		*(.kernel.data.hmemfunc)
		HMEMFUNC_STOP = .;

		. = ALIGN(ALIGN_SAME_SECTION);
		EARLYHW_START = .;
		*(.kernel.data.earlyhwfunc)
		EARLYHW_STOP = .;

		. = ALIGN(ALIGN_SAME_SECTION);
		EXITFUNC_START = .;
		*(.kernel.data.exitfunc)
		EXITFUNC_STOP = .;

		. = ALIGN(ALIGN_SAME_SECTION);
		CPUCORE_START = .;
		*(.kernel.data.cpufunc)
		CPUCORE_STOP = .;

		. = ALIGN(ALIGN_SAME_SECTION);
		ALTINSTR_START = .;
		*(.data.altinstr)
		ALTINSTR_STOP = .;


		. = ALIGN(ALIGN_SAME_SECTION);
		KERNEL_RODATA_STOP = .;
	}

	. = ALIGN(ALIGN_DIFF_SECTION);

	.bss : AT (ADDR (.bss) - ARM64_VA_KERNEL_FIRST_ADDR) ALIGN(ARM64_PAGE_SIZE) {
		KERNEL_BSS_START = .;
		*(.bss*)
		KERNEL_BSS_STOP = .;

	}
	KERNEL_END = .;
	IMAGE_END = .;
}

