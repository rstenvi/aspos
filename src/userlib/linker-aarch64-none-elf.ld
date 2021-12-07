OUTPUT_ARCH(aarch64)
ENTRY(_start)

SECTIONS {
	. = 0x400000;
	UMODE_IMAGE_START = .;
	.init   : { crt0.o(.text) }
	.text   : { *(.text*) }

	. = ALIGN(4096);

	.rodata : { *(.rodata*) }
	. = ALIGN(4096);
	.data   : { *(.data*) }
	. = ALIGN(4096);
	.bss   : { *(.bss*) }
	UMODE_IMAGE_STOP = .;
}
