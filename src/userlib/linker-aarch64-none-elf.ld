OUTPUT_ARCH(aarch64)
ENTRY(_start)

SECTIONS {
	. = 0x400000;
	.init   : { crt0.o(.text) }
	.text   : { *(.text) }

	. = ALIGN(0x1000);

	.data   : { *(.data) }
	.bss   : { *(.bss) }
}
