include $(CROOT)/config.mk

OBJ += $(wildcard arch/$(ARCH)/*.o)
OBJ += $(wildcard kernel/*.o)
OBJ += $(wildcard drivers/*.o)

LIB = $(wildcard lib/*.o)
OBJ += $(LIB)

ULIB = $(wildcard userlib/*.o)

all: Image libaspos.a

Image: aspos.elf
	$(CROSS_COMPILE)objcopy -O binary aspos.elf Image

aspos.elf: deps
	$(LD) -T arch/$(ARCH)/linker.lds -static $(OBJ) $(LDFLAGS) -o $@ -L$(NEWLIBLOC) -lc

libaspos.a: deps
	$(AR) rs libaspos.a $(LIB) $(ULIB)

disk.img:
	dd if=/dev/zero of=disk.img bs=1024 count=131072
	mkfs.ext2 disk.img

deps:
	make -C arch/$(ARCH)
	make -C kernel
	make -C drivers
	make -C lib
	make -C userlib

run:
	qemu-system-aarch64 $(QEMU_FLAGS)

rundbg:
	qemu-system-aarch64 $(QEMU_FLAGS) -s -S

clean:
	-rm -f aspos.elf Image libaspos.a disk.img
	make -C arch/$(ARCH) clean
	make -C kernel clean
	make -C drivers clean
	make -C lib clean
	make -C userlib clean
