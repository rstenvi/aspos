include $(CROOT)/config.mk

IMAGE_LOAD ?= 0x40080000

OBJ = crt0.o
OBJ += vectors.o
OBJ += exception.o
OBJ += mmu.o
OBJ += aarch64.o
OBJ += arch.o
OBJ += cpu_reset.o
OBJ += thread.o

all: $(OBJ) linker.lds

linker.lds: linker.lds.S
	-rm -f $@
	$(CC) -E -nostdinc -DIMAGE_LOAD=$(IMAGE_LOAD) $< -o $@
	sed -i '/#.*/d' $@
	chmod 400 $@


DEPS := $(OBJ:.o=.d)
-include $(DEPS)

clean:
	-rm -f $(OBJ) linker.lds *.d
