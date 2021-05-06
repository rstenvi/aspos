include $(CROOT)/config.mk

IMAGE_LOAD ?= 0x40080000

OBJ = crt0.o
OBJ += vectors.o
OBJ += exception.o
OBJ += mmu.o
OBJ += aarch64.o
OBJ += arch.o
OBJ += cpu_reset.o
OBJ += cpu_features.o


ifdef CONFIG_KASAN
CFLAGS := $(filter-out -fsanitize=kernel-address,$(CFLAGS))
#mmu.o: CFLAGS := $(filter-out -fsanitize=kernel-address,$(CFLAGS))
#arch.o: CFLAGS := $(filter-out -fsanitize=kernel-address,$(CFLAGS))
#cpy_features.o: CFLAGS := $(filter-out -fsanitize=kernel-address,$(CFLAGS))
endif

ifdef CONFIG_KCOV
CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
endif

all: $(OBJ) linker.lds

linker.lds: linker.lds.S
	-rm -f $@
	$(CC) -I$(CROOT)/src/include -include config.h -E -nostdinc -DIMAGE_LOAD=$(IMAGE_LOAD) $< -o $@
	sed -i '/#.*/d' $@
	chmod 400 $@


DEPS := $(OBJ:.o=.d)
-include $(DEPS)

clean:
	-rm -f $(OBJ) linker.lds *.d *.o
