include $(CROOT)/config.mk

IMAGE_LOAD ?= 0x40080000
#IMAGE_LOAD = 0x60000000

CFLAGS += -DIMAGE_LOAD=$(IMAGE_LOAD)

OBJ = crt0.o
OBJ += vectors.o
OBJ += exception.o
OBJ += mmu.o
OBJ += aarch64.o
OBJ += arch.o
OBJ += cpu_reset.o
OBJ += cpu_features.o
OBJ += svc.o

# All access to the tables generate array-bounds errors
mmu.o: CFLAGS += -Wno-array-bounds

ifdef CONFIG_KASAN
CFLAGS := $(filter-out -fsanitize=kernel-address,$(CFLAGS))
#mmu.o: CFLAGS := $(filter-out -fsanitize=kernel-address,$(CFLAGS))
#arch.o: CFLAGS := $(filter-out -fsanitize=kernel-address,$(CFLAGS))
#cpy_features.o: CFLAGS := $(filter-out -fsanitize=kernel-address,$(CFLAGS))
endif

ifdef CONFIG_KCOV
crt0.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
mmu.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
arch.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
exception.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
cpu_features.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
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
