include $(CROOT)/config.mk

OBJ = kstart.o
OBJ += dtb.o
OBJ += thread.o
OBJ += clibintegration.o
OBJ += pmm.o
OBJ += vmmap.o
OBJ += elf-loader.o
OBJ += power.o
OBJ += vfs.o
OBJ += cmdline.o
#OBJ += slab.o
OBJ += errorhandler.o
OBJ += iovec.o

#ifdef CONFIG_KASAN
#OBJ += kasan.o
#kasan.o: CFLAGS := $(filter-out -fsanitize=kernel-address,$(CFLAGS))
#kcov.o: CFLAGS := $(filter-out -fsanitize=kernel-address,$(CFLAGS))
#ifdef CONFIG_UBSAN
#kasan.o: CFLAGS := $(filter-out -fsanitize=$(UBSAN_SAN),$(CFLAGS))
#endif
#endif

ifdef CONFIG_KCOV
OBJ += kcov.o
kcov.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
kasan.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))

# Lot of noise, but should be fixed
pmm.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
dtb.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
endif

all: $(OBJ)


DEPS := $(OBJ:.o=.d)
-include $(DEPS)

clean:
	-rm -f $(OBJ) *.d *.o
