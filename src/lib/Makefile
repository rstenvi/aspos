include $(CROOT)/config.mk

OBJ = bitmap.o
OBJ += xifo.o
OBJ += string.o
OBJ += tlist.o
OBJ += spinlock.o
OBJ += llist.o
OBJ += ringbuf.o
OBJ += semaphore.o
OBJ += vector.o

ifdef CONFIG_KASAN
OBJ += kasan.o
kasan.o: CFLAGS := $(filter-out -fsanitize=kernel-address,$(CFLAGS))
kcov.o: CFLAGS := $(filter-out -fsanitize=kernel-address,$(CFLAGS))

ifdef CONFIG_UBSAN
kasan.o: CFLAGS := $(filter-out -fsanitize=$(UBSAN_SAN),$(CFLAGS))
endif
endif

ifdef CONFIG_UBSAN
OBJ += ubsan.o
ubsan.o: CFLAGS := $(filter-out -fsanitize=$(UBSAN_SAN),$(CFLAGS))
endif

ifdef CONFIG_KCOV
spinlock.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
kasan.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
# Lots of noise, should be fixed
bitmap.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
endif

all: $(OBJ)

DEPS := $(OBJ:.o=.d)
-include $(DEPS)


clean:
	-rm -f $(OBJ) *.d *.o
