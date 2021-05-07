UMODE := 1
CFLAGS += -DUMODE=1

include $(CROOT)/config.mk


OBJ = crt0.o
OBJ += syscalls.o
OBJ += network.o
OBJ += picol.o
OBJ += cmd.o
OBJ += picol_cmds.o
OBJ += aspos.o

# All the object files shared with kernel-mode
SOBJ += bitmap.o
SOBJ += xifo.o
SOBJ += string.o
SOBJ += tlist.o
SOBJ += spinlock.o
SOBJ += llist.o
SOBJ += ringbuf.o
SOBJ += semaphore.o
SOBJ += ubsan.o

network.o: CFLAGS += -DLWIP_USER=1

ifdef CONFIG_KCOV
OBJ += kcov.o
kcov.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
crt0.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
ubsan.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
syscalls.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
endif

all: $(OBJ) drivers lwip ustar $(SOBJ)

DEPS := $(OBJ:.o=.d)
-include $(DEPS)

SDEPS := $(SOBJ:.o=.d)
-include $(SDEPS)

drivers:
	make -C drivers
lwip:
	make -C lwip
ustar:
	make -C fs/ustar

%.o: ../lib/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-rm -f $(OBJ) *.d *.o
	make -C drivers clean
	make -C lwip clean
	make -C fs/ustar clean

.PHONY: clean drivers lwip
