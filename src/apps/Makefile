UMODE := 1
CFLAGS += -DUMODE=1

include $(CROOT)/config.mk

LDFLAGS += -L$(NEWLIBLOC)
LDFLAGS += -static
LDFLAGS += -T aspos-user.ld

# EXTRALIBS are included before the standard aspos and c on the command line
EXTRALIBS = 
LDLIBS += -laspos
LDLIBS += -lc

OBJ += test.o
OBJ += network.o
OBJ += netcat.o
OBJ += shell.o
OBJ += fuzzer.o
OBJ += executor.o

PROGS := $(OBJ:.o=)

all: $(OBJ) $(PROGS)

DEPS := $(OBJ:.o=.d)
-include $(DEPS)

# See https://stackoverflow.com/a/3263435
# for more details about target-specific flags
network.o: CFLAGS += -DLWIP_USER=1
netcat.o: CFLAGS += -DLWIP_USER=1
netcat: EXTRALIBS += -llwip4
network: EXTRALIBS += -llwip4

# TODO: Still in development, fix eventually
executor.o: CFLAGS += -Wno-unused-variable

ifdef CONFIG_KCOV
fuzzer.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
executor.o: CFLAGS := $(filter-out -fsanitize-coverage=trace-pc,$(CFLAGS))
endif

ifdef CONFIG_KASAN
executor.o: CFLAGS := $(filter-out -fsanitize=kernel-address,$(CFLAGS))
endif

%: %.o
	 $(LD) $(LDFLAGS) $^ -o $@ $(EXTRALIBS) $(LDLIBS)

clean:
	-rm -f *.o *.d $(PROGS)
