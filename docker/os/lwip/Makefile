CROSS_COMPILE = aarch64-none-elf-

CC=$(CROSS_COMPILE)gcc
AR=$(CROSS_COMPILE)ar

CFLAGS += -g
CFLAGS += -Ilwip/src/include/
CFLAGS += -Iinclude

SAPI = lwip/src/api
SDIR = lwip/src/core
NDIR = lwip/src/netif

CSRC += $(wildcard lwip/src/core/*.c)
CSRC += $(wildcard lwip/src/core/ipv4/*.c)
CSRC += $(wildcard lwip/src/api/*.c)
CSRC += $(wildcard lwip/src/netif/*.c)

LDFLAGS += -L/opt/cross/aarch64-none-elf/lib
LDFLAGS += -lc
LDFLAGS += -L.
LDFLAGS += -llwip4

OBJ=${CSRC:.c=.o}


all: liblwip4.a

liblwip4.a: $(OBJ)
	$(AR) rs liblwip4.a $(OBJ)

%.o: $(SDIR)/%.c
	$(CC) -c -o $@ $^ $(CFLAGS)

%.o: $(SDIR)/ipv4/%.c
	$(CC) -c -o $@ $^ $(CFLAGS)

%.o: $(SAPI)/%.c
	$(CC) -c -o $@ $^ $(CFLAGS)

%.o: $(NDIR)/%.c
	$(CC) -c -o $@ $^ $(CFLAGS)

clean:
	-rm $(OBJ) liblwip4.a
