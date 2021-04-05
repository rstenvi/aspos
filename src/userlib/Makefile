include $(CROOT)/config.mk

OBJ = crt0.o
OBJ += syscalls.o
OBJ += network.o
OBJ += picol.o
OBJ += cmd.o
OBJ += picol_cmds.o
OBJ += aspos.o

network.o: CFLAGS += -DLWIP_USER=1

all: $(OBJ) drivers lwip ustar

DEPS := $(OBJ:.o=.d)
-include $(DEPS)

drivers:
	make -C drivers
lwip:
	make -C lwip
ustar:
	make -C fs/ustar
clean:
	-rm -f $(OBJ) *.d
	make -C drivers clean
	make -C lwip clean
	make -C fs/ustar clean

.PHONY: clean drivers lwip
