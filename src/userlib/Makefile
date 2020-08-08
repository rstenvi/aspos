include $(CROOT)/config.mk

OBJ = crt0.o
OBJ += syscalls.o
OBJ += lwip_semaphore.o
OBJ += lwip_misc.o
OBJ += lwip_mbox.o
OBJ += lwip_mutex.o
OBJ += lwip_netif.o


all: $(OBJ)

DEPS := $(OBJ:.o=.d)
-include $(DEPS)

clean:
	-rm -f $(OBJ) *.d
