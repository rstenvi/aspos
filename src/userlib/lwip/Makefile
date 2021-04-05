include $(CROOT)/config.mk

OBJ += lwip_semaphore.o
OBJ += lwip_misc.o
OBJ += lwip_mbox.o
OBJ += lwip_netif.o

CFLAGS += -DLWIP_USER=1

all: $(OBJ)

DEPS := $(OBJ:.o=.d)
-include $(DEPS)

clean:
	-rm -f $(OBJ) *.d

.PHONY: clean
