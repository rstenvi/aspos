include $(CROOT)/config.mk

OBJ = pl011.o
OBJ += gic.o
OBJ += arm-timer.o
OBJ += cpus.o
OBJ += pl061.o
OBJ += psci.o
OBJ += virtio.o
OBJ += virtio-rng.o
OBJ += virtio-net.o
OBJ += virtio-blk.o
OBJ += virtio-socket.o
OBJ += virtio-console.o
OBJ += mutex.o
OBJ += semaphore.o
OBJ += cuse.o
OBJ += umem.o

ifdef CONFIG_UBSAN
OBJ += ubsan-test.o
endif

ifdef CONFIG_KASAN
OBJ += kasan-test.o
endif

all: $(OBJ)

DEPS := $(OBJ:.o=.d)
-include $(DEPS)

clean:
	-rm -f $(OBJ) *.d *.o
