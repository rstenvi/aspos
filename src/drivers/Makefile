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

all: $(OBJ)

DEPS := $(OBJ:.o=.d)
-include $(DEPS)

clean:
	-rm -f $(OBJ) *.d
