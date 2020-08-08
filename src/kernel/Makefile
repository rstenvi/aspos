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

all: $(OBJ)

DEPS := $(OBJ:.o=.d)
-include $(DEPS)


clean:
	-rm -f $(OBJ) *.d
