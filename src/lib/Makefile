include $(CROOT)/config.mk

OBJ = bitmap.o
OBJ += xifo.o
OBJ += string.o
OBJ += tlist.o
OBJ += spinlock.o
OBJ += llist.o
OBJ += ringbuf.o
OBJ += semaphore.o

all: $(OBJ)

DEPS := $(OBJ:.o=.d)
-include $(DEPS)


clean:
	-rm -f $(OBJ) *.d
