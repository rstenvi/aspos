UMODE := 1
CFLAGS += -DUMODE=1
include $(CROOT)/config.mk

OBJ = null.o
OBJ += proc.o

all: $(OBJ)

DEPS := $(OBJ:.o=.d)
-include $(DEPS)

clean:
	-rm -f $(OBJ) *.d
