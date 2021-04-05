include $(CROOT)/config.mk

OBJ = ustar.o

all: $(OBJ)

DEPS := $(OBJ:.o=.d)
-include $(DEPS)

clean:
	-rm -f $(OBJ) *.d

ustar: ustar.c
	gcc -I../../../include -g -include config.h -o ustar ustar.c

.PHONY: clean
