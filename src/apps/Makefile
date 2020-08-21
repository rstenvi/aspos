include $(CROOT)/config.mk

LDFLAGS += -L$(NEWLIBLOC)
LDFLAGS += -static
LDFLAGS += -T aspos-user.ld

OBJ += test.o
OBJ += network.o
OBJ += netcat.o

all: $(OBJ) test network netcat

DEPS := $(OBJ:.o=.d)
-include $(DEPS)

test: test.o
	 $(LD) $(LDFLAGS) $^ -o $@ -laspos -lc 

network: network.o
	 $(LD) $(LDFLAGS) $^ -o $@ -llwip4 -laspos -lc

netcat: netcat.o
	 $(LD) $(LDFLAGS) $^ -o $@ -llwip4 -laspos -lc


clean:
	-rm -f *.o *.d test network netcat
