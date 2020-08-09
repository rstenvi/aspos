include $(CROOT)/config.mk

LDFLAGS += -L$(NEWLIBLOC)
LDFLAGS += -static
LDFLAGS += -T aspos-user.ld

all: test network netcat


test: test.o
	 $(LD) $(LDFLAGS) $^ -o $@ -laspos -lc 

network: network.o
	 $(LD) $(LDFLAGS) $^ -o $@ -llwip4 -laspos -lc

netcat: netcat.o
	 $(LD) $(LDFLAGS) $^ -o $@ -llwip4 -laspos -lc

DEPS := $(OBJ:.o=.d)
-include $(DEPS)

clean:
	-rm -f *.o *.d test network netcat
