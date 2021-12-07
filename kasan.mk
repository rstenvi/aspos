CFLAGS += -fsanitize=kernel-address
CFLAGS += -DCONFIG_KASAN=1
ASFLAGS += -DKASAN_ENABLE=1

