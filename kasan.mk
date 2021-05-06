CFLAGS += -fsanitize=kernel-address
CFLAGS += -fsanitize-address-use-after-scope
CFLAGS += -DCONFIG_KASAN=1

