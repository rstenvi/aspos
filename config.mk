include $(CROOT)/cc_config.mk

ARMV_MAJOR = 8
ARMV_MINOR = 0
ARM_PROFILE = a

ifeq ($(ARMV_MINOR),0)
MARCH=armv$(ARMV_MAJOR)-$(ARM_PROFILE)
else
MARCH=armv$(ARMV_MAJOR).$(ARMV_MINOR)-$(ARM_PROFILE)
endif

UPROG = test


TARGET = aarch64-none-elf
CROSS_COMPILE = $(TARGET)-

NEWLIBLOC ?= /opt/cross/${TARGET}/lib

CC = $(CROSS_COMPILE)gcc
AS = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
AR = $(CROSS_COMPILE)ar
STRIP = $(CROSS_COMPILE)strip

SH_FLAGS += -march=$(MARCH)+fp+simd+nosve
SH_FLAGS += -DARMV_MAJOR=$(ARMV_MAJOR)
SH_FLAGS += -DARMV_MINOR=$(ARMV_MINOR)
SH_FLAGS += -DARM_PROFILE=$(ARM_PROFILE)
SH_FLAGS += -include config.h

# float-cast-overflow, pointer-overflow
#UBSAN_SAN = alignment,bool,builtin,bounds,enum,integer-divide-by-zero,nonnull-attribute,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound

CFLAGS += -I$(CROOT)/src/include -I$(CROOT)/src/arch/$(ARCH)
CFLAGS += -MMD

# TODO: Should fix the remaining warnings
CFLAGS += -Wall -Wextra -Werror -Wno-unused-function -Wno-unused-parameter -Wno-unused-but-set-variable

ifdef DEBUG_BUILD
CFLAGS += -g
CFLAGS += -O1
else
CFLAGS += -O2
endif

ifdef CONFIG_UBSAN
include $(CROOT)/ubsan.mk
endif

ifdef CONFIG_KASAN
include $(CROOT)/kasan.mk
endif

ifdef CONFIG_KCOV
include $(CROOT)/kcov.mk
endif

ASFLAGS += -I$(CROOT)/src/include


ifneq ("$(wildcard $(CROOT)/userconfig.mk)","")
include $(CROOT)/userconfig.mk
endif

# Place these last so that userconfig.mk can put data into SH_FLAGS

CFLAGS += $(SH_FLAGS)
ASFLAGS += $(SH_FLAGS)

QEMU_FLAGS += -machine virt
# Test older:
# - cortex-a57
QEMU_FLAGS += -cpu cortex-a72
QEMU_FLAGS += -nographic

# https://fadeevab.com/how-to-setup-qemu-output-to-console-and-automate-using-shell-script/
#QEMU_FLAGS += -serial pipe:/tmp/guest
QEMU_FLAGS += -smp 1
# TODO: There are some assumptions on the amount of memory in the code
QEMU_FLAGS += -m 128M

QEMU_FLAGS += -d unimp,guest_errors

# Variables which should be defined in userconfig.mk
ifdef USERARGS
KERNEL_APPEND += userargs=$(USERARGS)
endif

ifdef KERNEL_APPEND
QEMU_FLAGS += -append "$(KERNEL_APPEND)"
endif

ifeq ($(USE_DISK),1)
QEMU_FLAGS += -device virtio-blk-device,drive=hd0 -drive file=rootfs.tar,id=hd0,if=none,format=raw
endif

#QEMU_FLAGS += -device vhost-vsock-device,guest-cid=3
#QEMU_FLAGS += -chardev socket,host=127.0.0.1,port=8181,id=foo -device virtio-serial-device -device virtserialport,chardev=foo,id=test0,nr=1

# RNG device
QEMU_FLAGS += -object rng-random,filename=/dev/random,id=rng0
QEMU_FLAGS += -device virtio-rng-device,rng=rng0

# Useful for debugging
ifeq ($(QEMU_TRACE),1)
QEMU_FLAGS += -trace events=events
endif

# Networking
# tap device (requires admin)
# -netdev type=tap,id=net0 -device virtio-net-device,netdev=net0

NET_SHARED = net=192.168.1.0/24,dhcpstart=192.168.1.10

# Standard user
QEMU_FLAGS += -netdev user,id=net0,$(NET_SHARED)

# tap with root
#QEMU_FLAGS += -netdev type=tap,id=net0,$(NET_SHARED)

# tap w/o root
#QEMU_FLAGS += -netdev user,type=tap,ifname=tap0,id=net0,script=no,downscript=no
#QEMU_FLAGS += -netdev user,type=tap,ifname=tap0,id=net0

# Config of interface in guest
QEMU_FLAGS += -device virtio-net-device,netdev=net0


QEMU_FLAGS += -kernel Image
QEMU_FLAGS += -initrd apps/$(UPROG)

