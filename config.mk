
ARMV_MAJOR = 8
ARMV_MINOR = 0
ARM_PROFILE = a

ifeq ($(ARMV_MINOR),0)
MARCH=armv$(ARMV_MAJOR)-$(ARM_PROFILE)
else
MARCH=armv$(ARMV_MAJOR).$(ARMV_MINOR)-$(ARM_PROFILE)
endif

UPROG = test
USE_DISK = 0


TARGET = aarch64-none-elf
CROSS_COMPILE = $(TARGET)-

NEWLIBLOC ?= /opt/cross/${TARGET}/lib

CC = $(CROSS_COMPILE)gcc
AS = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)ld
AR = $(CROSS_COMPILE)ar
STRIP = $(CROSS_COMPILE)strip

SH_FLAGS += -march=$(MARCH)
SH_FLAGS += -DARMV_MAJOR=$(ARMV_MAJOR)
SH_FLAGS += -DARMV_MINOR=$(ARMV_MINOR)
SH_FLAGS += -DARM_PROFILE=$(ARM_PROFILE)
SH_FLAGS += -include config.h

CFLAGS += -I$(CROOT)/src/include -I$(CROOT)/src/arch/$(ARCH)
CFLAGS += -g
CFLAGS += -MMD

#CFLAGS += -Wno-implicit-function-declaration
#CFLAGS += -O1

ASFLAGS += -I$(CROOT)/src/include


ifneq ("$(wildcard $(CROOT)/userconfig.mk)","")
include $(CROOT)/userconfig.mk
endif

# Place these last so that userconfig.mk can put data into SH_FLAGS

CFLAGS += $(SH_FLAGS)
ASFLAGS += $(SH_FLAGS)

QEMU_FLAGS += -machine virt
QEMU_FLAGS += -cpu cortex-a57
QEMU_FLAGS += -nographic
QEMU_FLAGS += -smp 1

# Variables which should be defined in userconfig.mk
ifdef USERARGS
KERNEL_APPEND += userargs=$(USERARGS)
endif

ifdef KERNEL_APPEND
QEMU_FLAGS += -append "$(KERNEL_APPEND)"
endif

ifeq ($(USE_DISK),1)
QEMU_FLAGS += -device virtio-blk-device,drive=hd0 -drive file=disk.img,id=hd0,if=none,format=raw
endif

# RNG device
QEMU_FLAGS += -object rng-random,filename=/dev/random,id=rng0
QEMU_FLAGS += -device virtio-rng-device,rng=rng0

# Useful for debugging
#QEMU_FLAGS += -trace events=events

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


# Kernel disks
QEMU_FLAGS += -kernel Image
QEMU_FLAGS += -initrd apps/$(UPROG)

