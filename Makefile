#
# KBUILD build parameters.
#
KERNEL_SOURCES  ?= /lib/modules/$(shell uname -r)/build
KERNEL_HEADERS  := -I$(KERNEL_SOURCES)/include
MODULE_ROOT     ?= /lib/modules/$(shell uname -r)/CiscoVPN
SUBARCH         := $(shell uname -m)


MODULE_NAME := cisco_ipsec

SOURCE_OBJS := linuxcniapi.o frag.o IPSecDrvOS_linux.o interceptor.o linuxkernelapi.o

ifeq ($(SUBARCH),x86_64)
CFLAGS += -mcmodel=kernel -mno-red-zone
NO_SOURCE_OBJS := libdriver64.so
else
NO_SOURCE_OBJS := libdriver.so
endif

ifneq ($(KERNELRELEASE),)

obj-m := $(MODULE_NAME).o 

$(MODULE_NAME)-objs :=  $(SOURCE_OBJS) $(NO_SOURCE_OBJS)

EXTRA_CFLAGS += -Wall \
                -D_LOOSE_KERNEL_NAMES \
                -DCNI_LINUX_INTERFACE \
                -DHAVE_CONFIG_H

ifeq ($(PATCHLEVEL), 4)
$(obj)/$(MODULE_NAME).o: $($(MODULE_NAME)-objs)
	$(LD) $(EXTRA_LDFLAGS) -r -o $@ $($(MODULE_NAME)-objs)
endif #PATCHLEVEL

else #KERNRELEASE

default: 
	$(MAKE) -C $(KERNEL_SOURCES) SUBDIRS=$(PWD) modules
clean:
	-rm -f $(SOURCE_OBJS)
	-rm -f $(MODULE_NAME).mod.*
	-rm -f $(MODULE_NAME).{o,ko}

endif #KERNRELEASE
