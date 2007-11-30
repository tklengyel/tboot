#
# txt-test makefile
#

obj-m = txt-test.o

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk

LINUX_BASE_DIR = $(ROOTDIR)/../

LINUX_BUILD_DIR = $(LINUX_BASE_DIR)/build-linux-2.6.18-xen_$(TARGET_ARCH)
LINUX_SRC_DIR = $(LINUX_BASE_DIR)/linux-2.6.18-xen.hg

TARGET := $(CURDIR)/txt-test.ko


#
# universal targets
#
dist : install


build : $(TARGET)


install : build


clean :
	rm -f $(TARGET) *~ *.o *.mod.* *.symvers .*
	rm -rf .*


distclean : clean


#
# dependencies
#

$(TARGET) : $(ROOTDIR)/Config.mk $(CURDIR)/Makefile
	$(MAKE) -C $(LINUX_BUILD_DIR) M=$(CURDIR) modules

