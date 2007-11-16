#
# txt-test makefile
#

obj-m = txt-test.o

ROOTDIR ?= $(CURDIR)/..
XEN_ROOT ?= $(ROOTDIR)

include $(ROOTDIR)/Config.mk

LINUX_BUILD_DIR = $(ROOTDIR)/../build-linux-2.6.18-xen_$(TARGET_ARCH)
LINUX_SRC_DIR = $(ROOTDIR)/../linux-2.6.18-xen.hg

TARGET := $(CURDIR)/txt-test.ko


#
# universal targets
#
dist : install


build : $(TARGET)


install : build


clean :
	rm -f $(TARGET) *~ *.o *.mod.* *.symvers


distclean : clean


#
# dependencies
#

$(TARGET) : $(ROOTDIR)/Config.mk $(CURDIR)/Makefile
	$(MAKE) -C $(LINUX_BUILD_DIR) M=$(CURDIR) modules

