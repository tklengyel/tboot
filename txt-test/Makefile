#
# txt-test makefile
#

obj-m = txt-test.o

# Default target must appear before any include lines
.PHONY: all
all: dist

ROOTDIR ?= $(CURDIR)/..
XEN_ROOT ?= $(ROOTDIR)

include $(ROOTDIR)/Config.mk

LINUX_BUILD_DIR = $(ROOTDIR)/../build-linux-2.6.18-xen_$(TARGET_ARCH)
LINUX_SRC_DIR = $(ROOTDIR)/../linux-2.6.18-xen.hg

TARGET := $(CURDIR)/txt-test.ko


#
#    dist
#
.PHONY: dist
dist : install


#
#    build
#
.PHONY: build
build : $(TARGET)

#
#    install
#
.PHONY: install
install : build


#
#    clean
#
.PHONY: clean
clean :
	rm -f $(TARGET) *~ *.o *.mod.* *.symvers


#
#    distclean
#
.PHONY: distclean
distclean : clean


#
# dependencies
#

$(TARGET) : $(ROOTDIR)/Config.mk $(CURDIR)/Makefile
	$(MAKE) -C $(LINUX_BUILD_DIR) M=$(CURDIR) modules

