# -*- mode: Makefile; -*-

#
# global build settings
#

# supported targets
.PHONY: all build install dist clean distclean mrproper

# Default target
all : build


# debug build
debug ?= n

# for dist targets
DESTDIR     ?= $(ROOTDIR)/dist
DISTDIR     ?= /

dist : DISTDIR=$(DESTDIR)


#
# tools and flags for components built to run on build (host)
#

# cc-option: Check if compiler supports first option, else fall back to second.
# Usage: cflags-y += $(call cc-option,$(CC),-march=winchip-c6,-march=i586)
cc-option = $(shell if test -z "`$(1) $(2) -S -o /dev/null -xc \
              /dev/null 2>&1`"; then echo "$(2)"; else echo "$(3)"; fi ;)


HOSTCC            = gcc
HOSTCFLAGS        = -Wall -Wformat-security -Werror -Wstrict-prototypes
HOSTCFLAGS       += -O2 -std=gnu99 -fno-strict-aliasing

HOSTCFLAGS_x86_32 = -m32
HOSTCFLAGS_x86_64 = -m64

AS         = as
LD         = ld
CC         = gcc
CPP        = cpp
AR         = ar
RANLIB     = ranlib
NM         = nm
STRIP      = strip
OBJCOPY    = objcopy
OBJDUMP    = objdump

INSTALL      = install
INSTALL_DIR  = $(INSTALL) -d -m0755 -p
INSTALL_DATA = $(INSTALL) -m0644 -p
INSTALL_PROG = $(INSTALL) -m0755 -p


#
# tools and flags for components built to run on target
#
TARGET_ARCH  ?= $(shell uname -m | sed -e s/i.86/x86_32/ -e s/i86pc/x86_32/)

CFLAGS += -Wall -Wformat-security -Werror -Wstrict-prototypes
CFLAGS += -fno-strict-aliasing -std=gnu99
# due to bug in gcc v4.2,3,?
CFLAGS += $(call cc-option,$(CC),-Wno-array-bounds,)


ifeq ($(debug),y)
CFLAGS += -g -DDEBUG
else
CFLAGS += -O2
endif

ifeq ($(TARGET_ARCH),x86_64)
LIBDIR := lib64
CFLAGS += -m64
else
LIBDIR := lib
CFLAGS += -m32 -march=i686
endif

# common dummy rule to force execution
.PHONY: FORCE
FORCE :
	@: # do nothing
