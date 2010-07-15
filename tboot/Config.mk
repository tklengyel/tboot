# Copyright (c) 2006-2010, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# tboot-specific build settings
#

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk


# if target arch is 64b, then convert -m64 to -m32 (tboot is always 32b)
CFLAGS		:= $(shell echo $(CFLAGS) | sed -e s/-m64/-m32/)
CFLAGS		+= -march=i686
CFLAGS		+= -nostdinc
CFLAGS		+= -fno-builtin -fno-common -fno-strict-aliasing
CFLAGS		+= -fomit-frame-pointer
CFLAGS		+= -pipe
CFLAGS		+= -iwithprefix include
CFLAGS		+= -I$(CURDIR)/include -I$(ROOTDIR)/include
# ensure no floating-point variables
CFLAGS		+= -msoft-float
# Disable PIE/SSP if GCC supports them. They can break us.
CFLAGS		+= $(call cc-option,$(CC),-nopie,)
CFLAGS		+= $(call cc-option,$(CC),-fno-stack-protector,)
CFLAGS		+= $(call cc-option,$(CC),-fno-stack-protector-all,)
ifeq ($(TARGET_ARCH),x86_64)
CFLAGS		+= -DTARGET_ARCH_x86_64
endif

# changeset variable for banner
CFLAGS		+= -DTBOOT_CHANGESET=\""$(shell ((hg parents --template "{isodate|isodate} {rev}:{node|short}" >/dev/null && hg parents --template "{isodate|isodate} {rev}:{node|short}") || echo "unavailable") 2>/dev/null)"\"

# uncomment to support logging to memory location
#CFLAGS		+= -DMEM_LOGGING



AFLAGS		+= -D__ASSEMBLY__

# Most CFLAGS are safe for assembly files:
#  -std=gnu{89,99} gets confused by #-prefixed end-of-line comments
AFLAGS		+= $(patsubst -std=gnu%,,$(CFLAGS))


# LDFLAGS are only passed directly to $(LD)
LDFLAGS		+= -melf_i386
