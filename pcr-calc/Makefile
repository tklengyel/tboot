# Copyright (c) 2006-2010, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# utils makefile
#

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk

TARGETS := pcr-calc module_hash

CFLAGS += -D_LARGEFILE64_SOURCE

LIBS += -lcrypto -lz

ifdef HAVE_BZIP
BZIP_LIB := -lbz2
else
BZIP_LIB :=
endif

#
# universal targets
#
build : $(TARGETS)


dist : install


install :
	@set -e; for i in $(TARGETS);\
	do \
		$(MAKE) DISTDIR=$(DISTDIR) INST_TARGET=$(DISTDIR)/usr/sbin/$$i do_install; \
	done

.PHONY: do_install
do_install : $(INST_TARGET)

$(INST_TARGET) : $(notdir $(INST_TARGET))
	[ -d $(DISTDIR)/usr/sbin ] || $(INSTALL_DIR) $(DISTDIR)/usr/sbin
	$(INSTALL_PROG) -t $(DISTDIR)/usr/sbin $^


clean :
	rm -f $(TARGETS) *~ *.o *.mod.* *.symvers


distclean : clean


#
# dependencies
#

BUILD_DEPS := $(ROOTDIR)/Config.mk $(CURDIR)/Makefile


pcr-calc : eventlog.o pcr-calc.o tpm.o util.o hash.o tb_policy.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

module_hash : module_hash.o hash.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) $(BZIP_LIB) -o $@

%.o : %.c $(BUILD_DEPS)
	$(CC) $(CFLAGS) -DNO_TBOOT_LOGLVL -c $< -o $@
