# Copyright (c) 2006-2010, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# utils makefile
#

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk

TARGETS := txt-stat acminfo parse_err

CFLAGS += -D_LARGEFILE64_SOURCE

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

txt-stat : txt-stat.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

acminfo : acminfo.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

parse_err : parse_err.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

%.o : %.c $(BUILD_DEPS)
	$(CC) $(CFLAGS) -c $< -o $@
