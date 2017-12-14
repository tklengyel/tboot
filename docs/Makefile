# Copyright (c) 2012, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# docs makefile
#

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk
TBOOT_MANPATH ?= $(DISTDIR)/usr/share/man


#
# universal rules
#


build : 


dist : install


install :
	[ -d $(TBOOT_MANPATH)/man8 ] || $(INSTALL_DIR) $(TBOOT_MANPATH)/man8
	$(INSTALL_DATA) -t $(TBOOT_MANPATH)/man8 man/*.8*


clean :

mrproper : clean

distclean : clean


#
# dependencies
#


#
# implicit rules
#

