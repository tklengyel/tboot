# Copyright (c) 2006-2010, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# tboot makefile
#

include $(CURDIR)/Config.mk

TARGET := $(CURDIR)/tboot

C_SRCS := $(wildcard $(CURDIR)/common/*.c) $(wildcard $(CURDIR)/txt/*.c)

S_SRCS += $(wildcard $(CURDIR)/common/*.S) $(wildcard $(CURDIR)/txt/*.S)
# exclude wakeup.S and shutdown.S because they're included in boot.S
INCLUDED_S_SRCS = $(CURDIR)/common/wakeup.S $(CURDIR)/common/shutdown.S
S_SRCS := $(filter-out $(INCLUDED_S_SRCS),$(S_SRCS))

# for time being, ensure that boot.o is first module
OBJS := $(S_SRCS:.S=.o) $(C_SRCS:.c=.o)


TARGET_LDS := $(CURDIR)/common/tboot.lds

$(TARGET).gz : $(TARGET)
	gzip -f -9 < $< > $@

ifeq ($(debug),n)
LDFLAGS_STRIP = -s
endif

$(TARGET) : $(OBJS) $(TARGET_LDS)
	$(LD) $(LDFLAGS) -T $(TARGET_LDS) -N $(OBJS) -o $(@D)/.$(@F).0
	$(NM) -n $(@D)/.$(@F).0 >$(TARGET)-syms
	$(LD) $(LDFLAGS) -T $(TARGET_LDS) $(LDFLAGS_STRIP) $(@D)/.$(@F).0 -o $(TARGET)
	rm -f $(@D)/.$(@F).0

$(TARGET_LDS) : $(TARGET_LDS).x $(HDRS)
	$(CPP) -P -E -Ui386 $(AFLAGS) -o $@ $<

$(TARGET_LDS).x : FORCE

#
# universal rules
#
dist : install


build : $(TARGET).gz


install : $(DISTIR)/boot/$(TARGET).gz

$(DISTIR)/boot/$(TARGET).gz : $(TARGET).gz
	[ -d $(DISTDIR)/boot ] || $(INSTALL_DIR) $(DISTDIR)/boot
	$(INSTALL_DATA) $(TARGET).gz $(DISTDIR)/boot/$(notdir $(TARGET)).gz
	$(INSTALL_DATA) $(TARGET)-syms $(DISTDIR)/boot/$(notdir $(TARGET))-syms


clean :
	rm -f $(TARGET)* $(TARGET_LDS) *~ include/*~ include/txt/*~ *.o common/*~ txt/*~ common/*.o txt/*.o
	rm -f tags TAGS cscope.files cscope.in.out cscope.out cscope.po.out


distclean : clean


#
#    TAGS / tags
#
define all_sources
    ( find . -name '*.[chS]' -print )
endef
define set_exuberant_flags
    exuberant_flags=`$1 --version 2>/dev/null | grep -iq exuberant && \
	echo "-I __initdata,__exitdata,__acquires,__releases \
	    -I EXPORT_SYMBOL \
	    --extra=+f --c-kinds=+px"`
endef

.PHONY: TAGS
TAGS : 
	rm -f TAGS; \
	$(call set_exuberant_flags,etags); \
	$(all_sources) | xargs etags $$exuberant_flags -a

.PHONY: tags
tags : 
	rm -f tags; \
	$(call set_exuberant_flags,ctags); \
	$(all_sources) | xargs ctags $$exuberant_flags -a

#
#    cscope
#
.PHONY: cscope
cscope :
	$(all_sources) > cscope.files
	cscope -k -b -q

#
#    MAP
#
.PHONY: MAP
MAP :
	$(NM) -n $(TARGET)-syms | grep -v '\(compiled\)\|\(\.o$$\)\|\( [aUw] \)\|\(\.\.ng$$\)\|\(LASH[RL]DI\)' > System.map

#
# implicit rules
#

HDRS := $(wildcard $(CURDIR)/include/*.h)
HDRS += $(wildcard $(CURDIR)/include/txt/*.h)

BUILD_DEPS := $(ROOTDIR)/Config.mk $(CURDIR)/Config.mk $(CURDIR)/Makefile

# fix case where gcc doesn't use builtin memcmp() when built w/o optimizations
ifeq ($(debug),y)
CFLAGS += -O2
endif

%.o : %.c $(HDRS) $(BUILD_DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

%.o : %.S $(HDRS) $(BUILD_DEPS)
	$(CC) $(AFLAGS) -c $< -o $@

%.i : %.c $(HDRS) $(BUILD_DEPS)
	$(CPP) $(CFLAGS) $< -o $@

# -std=gnu{89,99} gets confused by # as an end-of-line comment marker
%.s : %.S $(HDRS)  $(BUILD_DEPS)
	$(CPP) $(AFLAGS) $< -o $@
