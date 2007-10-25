#
# tboot makefile
#

# Default target must appear before any include lines
.PHONY: all
all: dist

include $(CURDIR)/Config.mk

XEN_INC_ASMX86_DIR = $(ROOTDIR)/../xen/include/asm-x86

TARGET := $(CURDIR)/tboot

DUMMY_SYMS_OBJ := $(CURDIR)/common/symbols-dummy.o

C_SRCS := $(wildcard $(CURDIR)/common/*.c) $(wildcard $(CURDIR)/txt/*.c)
S_SRCS += $(wildcard $(CURDIR)/common/*.S) $(wildcard $(CURDIR)/txt/*.S)

# for time being, ensure that boot.o is first module
OBJS := $(S_SRCS:.S=.o) $(C_SRCS:.c=.o)
# exlcude symbols-dummy.o because that is linked explicitly
OBJS := $(filter-out $(DUMMY_SYMS_OBJ),$(OBJS))

TARGET_LDS := $(CURDIR)/common/tboot.lds

SYMBOLS = $(ROOTDIR)/build_tools/symbols
MKELF	= $(ROOTDIR)/build_tools/mkelf32

$(TARGET).gz : $(TARGET)
	gzip -f -9 < $< > $@

$(TARGET) : $(TARGET)-syms $(MKELF)
	$(MKELF) $(TARGET)-syms $(TARGET) 0x100000 \
	`$(NM) -nr $(TARGET)-syms | head -n 1 | sed -e 's/^\([^ ]*\).*/0x\1/'`

$(TARGET)-syms : $(OBJS) $(DUMMY_SYMS_OBJ) $(TARGET_LDS)
	$(LD) $(LDFLAGS) -T $(TARGET_LDS) -N $(OBJS) \
	    $(DUMMY_SYMS_OBJ) -o $(@D)/.$(@F).0
	$(NM) -n $(@D)/.$(@F).0 | $(SYMBOLS) >$(@D)/.$(@F).0.S
	$(MAKE) $(@D)/.$(@F).0.o
	$(LD) $(LDFLAGS) -T $(TARGET_LDS) -N $(OBJS) \
	    $(@D)/.$(@F).0.o -o $(@D)/.$(@F).1
	$(NM) -n $(@D)/.$(@F).1 | $(SYMBOLS) >$(@D)/.$(@F).1.S
	$(MAKE) $(@D)/.$(@F).1.o
	$(LD) $(LDFLAGS) -T $(TARGET_LDS) -N $(OBJS) $(@D)/.$(@F).1.o -o $@
	rm -f $(@D)/.$(@F).[0-9]*

$(TARGET_LDS) : $(TARGET_LDS).x $(HDRS)
	$(CPP) -P -E -Ui386 $(AFLAGS) -o $@ $<

$(TARGET_LDS).x : FORCE

#
#    dist
#
.PHONY: dist
dist : install


#
#    build
#
.PHONY: build
build : $(TARGET).gz


#
#    install
#
.PHONY: install
install : $(DESTIR)/boot/$(TARGET).gz
	if [ -d $(XEN_INC_ASMX86_DIR) ]; then \
		cp $(ROOTDIR)/include/tboot.h $(XEN_INC_ASMX86_DIR); \
	fi

$(DESTIR)/boot/$(TARGET).gz : $(TARGET).gz
	[ -d $(DESTDIR)/boot ] || $(INSTALL_DIR) $(DESTDIR)/boot
	$(INSTALL_DATA) $(TARGET).gz $(DESTDIR)/boot/$(notdir $(TARGET)).gz
	$(INSTALL_DATA) $(TARGET)-syms $(DESTDIR)/boot/$(notdir $(TARGET))-syms


#
#    clean
#
.PHONY: clean
clean :
	rm -f $(TARGET)* $(TARGET_LDS) *~ include/*~ include/txt/*~ *.o common/*~ txt/*~ common/*.o txt/*.o
	rm -f tags TAGS cscope.files cscope.in.out cscope.out cscope.po.out
	$(MAKE) -C $(ROOTDIR)/build_tools clean


#
#    distclean
#
.PHONY: distclean
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
	    -I EXPORT_SYMBOL,EXPORT_SYMBOL_GPL \
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

%.o : %.c $(HDRS) $(BUILD_DEPS)
	$(CC) $(CFLAGS) -c $< -o $@

%.o : %.S $(HDRS) $(BUILD_DEPS)
	$(CC) $(AFLAGS) -c $< -o $@

%.i : %.c $(HDRS) $(BUILD_DEPS)
	$(CPP) $(CFLAGS) $< -o $@

# -std=gnu{89,99} gets confused by # as an end-of-line comment marker
%.s : %.S $(HDRS)  $(BUILD_DEPS)
	$(CPP) $(AFLAGS) $< -o $@
