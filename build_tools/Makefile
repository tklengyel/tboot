#
# build_tools makefile
#

# Default target must appear before any include lines
.PHONY: all
all: dist

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk

SYMBOLS = symbols
MKELF	= mkelf32

$(SYMBOLS) : $(SYMBOLS).c Makefile
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

$(MKELF) : $(MKELF).c Makefile
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<



#
#    dist
#
.PHONY: dist
dist : install


#
#    build
#
.PHONY: build
build : $(SYMBOLS) $(MKELF)


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
	rm -f $(SYMBOLS) $(MKELF) *~ *.o


#
#    distclean
#
.PHONY: distclean
distclean : clean


#
# implicit rules
#

BUILD_DEPS := $(ROOTDIR)/Config.mk $(CURDIR)/Makefile

%.o : %.c $(BUILD_DEPS)
	$(CC) $(CFLAGS) -c $< -o $@
