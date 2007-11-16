#
# build_tools makefile
#

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk

SYMBOLS = symbols
MKELF	= mkelf32

$(SYMBOLS) : $(SYMBOLS).c Makefile
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<

$(MKELF) : $(MKELF).c Makefile
	$(HOSTCC) $(HOSTCFLAGS) -o $@ $<



#
# universal rules
#
dist : install


build : $(SYMBOLS) $(MKELF)


install : build


clean :
	rm -f $(SYMBOLS) $(MKELF) *~ *.o


distclean : clean


#
# implicit rules
#

BUILD_DEPS := $(ROOTDIR)/Config.mk $(CURDIR)/Makefile

%.o : %.c $(BUILD_DEPS)
	$(CC) $(CFLAGS) -c $< -o $@
