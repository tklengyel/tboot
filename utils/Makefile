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
dist : install


build : $(TARGETS)


install : build


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
