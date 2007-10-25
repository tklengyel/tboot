#
# lcptools makefile
#

# Default target must appear before any include lines
.PHONY: all
all : dist

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk


TPMNV_TARGETS := \
	tpmnv_defindex \
	tpmnv_relindex \
	tpmnv_lock     \
	tpmnv_getcap

LCP_TARGETS := \
	lcp_writepol   \
	lcp_readpol    \
	lcp_crtpconf   \
	lcp_crtpol     \
	lcp_mlehash

UTIL_OBJS := lcptools.o lcputils.o


# libraries
LIBS += -lssl -ltspi


#
# rules
#

.PHONY: build
build : $(TPMNV_TARGETS) $(LCP_TARGETS)

.PHONY: install dist
install dist : build

.PHONY: clean
clean :
	rm -f *~ *.a *.so *.o *.rpm $(DEP_FILES) $(TPMNV_TARGETS) $(LCP_TARGETS)

.PHONY: mrproper
mrproper : clean

.PHONY: distclean
distclean : clean

#
# dependencies
#

$(TPMNV_TARGETS) : tpmnv_% : %.o $(UTIL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@

$(LCP_TARGETS) : lcp_% : %.o $(UTIL_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@


#
# implicit rules
#

HDRS := $(wildcard $(ROOTDIR)/include/*.h) $(wildcard $(CURDIR)/*.h)

BUILD_DEPS := $(ROOTDIR)/Config.mk $(CURDIR)/Makefile

%.o : %.c $(HDRS) $(BUILD_DEPS)
	$(CC) $(CFLAGS) -c $< -o $@
