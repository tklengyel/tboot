#
# lcptools makefile
#

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
LIBS += -lcrypto -ltspi -lz


#
# universal rules
#

build : $(TPMNV_TARGETS) $(LCP_TARGETS)


dist : install


install :
	@set -e; for i in $(TPMNV_TARGETS) $(LCP_TARGETS); do \
		$(MAKE) DISTDIR=$(DISTDIR) INST_TARGET=$(DISTDIR)/usr/bin/$$i do_install; \
	done

.PHONY: do_install
do_install : $(INST_TARGET)

$(INST_TARGET) : $(notdir $(INST_TARGET))
	[ -d $(DISTDIR)/usr/bin ] || $(INSTALL_DIR) $(DISTDIR)/usr/bin
	$(INSTALL_PROG) -t $(DISTDIR)/usr/bin $^


clean :
	rm -f *~ *.a *.so *.o *.rpm $(DEP_FILES) $(TPMNV_TARGETS) $(LCP_TARGETS)


mrproper : clean


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
