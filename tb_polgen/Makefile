#
# tb_polgen makefile
#

# Default target must appear before any include lines
.PHONY: all
all : dist

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk


TARGET = tb_polgen

# libraries
LIBS += -lssl


#
# rules
#

.PHONY: build
build : $(TARGET)

.PHONY: install dist
install dist : build

.PHONY: clean
clean :
	rm -f *~ *.a *.so *.o *.rpm $(DEP_FILES) $(TARGET)

.PHONY: mrproper
mrproper : clean

.PHONY: distclean
distclean : clean

#
# dependencies
#

$(TARGET) : tb_polgen.o commands.o policy.o param.o hash.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(LIBS) -o $@


#
# implicit rules
#

HDRS := $(wildcard $(ROOTDIR)/include/*.h) $(wildcard $(CURDIR)/*.h)

BUILD_DEPS := $(ROOTDIR)/Config.mk $(CURDIR)/Makefile

%.o : %.c $(HDRS) $(BUILD_DEPS)
	$(CC) $(CFLAGS) -c $< -o $@
