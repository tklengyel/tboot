#
# trousers makefile
#

# Default target must appear before any include lines
.PHONY: all
all : dist

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk

TARGET_DIR = trousers
TARGET     = $(TARGET_DIR)/src/tcsd/tcsd
TARGET_TGZ = trousers.tar.gz

TROUSERS_HEADER_DIR = /usr/include/tss/

#
# rules
#

.PHONY: build
build : $(TARGET_DIR) $(TARGET)

.PHONY: install dist
install dist : build

.PHONY: clean
clean :
	rm -f *~
	if [ -d $(TARGET_DIR) ]; then \
		$(MAKE) -C $(TARGET_DIR) clean; \
		rm -f $(TARGET); \
	fi

.PHONY: mrproper
mrproper: clean
	rm -rf $(TARGET_DIR)

.PHONY: distclean
distclean : clean

#
# dependencies
#

$(TARGET_DIR) : $(TARGET_TGZ)
	@echo Extracting $^ ... $@
	tar -xzf $^

$(TARGET) : $(TARGET_DIR)/Makefile
	$(MAKE) -C $(TARGET_DIR) install
	$(INSTALL_DATA) $(TARGET_DIR)/src/include/tss/tcs_defines.h $(TROUSERS_HEADER_DIR)

$(TARGET_DIR)/Makefile : $(TARGET_DIR)/configure
	cd $(TARGET_DIR) && ./configure --prefix=/usr

$(TARGET_DIR)/configure :
	cd $(TARGET_DIR) && sh bootstrap.sh
