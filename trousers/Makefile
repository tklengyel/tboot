#
# trousers makefile
#

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk

TARGET           = $(TARGET_DIR)/src/tcsd/tcsd
TARGET_DIR       = trousers
TARGET_TARFILE   = trousers-0.3.1.tar.gz

TROUSERS_BASE_URL = http://downloads.sourceforge.net/trousers

#
# universal rules
#

build : $(TARGET)


dist : install


install : build


clean :
	rm -f *~
	if [ -d $(TARGET_DIR) ]; then \
		$(MAKE) -C $(TARGET_DIR) clean; \
		rm -f $(TARGET); \
	fi


mrproper : clean
	rm -rf $(TARGET_DIR)


distclean : clean


#
# dependencies
#

$(TARGET) : $(TARGET_DIR)/Makefile
	$(MAKE) -C $(TARGET_DIR) install

$(TARGET_DIR)/Makefile : $(TARGET_DIR)/configure
	cd $(TARGET_DIR) && ./configure --prefix=/usr

$(TARGET_DIR)/configure : $(TARGET_DIR)/bootstrap.h
	cd $(TARGET_DIR) && sh bootstrap.sh

$(TARGET_DIR)/bootstrap.h : $(TARGET_TARFILE)
	mkdir -p trousers
	tar -xzf $(TARGET_TARFILE) -C $(TARGET_DIR)/ --strip-components 1
	touch $@

$(TARGET_TARFILE) :
	wget $(TROUSERS_BASE_URL)/$(TARGET_TARFILE)
