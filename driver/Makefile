# Build + install the BCM5880 ControlVault 2 libfprint TOD driver.
#
# TOD drivers are compiled against libfprint's *internal* driver API (drivers_api.h),
# which is not shipped by the runtime package. You therefore need the libfprint-tod
# SOURCE matching your installed libfprint-2-tod-1, pointed to by LIBFPRINT_SRC, and
# its meson build dir (for the generated fp-enums.h) in LIBFPRINT_BUILD.
#
# Fedora example:
#   dnf download --source libfprint-tod && rpm2cpio libfprint-tod-*.src.rpm | cpio -idmv
#   tar xf libfprint-*.tar.* && cd libfprint-* && meson setup build && ninja -C build
#   make LIBFPRINT_SRC=$PWD LIBFPRINT_BUILD=$PWD/build
#
# Then:  sudo make install   (drops the .so into the TOD driver dir; restart fprintd)

LIBFPRINT_SRC   ?= $(error set LIBFPRINT_SRC to the libfprint-tod source tree)
LIBFPRINT_BUILD ?= $(LIBFPRINT_SRC)/build
PKG_CONFIG_PATH := $(LIBFPRINT_BUILD)/meson-uninstalled
export PKG_CONFIG_PATH

TOD_CFLAGS := $(shell pkg-config --cflags libfprint-2-tod-1) -I$(LIBFPRINT_BUILD)/libfprint
TOD_LIBS   := $(shell pkg-config --libs libfprint-2-tod-1)
TODDIR     := $(shell pkg-config --variable=tod_driversdir libfprint-2-tod-1 2>/dev/null)
TODDIR     := $(if $(TODDIR),$(TODDIR),/usr/lib64/libfprint-2/tod-1)

SONAME := libfprint-2-tod-1-bcm5880cv2.so
SRCS   := bcm5880cv2.c cv2_session.c

all: $(SONAME)

$(SONAME): $(SRCS) cv2_session.h
	$(CC) -shared -fPIC -O2 -o $@ $(SRCS) $(TOD_CFLAGS) $(TOD_LIBS) -lcrypto -Wno-deprecated-declarations

install: $(SONAME)
	install -d $(DESTDIR)$(TODDIR)
	install -m 0644 $(SONAME) $(DESTDIR)$(TODDIR)/$(SONAME)
	@echo "Installed to $(DESTDIR)$(TODDIR)/$(SONAME) — restart fprintd to load it."

clean:
	rm -f $(SONAME)

.PHONY: all install clean
