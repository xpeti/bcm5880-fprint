CFLAGS ?= -O2 -Wall
PKG := $(shell pkg-config --cflags --libs libusb-1.0 libcrypto)

probe: probe.c
	$(CC) $(CFLAGS) -o $@ probe.c $(PKG)

clean:
	rm -f probe

.PHONY: clean
