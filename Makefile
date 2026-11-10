CFLAGS ?= -O2 -Wall
PKG := $(shell pkg-config --cflags --libs libusb-1.0 libcrypto)

all: probe cv2-session-shim.so

probe: probe.c
	$(CC) $(CFLAGS) -o $@ probe.c $(PKG)

cv2-session-shim.so: cv2-session-shim.c
	$(CC) -shared -fPIC $(CFLAGS) -Wno-deprecated-declarations -o $@ cv2-session-shim.c -ldl -lcrypto

clean:
	rm -f probe cv2-session-shim.so

.PHONY: all clean
