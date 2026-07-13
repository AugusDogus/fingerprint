CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -Wpedantic
LDFLAGS ?=

LIBUSB_CFLAGS := $(shell pkg-config --cflags libusb-1.0)
LIBUSB_LIBS := $(shell pkg-config --libs libusb-1.0)

.PHONY: all clean

all: build/goodix-probe

build/goodix-probe: src/goodix_probe.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(LIBUSB_CFLAGS) $< -o $@ $(LDFLAGS) $(LIBUSB_LIBS)

clean:
	rm -rf build
