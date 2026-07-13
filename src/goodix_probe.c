#include <errno.h>
#include <libusb-1.0/libusb.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GOODIX_VID 0x27c6
#define GOODIX_PID 0x5584
#define EP_OUT 0x01
#define EP_IN  0x82

static const uint8_t MCU_GET_VERSION_CMD[] = {
    0x00, 0xa8, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x9f, 0xab, 0xaf, 0x6a,
};

static const uint8_t MCU_NOP_CMD[] = {
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xda, 0xdd, 0x30, 0xa8,
};

static const uint8_t RT_MCU_GET_VERSION_CMD[] = {
    0xa0, 0x06, 0x00, 0xa6, 0xa8, 0x03, 0x00, 0x00,
    0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static const uint8_t RT_MCU_NOP_CMD[] = {
    0xa0, 0x08, 0x00, 0xa8, 0x00, 0x05, 0x00, 0x00,
    0x00, 0x00, 0x00, 0xa5, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static void print_hex(const char *label, const uint8_t *buf, int len) {
    printf("%s (%d bytes):", label, len);
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) {
            printf("\n  %04x:", i);
        }
        printf(" %02x", buf[i]);
    }
    printf("\n");
}

static int claim_device(libusb_context *ctx, libusb_device_handle **out_handle) {
    libusb_device_handle *handle = libusb_open_device_with_vid_pid(ctx, GOODIX_VID, GOODIX_PID);
    if (!handle) {
        fprintf(stderr, "failed to open %04x:%04x\n", GOODIX_VID, GOODIX_PID);
        return -1;
    }

    if (libusb_kernel_driver_active(handle, 0) == 1) {
        int rc = libusb_detach_kernel_driver(handle, 0);
        if (rc != 0) {
            fprintf(stderr, "failed to detach kernel driver: %s\n", libusb_error_name(rc));
            libusb_close(handle);
            return rc;
        }
    }

    int rc = libusb_claim_interface(handle, 0);
    if (rc != 0) {
        fprintf(stderr, "failed to claim interface 0: %s\n", libusb_error_name(rc));
        libusb_close(handle);
        return rc;
    }

    *out_handle = handle;
    return 0;
}

static int read_once(libusb_device_handle *handle, unsigned timeout_ms) {
    uint8_t buf[1500];
    int transferred = 0;
    int rc = libusb_bulk_transfer(handle, EP_IN, buf, sizeof(buf), &transferred, timeout_ms);
    if (rc == LIBUSB_ERROR_TIMEOUT) {
        printf("read timed out after %u ms\n", timeout_ms);
        return 0;
    }
    if (rc != 0) {
        fprintf(stderr, "bulk read failed: %s\n", libusb_error_name(rc));
        return rc;
    }

    print_hex("read", buf, transferred);
    return 0;
}

static int read_responses(libusb_device_handle *handle, unsigned initial_timeout_ms,
                          unsigned inter_packet_timeout_ms, unsigned max_packets) {
    uint8_t buf[16384];
    unsigned packets = 0;

    while (packets < max_packets) {
        int transferred = 0;
        unsigned timeout_ms = packets == 0 ? initial_timeout_ms : inter_packet_timeout_ms;
        int rc = libusb_bulk_transfer(handle, EP_IN, buf, sizeof(buf), &transferred, timeout_ms);

        if (rc == LIBUSB_ERROR_TIMEOUT) {
            if (packets == 0) {
                printf("read timed out after %u ms\n", timeout_ms);
            } else {
                printf("response window complete after %u packet(s)\n", packets);
            }
            return 0;
        }
        if (rc != 0) {
            fprintf(stderr, "bulk read failed: %s\n", libusb_error_name(rc));
            return rc;
        }

        print_hex("read", buf, transferred);
        packets++;
    }

    return 0;
}

static int send_frame(libusb_device_handle *handle, const uint8_t *cmd, size_t cmd_len) {
    int transferred = 0;

    print_hex("write", cmd, (int)cmd_len);
    int rc = libusb_bulk_transfer(handle, EP_OUT, (uint8_t *)cmd, cmd_len, &transferred, 1000);
    if (rc != 0) {
        fprintf(stderr, "bulk write failed: %s\n", libusb_error_name(rc));
        return rc;
    }
    if (transferred != (int)cmd_len) {
        fprintf(stderr, "short bulk write: %d/%zu bytes\n", transferred, cmd_len);
        return -EIO;
    }

    return 0;
}

static int send_nop(libusb_device_handle *handle) {
    int rc = send_frame(handle, MCU_NOP_CMD, sizeof(MCU_NOP_CMD));
    if (rc != 0) {
        return rc;
    }

    return read_once(handle, 2000);
}

static int send_version(libusb_device_handle *handle) {
    int rc = send_frame(handle, MCU_GET_VERSION_CMD, sizeof(MCU_GET_VERSION_CMD));
    if (rc != 0) {
        return rc;
    }

    return read_once(handle, 6000);
}

static int send_rt_nop(libusb_device_handle *handle) {
    int rc = send_frame(handle, RT_MCU_NOP_CMD, sizeof(RT_MCU_NOP_CMD));
    if (rc != 0) {
        return rc;
    }

    return read_responses(handle, 2000, 250, 2);
}

static int send_rt_version(libusb_device_handle *handle) {
    int rc = send_frame(handle, RT_MCU_GET_VERSION_CMD, sizeof(RT_MCU_GET_VERSION_CMD));
    if (rc != 0) {
        return rc;
    }

    return read_responses(handle, 6000, 250, 4);
}

int main(int argc, char **argv) {
    bool do_read = argc > 1 && strcmp(argv[1], "read") == 0;
    bool do_nop = argc > 1 && strcmp(argv[1], "nop") == 0;
    bool do_version = argc > 1 && strcmp(argv[1], "version") == 0;
    bool do_wake_version = argc > 1 && strcmp(argv[1], "wake-version") == 0;
    bool do_rt_nop = argc > 1 && strcmp(argv[1], "rt-nop") == 0;
    bool do_rt_version = argc > 1 && strcmp(argv[1], "rt-version") == 0;
    bool do_rt_wake_version = argc > 1 && strcmp(argv[1], "rt-wake-version") == 0;

    libusb_context *ctx = NULL;
    int rc = libusb_init(&ctx);
    if (rc != 0) {
        fprintf(stderr, "libusb_init failed: %s\n", libusb_error_name(rc));
        return 1;
    }

    libusb_device_handle *handle = NULL;
    rc = claim_device(ctx, &handle);
    if (rc != 0) {
        libusb_exit(ctx);
        return 1;
    }

    printf("claimed %04x:%04x interface 0\n", GOODIX_VID, GOODIX_PID);
    printf("bulk endpoints: OUT=0x%02x IN=0x%02x\n", EP_OUT, EP_IN);

    if (do_read) {
        rc = read_once(handle, 1000);
    } else if (do_nop) {
        rc = send_nop(handle);
    } else if (do_version) {
        rc = send_version(handle);
    } else if (do_wake_version) {
        rc = send_nop(handle);
        if (rc == 0) {
            rc = send_version(handle);
        }
    } else if (do_rt_nop) {
        rc = send_rt_nop(handle);
    } else if (do_rt_version) {
        rc = send_rt_version(handle);
    } else if (do_rt_wake_version) {
        rc = send_rt_nop(handle);
        if (rc == 0) {
            rc = send_rt_version(handle);
        }
    } else {
        printf("no command sent; pass 'read', 'nop', 'version', 'wake-version', 'rt-nop', 'rt-version', or 'rt-wake-version'\n");
    }

    libusb_release_interface(handle, 0);
    libusb_close(handle);
    libusb_exit(ctx);

    return rc == 0 ? 0 : 1;
}
