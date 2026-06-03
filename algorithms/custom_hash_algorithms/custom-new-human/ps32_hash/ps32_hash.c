#include <stdint.h>
#include <stddef.h>

uint32_t hash(const uint8_t *data, size_t len) {
    uint32_t h = 0x87654321;
    for (size_t i = 0; i < len; i++) {
        h = (h * 131) - (uint32_t)data[i];
    }
    return h;
}