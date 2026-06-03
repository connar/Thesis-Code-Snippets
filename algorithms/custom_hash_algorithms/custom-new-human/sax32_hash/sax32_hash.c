#include <stdint.h>
#include <stddef.h>

uint32_t hash(const uint8_t *data, size_t len) {
    uint32_t h = 0x55555555;
    for (size_t i = 0; i < len; i++) {
        uint32_t mixed = (h << 5) ^ (h >> 3);
        h = mixed + (uint32_t)data[i];
    }
    return h;
}