#include <stdint.h>
#include <stddef.h>

uint32_t hash(const uint8_t *data, size_t len) {
    uint32_t h = 0x0987ABCD;
    for (size_t i = 0; i < len; i++) {
        uint32_t rol = (h << 7) | (h >> 25);
        h = rol + (uint32_t)data[i];
    }
    return h;
}