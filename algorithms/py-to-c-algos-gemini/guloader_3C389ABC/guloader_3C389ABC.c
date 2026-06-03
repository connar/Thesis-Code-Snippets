#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t, uint8_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t out_hash = 0x1505;
    for (size_t i = 0; i < len; ++i) {
        uint8_t c = data[i];
        out_hash = (((uint32_t)c + 33 * out_hash) ^ 0x3C389ABC) & 0xffffffff;
    }
    return out_hash;
}