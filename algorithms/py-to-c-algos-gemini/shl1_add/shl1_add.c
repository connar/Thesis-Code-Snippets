#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    for (size_t i = 0; i < len; ++i) {
        uint8_t b = data[i];
        uint8_t processed_b = b | 0x60;
        val = val + (uint32_t)processed_b;
        val = val << 1;
        val = 0xffffffff & val;
    }
    return val;
}