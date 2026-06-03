#include <stdint.h>
#include <stddef.h>

static inline uint32_t ROR32(uint32_t val, unsigned int r_bits) {
    r_bits %= 32;
    return (val >> r_bits) | (val << (32 - r_bits));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0xFFFFFFFFU;

    for (size_t i = 0; i < len; ++i) {
        val = ROR32(val, 0xd);
        val += (uint32_t)data[i];
    }

    return val;
}