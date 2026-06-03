#include <stddef.h>
#include <stdint.h>

static inline uint32_t rol32(uint32_t inVal, unsigned int numShifts) {
    return (inVal << numShifts) | (inVal >> (32 - numShifts));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;

    for (size_t i = 0; i < len; ++i) {
        val += (unsigned int)data[i];
        val = rol32(val, 5);
    }

    val = rol32(val, 5);

    return val;
}