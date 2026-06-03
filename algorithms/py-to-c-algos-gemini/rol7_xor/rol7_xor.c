#include <stdint.h>
#include <stddef.h>

static uint32_t rol(uint32_t inVal, unsigned int numShifts) {
    return (inVal << numShifts) | (inVal >> (32 - numShifts));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    for (size_t i = 0; i < len; ++i) {
        val = rol(val, 7);
        val = val ^ (uint32_t)data[i];
    }
    return val;
}