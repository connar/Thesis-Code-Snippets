#include <stdint.h>
#include <stddef.h>

static inline uint32_t rol(uint32_t inVal, unsigned int numShifts) {
    return (inVal << numShifts) | (inVal >> (32 - numShifts));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    for (size_t k = 0; k < len; ++k) {
        uint8_t i = data[k];

        val = val ^ ((uint32_t)i << 8);
        val = rol(val, 8);
        
        // This extracts the third byte (0-indexed) of the 32-bit value.
        // If val is 0xAABBCCDD, val_hex[4:6] corresponds to 0xCC.
        uint32_t valh = (val >> 8) & 0xFF;
        
        val = val ^ valh;
    }
    return val;
}