#include <stdint.h> // For uint32_t, size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    size_t i;

    for (i = 0; i < len; ++i) {
        // Python: edx = 0xffffffff & (val << 7)
        // In C, for uint32_t, left shift naturally wraps around at 32 bits.
        uint32_t edx = val << 7;

        // Python: ecx = 0xffffffff & (val >> 0x19)
        // 0x19 is 25. Right shift for uint32_t is logical (zero-filling).
        uint32_t ecx = val >> 25;

        // Python: eax = edx | ecx
        uint32_t eax = edx | ecx;

        // Python: t = 0xff & (i ^ 0xf4)
        // Requirement: Cast to (unsigned int) before XOR to avoid sign extension.
        // Then mask with 0xff to mimic Python's 8-bit truncation.
        uint32_t t = (((unsigned int)data[i]) ^ 0xf4) & 0xff;

        // Python: val = eax ^ t
        val = eax ^ t;
    }

    return val;
}