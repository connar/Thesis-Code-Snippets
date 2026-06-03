#include <stdint.h>
#include <stddef.h>

static uint32_t rol32(uint32_t inVal, unsigned int numShifts) {
    return (inVal << numShifts) | (inVal >> (32 - numShifts));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t ecx = 0;
    uint32_t eax = 0;

    for (size_t k = 0; k < len; ++k) {
        eax = eax | (uint32_t)data[k];
        ecx = ecx ^ eax;
        ecx = rol32(ecx, 3);
        ecx += 1;
        eax = (eax << 8);
    }

    return ecx;
}