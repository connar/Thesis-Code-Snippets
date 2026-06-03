#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0xFFFFFFFFU;

    for (size_t k = 0; k < len; ++k) {
        uint32_t ci = (uint32_t)data[k];

        ci = ci ^ val;

        // Python's 'ci' can become larger than 32 bits here due to arbitrary precision integers.
        // Perform multiplication in 64-bit space to mimic this behavior.
        uint64_t temp_product = (uint64_t)ci * val;

        // The Python sequence:
        // ci_hex = "%16x" % ci
        // ci_hex = ci_hex[8:16]
        // ci_hex = int(ci_hex, 16)
        // effectively extracts the lower 32 bits of the potentially 64-bit 'temp_product'.
        uint32_t ci_lower_32_bits = (uint32_t)(temp_product & 0xFFFFFFFFULL);

        uint32_t shr8 = val >> 8;

        val = ci_lower_32_bits ^ shr8;
    }

    // In Python, the final result is masked with 0xffffffff.
    // Since 'val' is already a uint32_t in C, this mask is redundant as
    // uint32_t operations naturally wrap around at 2^32.
    return val;
}