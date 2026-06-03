#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0x1505U; // Initialize with unsigned literal

    for (size_t k = 0; k < len; ++k) {
        // Python: val = (val * 0x21) & 0xFFFFFFFF
        // In C, for uint32_t, multiplication naturally wraps around 2^32,
        // which is equivalent to masking with 0xFFFFFFFF.
        val *= 0x21U;

        // Python: val = (val + (i & 0xFFFFFFDF)) & 0xFFFFFFFF
        // 'i' corresponds to data[k].
        // Cast data[k] to uint32_t before bitwise AND to ensure a 32-bit operation
        // and prevent any potential sign extension issues if data[k] were a signed char.
        // For uint32_t, addition naturally wraps around 2^32,
        // which is equivalent to masking with 0xFFFFFFFF.
        val += ((uint32_t)data[k] & 0xFFFFFFDFU);
    }

    return val;
}