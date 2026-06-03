#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    for (size_t k = 0; k < len; ++k) {
        val = val * 131;
        // Cast data[k] to uint32_t to ensure correct promotion and
        // avoid potential sign extension issues, as per requirement 3.
        val += (uint32_t)data[k];
    }
    // In Python, 'val' can grow arbitrarily large, and the final
    // 'val = val & 0xFFFFFFFF' truncates it to 32 bits.
    // In C, when 'val' is a 'uint32_t', arithmetic operations
    // (multiplication and addition) naturally wrap around at 2^32.
    // This behavior effectively mimics the 32-bit truncation at each step,
    // which is the common interpretation for such hash algorithms
    // designed for fixed-width registers. The final explicit mask
    // is redundant for a uint32_t variable as it's already constrained.
    return val;
}