#include <stdint.h> // For uint32_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0xFFFFFFFFU; // Initialize with 32-bit unsigned value

    for (size_t k = 0; k < len; ++k) {
        // Requirement 3: Cast to (uint32_t) before XORing to avoid sign extension.
        // data[k] is unsigned char, which will be promoted to int, then to uint32_t for XOR.
        // Explicit cast to uint32_t is safer and clearer.
        val ^= (uint32_t)data[k];

        for (int j = 0; j < 8; ++j) {
            if (val & 0x1) { // Check the least significant bit
                val ^= 0xe8677835U; // XOR with the polynomial
            }
            val >>= 1; // Logical right shift (for unsigned types)
        }
    }

    // Final XOR and return
    return val ^ 0xFFFFFFFFU;
}