#include <stdint.h> // For uint32_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0x811c9dc5;

    for (size_t i = 0; i < len; ++i) {
        // Cast the current byte to uint32_t to ensure it's treated as an
        // unsigned 32-bit integer before operations, preventing potential
        // sign extension issues as per requirement 3.
        uint32_t byte_val = (uint32_t)data[i];

        // Perform the XOR operation, then multiplication.
        // The result of the multiplication is stored back into a uint32_t,
        // which naturally wraps around modulo 2^32. This behavior correctly
        // mimics Python's `& 0xffffffff` mask for positive results,
        // satisfying requirement 5.
        val = 0x1000193 * (byte_val ^ val);
    }

    // Perform the final XOR operation and return the 32-bit hash value.
    return val ^ 0x67f;
}