#include <stdint.h> // For uint32_t
#include <stddef.h> // For size_t

// Helper function for rotate left (ROL) operation on a 32-bit unsigned integer
static inline uint32_t rol(uint32_t val, int numShifts) {
    // For a 32-bit unsigned integer, the rotation naturally wraps around.
    // The numShifts value (0x7) is within the valid range [0, 31].
    return (val << numShifts) | (val >> (32 - numShifts));
}

// Main hashing function
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    for (size_t i = 0; i < len; ++i) {
        val = rol(val, 0x7); // Rotate current hash value left by 7 bits
        // Add the current byte. Cast to uint32_t to ensure proper
        // unsigned addition and avoid potential sign extension issues
        // if 'unsigned char' were promoted to a signed type.
        val += (uint32_t)data[i];
    }
    return val;
}