#include <stdint.h> // For uint32_t and size_t

// Helper function for rotate left (ROL) specific to 32-bit values.
static uint32_t rol(uint32_t inVal, unsigned int numShifts) {
    // For uint32_t, bitwise shifts naturally handle the 32-bit wrap-around,
    // equivalent to masking with 0xFFFFFFFF as seen in the Python implementation.
    return (inVal << numShifts) | (inVal >> (32 - numShifts));
}

// The main hashing algorithm.
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;

    for (size_t i = 0; i < len; ++i) {
        // Rotate left by 9 bits (0x9).
        val = rol(val, 9);

        // Add the current byte.
        // Cast to uint32_t to ensure the byte is treated as an unsigned 32-bit value
        // before addition, preventing potential sign extension issues.
        val += (uint32_t)data[i];
        
        // The addition `val += ...` for uint32_t inherently handles overflow
        // by wrapping around, which matches the Python behavior of masking with 0xFFFFFFFF.
    }

    return val;
}