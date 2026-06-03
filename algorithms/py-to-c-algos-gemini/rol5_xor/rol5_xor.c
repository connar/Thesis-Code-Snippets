#include <stdint.h> // For uint32_t, uint8_t, size_t

// Helper function for 32-bit rotate left
// This function is specialized for dataSize=32 as used by the hash function.
// The bitmasking (0xffffffff) is implicitly handled by the uint32_t type.
static inline uint32_t rol32(uint32_t inVal, unsigned int numShifts) {
    // Ensure numShifts is within 0-31 for predictable behavior
    // The original Python code raises ValueError for numShifts < 0 or > dataSize.
    // For a static inline helper, we assume valid input (0x5 is valid).
    // If numShifts is 0, the result is inVal, which this formula handles.
    return (inVal << numShifts) | (inVal >> (32 - numShifts));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    for (size_t k = 0; k < len; ++k) {
        // Equivalent to val = rol(val, 0x5, 32)
        val = rol32(val, 0x5);

        // Get the current byte from data
        uint8_t i = data[k];

        // Equivalent to ors = i | 32
        // Cast i to uint32_t before ORing to ensure the operation is 32-bit
        // and avoids any potential sign extension issues if i were a signed char.
        uint32_t ors = (uint32_t)i | 32;

        // Equivalent to val = val ^ ors
        val = val ^ ors;
    }
    return val;
}