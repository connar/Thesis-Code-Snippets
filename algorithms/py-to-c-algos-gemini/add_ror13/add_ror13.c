#include <stdint.h> // For uint32_t, size_t

// Helper function for rotate right
// dataSize is implicitly 32 for this algorithm
static inline uint32_t ror(uint32_t inVal, unsigned int numShifts) {
    if (numShifts == 0) {
        return inVal;
    }
    // For 32-bit rotation, numShifts should be in [0, 31].
    // The Python code raises an error for numShifts > dataSize,
    // but for the fixed numShifts=13, this is not an issue.
    // The result is implicitly masked to 32 bits by the uint32_t type.
    return (inVal >> numShifts) | (inVal << (32 - numShifts));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    for (size_t i = 0; i < len; ++i) {
        // Add the current byte value.
        // data[i] is unsigned char, which promotes safely to uint32_t.
        // uint32_t addition naturally handles 32-bit overflow by wrapping around.
        val += (uint32_t)data[i];
        
        // Rotate right by 13 bits (0xd)
        val = ror(val, 13);
    }
    return val;
}