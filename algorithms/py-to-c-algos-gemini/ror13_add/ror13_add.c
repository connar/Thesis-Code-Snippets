#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

// Helper function for 32-bit rotate right (ROR)
// This function is equivalent to the Python ror(inVal, numShifts, dataSize=32)
// when dataSize is fixed to 32 bits.
static inline uint32_t ror32(uint32_t inVal, unsigned int numShifts) {
    // For uint32_t, the bitmask 0xffffffff is implicitly handled by the type.
    // The shift amount is always 0xd (13) in the hash function.
    // The dataSize is always 32.
    return (inVal >> numShifts) | (inVal << (32 - numShifts));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    for (size_t k = 0; k < len; ++k) {
        // Rotate right by 13 bits (0xd)
        val = ror32(val, 0xd);
        // Add the current byte.
        // Cast to uint32_t to ensure the addition is performed with 32-bit operands
        // and wraps correctly, mimicking Python's behavior for fixed-size operations.
        val += (uint32_t)data[k];
    }
    return val;
}