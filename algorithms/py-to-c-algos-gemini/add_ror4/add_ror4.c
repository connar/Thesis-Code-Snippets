#include <stdint.h> // For uint32_t, uint8_t, size_t

// Helper function for 32-bit right rotation
// This function emulates the Python ror(inVal, numShifts, dataSize=32)
// with dataSize fixed at 32.
static inline uint32_t ror32(uint32_t val, unsigned int numShifts) {
    // For a uint32_t type, the 32-bit wrap-around is handled naturally.
    // The explicit bitmask (0xffffffff) from Python is not needed here.
    // numShifts must be less than 32. The Python code uses 4, which is valid.
    return (val >> numShifts) | (val << (32 - numShifts));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;

    for (size_t k = 0; k < len; ++k) {
        // Use unsigned char for data bytes as per requirement.
        // When added to val (uint32_t), current_byte (unsigned char) will be
        // promoted to uint32_t without sign extension, fulfilling requirement 3.
        unsigned char current_byte = data[k];

        // Python equivalent: val = (val & 0xffffff00) + ((val + i) & 0xff)
        // The addition (val + current_byte) is performed as uint32_t.
        // The result is then masked with 0xff to get the lower 8 bits.
        // This result is then added to the upper 24 bits of the original val.
        val = (val & 0xffffff00) + ((val + current_byte) & 0xff);

        // Python equivalent: val = ror(val, 0x4, 32)
        val = ror32(val, 4);
    }

    return val;
}