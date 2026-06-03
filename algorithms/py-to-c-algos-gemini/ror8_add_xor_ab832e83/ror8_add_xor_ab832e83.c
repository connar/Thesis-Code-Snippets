#include <stdint.h> // For uint32_t, size_t

// Helper function for rotate right (ror) for 32-bit values.
// The original Python ror function is called with dataSize=32 and numShifts=8
// within the hash algorithm. This specialized version handles that case.
static inline uint32_t ror32(uint32_t inVal, unsigned int numShifts) {
    // For unsigned integer types in C, right shifts are logical shifts,
    // and arithmetic operations naturally wrap around at the type's maximum value.
    // This behavior correctly mimics the Python code's fixed-width integer arithmetic.
    return (inVal >> numShifts) | (inVal << (32 - numShifts));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t state = 0x832E83AB;

    for (size_t i = 0; i < len; ++i) {
        uint32_t val = ror32(state, 8); // Rotate state right by 8 bits

        if (i < len - 1) {
            // Python: val += data[i] | data[i + 1] << 8
            // Cast data bytes to uint32_t before bitwise and arithmetic operations
            // to prevent sign extension issues and ensure 32-bit arithmetic.
            uint32_t byte_current = (uint32_t)data[i];
            uint32_t byte_next = (uint32_t)data[i + 1];
            val += byte_current | (byte_next << 8);
        } else {
            // Python: val += data[i]
            // Cast the single byte to uint32_t before addition.
            val += (uint32_t)data[i];
        }

        state ^= val; // XOR val with state
    }

    return state;
}