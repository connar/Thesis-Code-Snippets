#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

// Helper function for 32-bit rotate left (ROL)
static inline uint32_t rol32(uint32_t inVal, int numShifts) {
    // For uint32_t, dataSize is implicitly 32.
    // The numShifts value used in the hash function is 8.
    // (32 - numShifts) will be 24.
    return (inVal << numShifts) | (inVal >> (32 - numShifts));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;

    for (size_t k = 0; k < len; ++k) {
        // Requirement 3: When XORing/Adding bytes, cast to (unsigned int) first to avoid sign extension.
        // The Python code uses `i & 0xDF`. `data[k]` is `unsigned char`.
        // Casting to `uint32_t` (which is an `unsigned int` type) before the bitwise AND
        // ensures the operation is performed on an unsigned integer type.
        uint32_t current_byte_processed = (uint32_t)data[k] & 0xDF;

        val = val ^ current_byte_processed;
        val = rol32(val, 8); // Rotate left by 8 bits
        val = val + current_byte_processed;
        // Requirement 5: Ensure integer overflow mimics Python behavior.
        // For `uint32_t`, arithmetic operations naturally wrap around on overflow,
        // which matches the behavior of Python's arbitrary-precision integers when
        // implicitly masked to a 32-bit unsigned value.
    }

    // Final XOR operation.
    // The `U` suffix ensures the literal `0xB0D4D06` is treated as an `unsigned int`.
    // The result of `val ^ 0xB0D4D06U` will inherently be a `uint32_t`,
    // so an explicit `& 0xffffffff` mask is not needed as `uint32_t` already
    // represents a 32-bit unsigned integer.
    return (val ^ 0xB0D4D06U);
}