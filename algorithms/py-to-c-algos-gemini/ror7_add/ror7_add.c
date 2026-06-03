#include <stdint.h> // For uint32_t, size_t

// Helper function for rotate right
static uint32_t ror(uint32_t inVal, unsigned int numShifts) {
    // For 32-bit rotation, numShifts should be in [0, 31].
    // The hash function always calls this with numShifts = 7.
    // The bitmask 0xffffffff is implicitly handled by uint32_t arithmetic.
    return (inVal >> numShifts) | (inVal << (32 - numShifts));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    for (size_t i = 0; i < len; ++i) {
        val = ror(val, 7);
        // Cast data[i] to uint32_t to ensure the addition is performed
        // with 32-bit unsigned integers, preventing potential sign extension
        // issues if `unsigned char` were promoted to a signed `int`.
        val += (uint32_t)data[i];
    }
    // For uint32_t, arithmetic operations naturally wrap around at 2^32,
    // mimicking Python's behavior with a 32-bit mask.
    return val;
}