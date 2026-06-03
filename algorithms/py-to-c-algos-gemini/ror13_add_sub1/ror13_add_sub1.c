#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

// Helper function for rotate right (ROR)
// Equivalent to Python's ror(inVal, numShifts, 32)
static inline uint32_t ror32(uint32_t inVal, unsigned int numShifts) {
    // For 32-bit rotation, numShifts should be in the range [0, 31].
    // The Python code uses 0xd (13), which is a valid shift amount.
    // The expression (inVal >> numShifts) | (inVal << (32 - numShifts))
    // correctly performs a 32-bit right rotation.
    // The Python version's bitMask & ... is implicitly handled by uint32_t arithmetic.
    return (inVal >> numShifts) | (inVal << (32 - numShifts));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;

    for (size_t i = 0; i < len; ++i) {
        val = ror32(val, 0xd); // Rotate right by 13 bits (0xd)
        
        // Requirement 3: When adding bytes, cast to (unsigned int) first to avoid sign extension.
        // Although 'unsigned char' is already positive, casting to 'unsigned int'
        // ensures explicit promotion to a wider unsigned type before addition,
        // adhering strictly to the requirement.
        val += (unsigned int)data[i];
    }

    // Requirement 5: Ensure integer overflow mimics Python behavior (mask with 0xFFFFFFFF).
    // For uint32_t, (val - 1) correctly handles underflow (e.g., 0 - 1 results in 0xFFFFFFFF).
    // The final bitwise AND with 0xffffffff explicitly truncates the result to 32 bits,
    // matching the Python behavior, although it's redundant for a uint32_t return type.
    return (val - 1) & 0xffffffff;
}