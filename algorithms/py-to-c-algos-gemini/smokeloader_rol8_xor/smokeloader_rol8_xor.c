#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t, uint8_t

// Helper function for 32-bit rotate left (ROL)
// This function emulates the Python rol function for dataSize=32.
// For uint32_t, the bitmask 0xffffffff is implicitly handled by the type's arithmetic.
static inline uint32_t rol32(uint32_t inVal, unsigned int numShifts) {
    // The Python code includes checks for numShifts and dataSize.
    // In this C implementation, we specifically target the 32-bit rotation
    // with numShifts=8, as used by the hash function.
    // The result of the shifts will naturally wrap around within 32 bits.
    return (inVal << numShifts) | (inVal >> (32 - numShifts));
}

// Converts the Python hashing algorithm to C.
// The function signature strictly adheres to the requirement.
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0; // Initialize hash value to 0

    // Iterate through each byte of the input data
    for (size_t k = 0; k < len; ++k) {
        // Use uint8_t for the current byte to ensure it's treated as an unsigned value.
        // This matches the Python 'i' being a byte from the data.
        uint8_t current_byte = data[k];

        // Python: val = val ^ (i & 0xDF)
        // Cast current_byte to unsigned int before operations to prevent potential
        // sign extension issues, as per requirement 3.
        val = val ^ ((unsigned int)current_byte & 0xDF);

        // Python: val = rol(val, 0x8, 32)
        // Perform a 32-bit rotate left by 8 bits.
        val = rol32(val, 8);

        // Python: val = val + (i & 0xDF)
        // Cast current_byte to unsigned int before addition.
        // The addition will naturally wrap around for uint32_t,
        // mimicking Python's 32-bit integer overflow behavior (modulo 2^32),
        // as per requirement 5.
        val = val + ((unsigned int)current_byte & 0xDF);
    }

    // Python: return val & 0xffffffff
    // Since 'val' is already a uint32_t, its value is implicitly masked to 32 bits.
    // No explicit masking is needed here.
    return val;
}