#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

// Helper function for rotate right (ROR)
// This implementation assumes a 32-bit data size, as used by the Python hash function.
// The numShifts parameter is expected to be within the range [0, 31].
static uint32_t ror(uint32_t inVal, unsigned int numShifts) {
    // For 32-bit unsigned integers, the bitwise shifts naturally handle
    // the 32-bit wrap-around behavior.
    // The Python equivalent's bitmask (0xffffffff) is implicitly handled by uint32_t.
    return (inVal >> numShifts) | (inVal << (32 - numShifts));
}

// Converts the Python hashing algorithm to C.
// The function signature strictly adheres to the requirement.
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0; // Initialize hash value to 0

    // Iterate through each byte of the input data
    for (size_t i = 0; i < len; ++i) {
        // Step 1: Rotate the current hash value right by 11 bits (0xb in hex)
        val = ror(val, 11);

        // Step 2: Add the current data byte to the rotated hash value.
        // Requirement 3: Cast data[i] to uint32_t (unsigned int) before adding
        // to prevent potential sign extension issues if 'unsigned char' were
        // implicitly promoted to a signed integer type before addition.
        val += (uint32_t)data[i];
    }

    // Requirement 5: uint32_t naturally handles 32-bit integer overflow,
    // mimicking Python's behavior for fixed-width integers.
    return val;
}