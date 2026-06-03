#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

// Helper function for 32-bit rotate left (ROL)
// This function is specialized for dataSize=32 as used in the hash algorithm.
static inline uint32_t rol32(uint32_t inVal, unsigned int numShifts) {
    // For uint32_t, the 0xffffffff bitmask is implicitly handled by the type.
    // numShifts is expected to be within [0, 31] for standard ROL behavior.
    // The Python code uses 0x9 (9), which is valid.
    return (inVal << numShifts) | (inVal >> (32 - numShifts));
}

// Converts the Python hashing algorithm to C.
// Function signature strictly adheres to the requirement.
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0; // Initialize hash value to 0

    // Iterate over each byte in the input data
    for (size_t i = 0; i < len; ++i) {
        // 1. Rotate the current hash value left by 9 bits (0x9)
        val = rol32(val, 0x9);

        // 2. XOR the rotated value with the current byte from the data.
        //    Cast data[i] to uint32_t to prevent potential sign extension
        //    if 'unsigned char' were promoted to 'int' before XORing with 'uint32_t'.
        val = val ^ (uint32_t)data[i];
    }

    return val; // Return the final 32-bit hash value
}