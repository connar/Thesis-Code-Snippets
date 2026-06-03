#include <stdint.h> // For uint32_t
#include <stddef.h> // For size_t

// Helper function for 32-bit rotate left
static inline uint32_t rol(uint32_t inVal, unsigned int numShifts) {
    // numShifts is expected to be between 0 and 31 for 32-bit rotation.
    // The Python code uses 0x9 (9), which is valid.
    return (inVal << numShifts) | (inVal >> (32 - numShifts));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    for (size_t k = 0; k < len; ++k) {
        // Cast data[k] to uint32_t to ensure proper promotion and avoid sign extension
        // before XORing with val, which is a uint32_t.
        val = val ^ (uint32_t)data[k];
        val = rol(val, 9); // Rotate left by 9 bits
    }
    return val;
}