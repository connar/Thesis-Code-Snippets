#include <stdint.h> // For uint32_t
#include <stddef.h> // For size_t

// Helper function for 32-bit rotate left by 3 bits.
// This directly implements the rol(val, 0x3, 32) call from the Python hash function.
static inline uint32_t rol32_3(uint32_t inVal) {
    // For a 32-bit value rotated left by 3 bits:
    // The bits shifted out from the left are shifted in from the right.
    return (inVal << 3) | (inVal >> (32 - 3));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    for (size_t i = 0; i < len; ++i) {
        val = rol32_3(val);
        // Cast the current byte to uint32_t before XORing to prevent
        // potential sign extension issues if 'unsigned char' were
        // promoted to a signed integer type during the XOR operation.
        val = val ^ (uint32_t)data[i];
    }
    return val;
}