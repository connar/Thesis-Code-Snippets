#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

// Macro for 32-bit rotate left operation
// The dataSize is fixed at 32 bits for this specific hashing algorithm.
#define ROL32(val, numShifts) (((val) << (numShifts)) | ((val) >> (32 - (numShifts))))

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    uint32_t ors;

    for (size_t i = 0; i < len; ++i) {
        // Cast the current byte to uint32_t before operations.
        // This ensures that all intermediate calculations are performed at 32-bit width
        // and prevents potential sign extension issues or unexpected promotions
        // as per requirement 3.
        uint32_t current_byte_val = (uint32_t)data[i];

        // Python: ors = i | 33
        ors = current_byte_val | 33;

        // Python: val = val ^ ors
        val = val ^ ors;

        // Python: val = rol(val, 0xb, 32)
        val = ROL32(val, 11); // 0xb is 11 in decimal
    }

    return val;
}