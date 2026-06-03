#include <stdint.h>
#include <stddef.h>

// Helper function for 32-bit right rotation
static inline uint32_t ror32(uint32_t inVal, unsigned int numShifts) {
    // For uint32_t, the bitmask (0xffffffff) is implicit due to the type's size.
    // The rotation is (value >> shifts) | (value << (32 - shifts)).
    return (inVal >> numShifts) | (inVal << (32 - numShifts));
}

// Hashing algorithm function
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;

    for (size_t k = 0; k < len; ++k) {
        // Use uint8_t for the current byte to ensure it's treated as an unsigned value.
        uint8_t i = data[k];

        // Perform ROR 13 on the current hash value
        val = ror32(val, 0xd); // 0xd is 13 in decimal

        // Python logic:
        // if i < 97:  # 97 is ASCII for 'a'
        //     val = (val & 0xffffffff) + i
        // else:
        //     val = ((val & 0xffffffff) + i - 32) & 0xffffffff

        // In C, with uint32_t, the `& 0xffffffff` for overflow handling is
        // implicitly handled by the fixed-width unsigned integer arithmetic.
        // We cast `i` to `uint32_t` before addition/subtraction to prevent
        // potential sign extension issues, as per requirement 3.
        if (i < 97) {
            val = val + (uint32_t)i;
        } else {
            // `i - 32` effectively converts lowercase ASCII to uppercase ASCII.
            // Since `i` is guaranteed to be >= 97 here, `i - 32` will always be positive.
            val = val + ((uint32_t)i - 32);
        }
    }

    return val;
}