#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

// Helper function for 32-bit right rotation
// num_shifts is typically 0-31 for 32-bit values.
// The Python code uses 0xd (13) for numShifts.
static inline uint32_t ror32(uint32_t val, unsigned int num_shifts) {
    // Ensure num_shifts is within the valid range for 32-bit rotation
    // (0 to 31). This handles cases where num_shifts might be >= 32.
    num_shifts &= 31;
    if (num_shifts == 0) {
        return val;
    }
    // Perform the right rotation.
    // The C standard guarantees that for unsigned types, right shifts are logical (zero-filling).
    // The left shift part (val << (32 - num_shifts)) will wrap around naturally for uint32_t.
    return (val >> num_shifts) | (val << (32 - num_shifts));
}

// Converts the Python hashing algorithm to C.
// Function signature MUST be strictly: 'uint32_t hash(const unsigned char* data, size_t len)'.
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0; // Initialize val to 0, as per Python code.

    // Iterate through each byte of the input data.
    for (size_t k = 0; k < len; ++k) {
        // Add the current byte to val.
        // Cast data[k] to uint32_t to ensure the addition is performed
        // as a 32-bit unsigned operation, preventing sign extension issues
        // and allowing natural 32-bit overflow (wrap-around).
        val += (uint32_t)data[k];

        // Rotate val right by 13 bits (0xd in hex).
        val = ror32(val, 0xd);
    }

    // After the loop, perform one more right rotation by 13 bits.
    val = ror32(val, 0xd);

    return val; // Return the final 32-bit hash value.
}