#include <stdint.h> // For uint32_t, size_t

// Helper function to perform a left rotation (ROL) on a 32-bit unsigned integer.
// This function emulates the Python rol function with dataSize fixed to 32.
// numShifts is expected to be between 0 and 31 (inclusive).
static inline uint32_t rol(uint32_t inVal, unsigned int numShifts) {
    // The Python code uses a bitmask (0xFFFFFFFF for 32-bit) to ensure the result
    // stays within the 32-bit range. For uint32_t in C, the operations naturally
    // wrap around, but explicitly including the mask makes it a direct translation.
    const uint32_t bitMask = 0xFFFFFFFFU;
    return bitMask & ((inVal << numShifts) | (inVal >> (32U - numShifts)));
}

// The main hashing algorithm.
// Converts the Python hashing algorithm to C.
// Requirements:
// 1. Function signature: 'uint32_t hash(const unsigned char* data, size_t len)'
// 2. Use 'uint8_t' or 'unsigned char' for data bytes.
// 3. Cast to (unsigned int) for XORing/Adding bytes to avoid sign extension.
// 4. No toupper/tolower used, so <ctype.h> is not needed.
// 5. Integer overflow mimics Python behavior (uint32_t handles 32-bit unsigned wrap-around).
// 6. No external libraries.
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0xFFFFFFFFU; // Initialize val with 0xffffffff
    uint32_t ors;               // Temporary variable for the 'i | 32' operation

    // Iterate through each byte in the input data
    for (size_t k = 0; k < len; ++k) {
        // Get the current byte. Cast to uint32_t to ensure the OR operation
        // is performed using 32-bit unsigned integers, preventing potential
        // sign extension issues if 'unsigned char' were promoted to 'int'
        // and 'int' was signed.
        ors = (uint32_t)data[k] | 32U;

        // Perform the XOR and ROL operation as per the Python algorithm.
        // The rol function is called with a fixed shift of 19 bits and dataSize 32.
        val = ors ^ rol(val, 19U);
    }

    return val; // Return the final 32-bit hash value
}