#include <stdint.h> // Required for uint32_t
#include <stddef.h> // Required for size_t

// Helper function for 32-bit rotate left (ROL)
// This function mimics the behavior of the Python rol function when dataSize is 32.
// For this specific hashing algorithm, numShifts is always 0x11 (17).
static inline uint32_t rol32(uint32_t inVal, unsigned int numShifts) {
    // C's unsigned integer shift operations naturally handle the wrap-around for 32-bit values.
    // The Python code includes checks for numShifts being 0 or out of bounds,
    // but for this specific hash, numShifts is always 17, which is valid for 32-bit rotation.
    return (inVal << numShifts) | (inVal >> (32 - numShifts));
}

// The main hashing algorithm function
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;
    uint32_t ors; // This variable will hold the result of the OR operation, treated as 32-bit.

    // Iterate through each byte of the input data
    for (size_t i = 0; i < len; ++i) {
        // Python: ors = i | 35
        // data[i] is an unsigned char. When ORed with 35 (an int literal),
        // data[i] is promoted to int, the operation is performed, and the result (an int)
        // is then assigned to uint32_t ors. This is correct and matches Python's behavior
        // where the result of `i | 35` is then used in a 32-bit context.
        ors = data[i] | 35; // 35 is 0x23

        // Python: val = val ^ ors
        // val is uint32_t, ors is uint32_t. XOR operation is straightforward.
        val = val ^ ors;

        // Python: val = rol(val, 0x11, 32)
        // Rotate val left by 17 bits (0x11) as a 32-bit value.
        val = rol32(val, 0x11);
    }

    return val;
}