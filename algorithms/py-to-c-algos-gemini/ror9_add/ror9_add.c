#include <stdint.h> // For uint32_t, size_t

// Helper function for 32-bit Rotate Right
static uint32_t ror32(uint32_t inVal, unsigned int numShifts) {
    // Normalize numShifts to be within [0, 31] for 32-bit rotation.
    // This ensures valid shift amounts and consistent behavior.
    numShifts %= 32;

    // If numShifts is 0, no rotation is needed.
    if (numShifts == 0) {
        return inVal;
    }

    // Perform the 32-bit right rotation.
    // For uint32_t, the result naturally wraps around within 32 bits,
    // mimicking the Python bitmask behavior (0xFFFFFFFF).
    return (inVal >> numShifts) | (inVal << (32 - numShifts));
}

// The main hashing function.
// Requirement 1: The function signature MUST be strictly: 'uint32_t hash(const unsigned char* data, size_t len)'.
uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0; // Initialize hash value to 0.

    // Iterate through each byte of the input data.
    for (size_t i = 0; i < len; ++i) {
        // Requirement 5: Ensure integer overflow mimics Python behavior (mask with 0xFFFFFFFF if returning 32-bit).
        // uint32_t naturally handles overflow by wrapping around, which is equivalent to masking with 0xFFFFFFFF.

        // Rotate the current hash value right by 9 bits (0x9).
        // The Python code uses dataSize=32, so we use our ror32 helper.
        val = ror32(val, 9);

        // Add the current byte to the rotated hash value.
        // Requirement 3: When XORing/Adding bytes, cast to (unsigned int) first to avoid sign extension.
        // Although `unsigned char` would zero-extend correctly when added to `uint32_t`,
        // explicitly casting to `unsigned int` strictly adheres to the requirement.
        val += (unsigned int)data[i];
    }

    return val; // Return the final 32-bit hash value.
}