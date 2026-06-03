#include <stdint.h> // Required for uint32_t, uint8_t, size_t

// Helper function for 32-bit right rotation
static uint32_t ror(uint32_t n, unsigned int rotations) {
    return (n >> rotations) | (n << (32 - rotations));
}

// Main hashing algorithm
uint32_t hash(const unsigned char* data, size_t len) {
    // Initial hash value, equivalent to 0xC8B32494 ^ 0 (seed is 0)
    uint32_t result = 0xC8B32494;
    size_t i;

    // Process each byte of the input data
    for (i = 0; i < len; ++i) {
        uint8_t c = data[i];

        // Apply ROR13 to the current result
        result = ror(result, 13);

        // Add the current byte to the result.
        // Casting 'c' to uint32_t ensures the addition is performed
        // as a 32-bit unsigned operation, preventing sign extension
        // and ensuring 32-bit overflow behavior (wrap-around).
        result = result + (uint32_t)c;
    }

    // The Python algorithm appends a null byte (b'\x00') to the string
    // and processes it before breaking. This final step mimics that behavior.
    // Apply ROR13 for the appended null byte
    result = ror(result, 13);
    // Add the null byte (0x00). This doesn't change the value, but the ROR still occurs.
    result = result + (uint32_t)0x00;

    return result;
}