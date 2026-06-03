#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t, uint8_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t generated_hash = 5381U;

    for (size_t i = 0; i < len; ++i) {
        // Get the byte and promote it to uint32_t for calculations
        uint32_t b_val = data[i];

        // Apply the character transformation logic:
        // (b if b < 0x61 else (b - 0x20))
        // This converts lowercase ASCII letters to uppercase.
        uint32_t transformed_b = (b_val < 0x61U) ? b_val : (b_val - 0x20U);

        // Perform the hash calculation, ensuring 32-bit overflow behavior
        // by explicitly masking with 0xFFFFFFFFU, mirroring Python's behavior.
        generated_hash = (generated_hash * 33U + transformed_b) & 0xFFFFFFFFU;
    }

    return generated_hash;
}