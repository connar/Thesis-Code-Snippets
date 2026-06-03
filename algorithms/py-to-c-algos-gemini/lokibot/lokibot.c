#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t hash_value = 0xFFFFFFFFU;

    for (size_t i = 0; i < len; ++i) {
        // Requirement 3: Cast to (uint32_t) before XORing to avoid sign extension.
        hash_value ^= (uint32_t)data[i];

        for (int j = 0; j < 8; ++j) {
            if (hash_value & 1U) {
                hash_value ^= 0x4358AD54U;
            }
            hash_value >>= 1;
        }
    }

    // Requirement 5: Ensure integer overflow mimics Python behavior (mask with 0xFFFFFFFF).
    // The mask 0xFFFFFFFFU is technically redundant for a uint32_t return type,
    // but it strictly adheres to the Python code's explicit masking.
    return (~hash_value) & 0xFFFFFFFFU;
}