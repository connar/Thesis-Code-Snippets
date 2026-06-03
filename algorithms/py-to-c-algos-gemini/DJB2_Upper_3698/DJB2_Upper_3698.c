#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t hash_value = 3698;
    for (size_t i = 0; i < len; ++i) {
        unsigned char current_byte = data[i];
        unsigned char upper_char_val;

        // Custom 'toupper' logic mimicking Python:
        // If byte is a lowercase letter (ASCII 97-122), convert to uppercase (subtract 32).
        // Otherwise, keep the byte as is.
        if (current_byte >= 97 && current_byte <= 122) {
            upper_char_val = current_byte - 32;
        } else {
            upper_char_val = current_byte;
        }

        // Perform the hash calculation: (hash_value * 33 + upper_char_val)
        // To mimic Python's arbitrary precision integers before the 32-bit mask,
        // cast hash_value to uint64_t for the multiplication. This prevents
        // intermediate overflow if (hash_value * 33) exceeds UINT32_MAX.
        // The result of the expression is then masked with 0xFFFFFFFFU to
        // ensure it fits within a 32-bit unsigned integer, matching Python's behavior.
        hash_value = (uint32_t)(((uint64_t)hash_value * 33 + upper_char_val) & 0xFFFFFFFFU);
    }
    return hash_value;
}