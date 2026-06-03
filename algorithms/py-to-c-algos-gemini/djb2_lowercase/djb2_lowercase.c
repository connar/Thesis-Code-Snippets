#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t hash_value = 0x624;
    for (size_t i = 0; i < len; ++i) {
        // Get the current character value.
        // Cast to uint32_t to ensure it's treated as an unsigned 32-bit integer
        // for arithmetic, avoiding potential sign extension issues if 'char' were used
        // and promoting 'unsigned char' safely.
        uint32_t current_char_val = (uint32_t)data[i];

        // Check if uppercase ASCII (0x41 'A' to 0x5A 'Z')
        if (current_char_val >= 0x41 && current_char_val <= 0x5A) {
            current_char_val += 0x20; // Convert to lowercase (e.g., 'A' + 0x20 = 'a')
        }

        // Update hash_value using DJB2-like algorithm.
        // The multiplication and addition are performed using uint32_t arithmetic,
        // which naturally wraps around modulo 2^32.
        // The explicit & 0xFFFFFFFF makes the 32-bit wrapping explicit,
        // mimicking Python's behavior and satisfying the requirement.
        hash_value = (hash_value * 33 + current_char_val) & 0xFFFFFFFF;
    }
    return hash_value;
}