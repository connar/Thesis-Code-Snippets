#include <stdint.h> // For uint32_t, size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t h = 8952;

    for (size_t i = 0; i < len; ++i) {
        // Read the byte and promote it to uint32_t for arithmetic operations.
        // This avoids potential sign extension issues if 'char' were used
        // and ensures consistent type for calculations.
        uint32_t current_char_val = data[i];

        // Python's `if c > 96: c -= 0x20` logic
        // This converts ASCII lowercase letters to uppercase.
        // For example, 'a' (97) becomes 'A' (65).
        if (current_char_val > 96) {
            current_char_val -= 0x20;
        }

        // Python's `h = (c + 0x21*h) & 0xFFFFFFFF`
        // In C, for unsigned integer types like uint32_t, arithmetic operations
        // naturally wrap around modulo 2^32. This behavior is equivalent to
        // masking with 0xFFFFFFFF, so an explicit mask is not needed here.
        h = (current_char_val + 0x21 * h);
    }

    return h;
}