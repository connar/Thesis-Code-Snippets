#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t hash_value = 4919;
    size_t i;

    for (i = 0; i < len; ++i) {
        // Cast the byte to uint32_t to avoid sign extension issues
        uint32_t current_char_val = (uint32_t)data[i];

        // Python's lowercase to uppercase conversion logic
        // if ord('a') <= ord(char) <= ord('z'):
        //     char = chr(ord(char) - 32)
        if (current_char_val >= (uint32_t)'a' && current_char_val <= (uint32_t)'z') {
            current_char_val -= 32; // Convert to uppercase (e.g., 'a' - 32 = 'A')
        }
        
        // DJB2-like hash update
        hash_value = (hash_value * 33) + current_char_val;
        // For uint32_t, integer overflow implicitly handles the & 0xFFFFFFFF masking.
    }

    return hash_value;
}