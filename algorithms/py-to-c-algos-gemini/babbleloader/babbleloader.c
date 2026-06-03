#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t final_hash = 0;
    size_t i = 0;

    while (i < len) {
        uint32_t char_orded;
        unsigned char current_byte = data[i];
        size_t bytes_read = 0;

        // UTF-8 decoding logic
        if ((current_byte & 0x80) == 0) { // 1-byte character (0xxxxxxx)
            char_orded = current_byte;
            bytes_read = 1;
        } else if ((current_byte & 0xE0) == 0xC0) { // 2-byte character (110xxxxx 10xxxxxx)
            if (i + 1 >= len || (data[i+1] & 0xC0) != 0x80) {
                return 0; // Incomplete or invalid continuation byte
            }
            char_orded = ((uint32_t)(current_byte & 0x1F) << 6) | (data[i+1] & 0x3F);
            bytes_read = 2;
        } else if ((current_byte & 0xF0) == 0xE0) { // 3-byte character (1110xxxx 10xxxxxx 10xxxxxx)
            if (i + 2 >= len || (data[i+1] & 0xC0) != 0x80 || (data[i+2] & 0xC0) != 0x80) {
                return 0; // Incomplete or invalid continuation byte
            }
            char_orded = ((uint32_t)(current_byte & 0x0F) << 12) | ((uint32_t)(data[i+1] & 0x3F) << 6) | (data[i+2] & 0x3F);
            bytes_read = 3;
        } else if ((current_byte & 0xF8) == 0xF0) { // 4-byte character (11110xxx 10xxxxxx 10xxxxxx 10xxxxxx)
            if (i + 3 >= len || (data[i+1] & 0xC0) != 0x80 || (data[i+2] & 0xC0) != 0x80 || (data[i+3] & 0xC0) != 0x80) {
                return 0; // Incomplete or invalid continuation byte
            }
            char_orded = ((uint32_t)(current_byte & 0x07) << 18) | ((uint32_t)(data[i+1] & 0x3F) << 12) | ((uint32_t)(data[i+2] & 0x3F) << 6) | (data[i+3] & 0x3F);
            bytes_read = 4;
        } else {
            // Invalid UTF-8 start byte (e.g., 10xxxxxx, 11111xxx, etc.)
            return 0;
        }

        // Hash calculation, mimicking Python's arbitrary precision then 32-bit truncation
        uint64_t term1 = (uint64_t)final_hash + char_orded;
        uint64_t term2 = (uint64_t)char_orded + 0x4af1e366U; // U suffix ensures unsigned literal
        uint64_t product = term1 * term2;
        final_hash = (uint32_t)(product & 0xFFFFFFFFU); // Mask to get lower 32 bits

        i += bytes_read;
    }

    return final_hash;
}