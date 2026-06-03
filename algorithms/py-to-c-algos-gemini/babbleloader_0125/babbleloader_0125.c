#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t final_hash = 0;
    size_t i = 0;

    while (i < len) {
        uint32_t char_orded;
        uint8_t current_byte = data[i];

        if (current_byte < 0x80) { // 1-byte sequence (0xxxxxxx)
            char_orded = current_byte;
            i++;
        } else if ((current_byte & 0xE0) == 0xC0) { // 2-byte sequence (110xxxxx)
            // Check for sufficient bytes and valid continuation byte
            if (i + 1 < len && (data[i+1] & 0xC0) == 0x80) {
                char_orded = ((uint32_t)(current_byte & 0x1F) << 6) | (data[i+1] & 0x3F);
                i += 2;
            } else { // Malformed or incomplete sequence, treat current byte as single byte
                char_orded = current_byte;
                i++;
            }
        } else if ((current_byte & 0xF0) == 0xE0) { // 3-byte sequence (1110xxxx)
            // Check for sufficient bytes and valid continuation bytes
            if (i + 2 < len && (data[i+1] & 0xC0) == 0x80 && (data[i+2] & 0xC0) == 0x80) {
                char_orded = ((uint32_t)(current_byte & 0x0F) << 12) | ((uint32_t)(data[i+1] & 0x3F) << 6) | (data[i+2] & 0x3F);
                i += 3;
            } else { // Malformed or incomplete sequence, treat current byte as single byte
                char_orded = current_byte;
                i++;
            }
        } else if ((current_byte & 0xF8) == 0xF0) { // 4-byte sequence (11110xxx)
            // Check for sufficient bytes and valid continuation bytes
            if (i + 3 < len && (data[i+1] & 0xC0) == 0x80 && (data[i+2] & 0xC0) == 0x80 && (data[i+3] & 0xC0) == 0x80) {
                char_orded = ((uint32_t)(current_byte & 0x07) << 18) | ((uint32_t)(data[i+1] & 0x3F) << 12) | ((uint32_t)(data[i+2] & 0x3F) << 6) | (data[i+3] & 0x3F);
                i += 4;
            } else { // Malformed or incomplete sequence, treat current byte as single byte
                char_orded = current_byte;
                i++;
            }
        } else { // Invalid UTF-8 start byte (e.g., 10xxxxxx, 11111xxx, etc.), treat as single byte
            char_orded = current_byte;
            i++;
        }

        final_hash = (final_hash + char_orded) * (char_orded + 0x1c9943d2);
        // The final_hash is uint32_t, so arithmetic operations naturally wrap around at 2^32,
        // mimicking Python's `&= 0xFFFFFFFF` behavior.
    }

    return final_hash;
}