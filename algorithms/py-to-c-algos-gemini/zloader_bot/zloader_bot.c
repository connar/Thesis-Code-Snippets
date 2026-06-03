#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t generated_hash = 0;

    for (size_t i = 0; i < len; ++i) {
        uint8_t current_char = data[i];

        // v17 = (current_char + (generated_hash << 4)) & 0xFFFFFFFF
        // Cast current_char to uint32_t to avoid sign extension issues during addition.
        uint32_t v17_intermediate = (uint32_t)current_char + (generated_hash << 4);
        uint32_t v17 = v17_intermediate & 0xFFFFFFFF; // Ensure 32-bit behavior

        // if v17 & 0xF0000000 != 0:
        if ((v17 & 0xF0000000) != 0) {
            // v10 = (v17 & 0xF0000000) >> 0x18
            uint32_t v10 = (v17 & 0xF0000000) >> 24; // 0x18 is 24 in decimal

            // v18 = v17 & 0xFFFFFFFF
            // Since v17 is already a uint32_t and masked, v18 is simply v17.
            uint32_t v18 = v17; 

            // v11 = v18 ^ 0x0FFFFFFF
            uint32_t v11 = v18 ^ 0x0FFFFFFF;

            // generated_hash = (v18 & ~v10) | (v10 & v11)
            generated_hash = (v18 & ~v10) | (v10 & v11);
        } else {
            // generated_hash = v17
            generated_hash = v17;
        }
    }

    return generated_hash;
}