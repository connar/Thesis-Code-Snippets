#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t hash_value = 0x170F;

    for (size_t i = 0; i < len; ++i) {
        // The core hashing logic:
        // 1. Multiply the current hash_value by 0x21.
        // 2. Add the current byte from the data. The byte is cast to uint32_t
        //    to ensure it's treated as an unsigned 32-bit integer during addition,
        //    preventing any potential sign extension issues.
        // 3. Mask the entire result with 0xFFFFFFFF. This explicitly truncates
        //    the value to a 32-bit unsigned integer, mimicking Python's behavior
        //    where intermediate calculations might exceed 32 bits before the mask.
        hash_value = (hash_value * 0x21 + (uint32_t)data[i]) & 0xFFFFFFFF;
    }

    return hash_value;
}