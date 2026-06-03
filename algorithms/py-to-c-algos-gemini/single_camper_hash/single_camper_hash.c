#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

// Function to perform 32-bit right rotation
static uint32_t ror(uint32_t val, int bits) {
    return (val >> bits) | (val << (32 - bits));
}

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t h = 0xAE54C677;
    uint32_t result = 0;

    for (size_t i = 0; i < len; ++i) {
        // Get the current byte from data
        uint8_t c_byte = data[i];
        // Cast the byte to uint32_t for arithmetic operations to avoid sign extension
        // and ensure 32-bit unsigned arithmetic.
        uint32_t c = (uint32_t)c_byte;

        // temp = ((c + h) * 0xBF2E2729) & 0xFFFFFFFF
        // uint32_t arithmetic naturally handles the 0xFFFFFFFF wrap-around
        uint32_t temp = (c + h) * 0xBF2E2729;

        // temp = (ror(temp, 17) + 0xBF2E2729 + h) & 0xFFFFFFFF
        temp = ror(temp, 17) + 0xBF2E2729 + h;

        // h = (ror(temp, 15) * c) & 0xFFFFFFFF
        h = ror(temp, 15) * c;

        // doubled = (2 * h) & 0xFFFFFFFF
        uint32_t doubled = 2 * h;

        // result = ror(doubled, 16)
        result = ror(doubled, 16);

        // h = ror(doubled, 14)
        h = ror(doubled, 14);
    }
    return result;
}