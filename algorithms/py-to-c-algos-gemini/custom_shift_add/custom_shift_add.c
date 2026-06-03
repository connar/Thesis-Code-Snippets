#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t, uint8_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t result = 0x733e14f;

    for (size_t i = 0; i < len; ++i) {
        uint8_t val = data[i];
        result = (result << 1) + val;
        result &= 0xffffffff; // Explicitly mask to 32 bits, mimicking Python's behavior
    }

    return result;
}