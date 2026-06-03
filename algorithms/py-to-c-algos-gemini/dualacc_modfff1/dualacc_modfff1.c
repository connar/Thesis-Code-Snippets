#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t v4 = 0;
    uint32_t v8 = 1;
    const uint32_t MODULO = 0x0FFF1; // 65521

    for (size_t i = 0; i < len; ++i) {
        // data[i] is already an unsigned char.
        // Cast to uint32_t for addition to ensure proper promotion and avoid sign extension issues.
        v8 = ((uint32_t)data[i] + v8) % MODULO;
        v4 = (v4 + v8) % MODULO;
    }

    // The final result is a 32-bit unsigned integer.
    // v4 is shifted left by 16 bits (0x10) and then bitwise OR'd with v8.
    return (v4 << 16) | v8;
}