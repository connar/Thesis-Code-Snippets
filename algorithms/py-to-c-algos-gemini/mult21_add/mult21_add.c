#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t acc = 0;

    for (size_t k = 0; k < len; ++k) {
        // Python: acc = 0xffffffff & (acc * 0x21)
        // In C, for uint32_t, multiplication naturally wraps around.
        // Explicit masking ensures strict adherence to Python's behavior.
        acc = (acc * 0x21) & 0xFFFFFFFF;

        // Python: acc = 0xffffffff & (acc + i)
        // Cast data[k] to uint32_t to ensure zero-extension and avoid
        // any potential issues with implicit type promotion, strictly
        // following the requirement to cast to (unsigned int) before adding.
        // The addition also naturally wraps around for uint32_t.
        acc = (acc + (uint32_t)data[k]) & 0xFFFFFFFF;
    }

    return acc;
}