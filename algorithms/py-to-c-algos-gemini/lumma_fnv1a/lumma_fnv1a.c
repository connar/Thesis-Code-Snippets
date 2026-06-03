#include <stdint.h> // For uint32_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0x268c190a;
    for (size_t i = 0; i < len; ++i) {
        // Cast data[i] to uint32_t to ensure the XOR operation is performed
        // with a 32-bit unsigned integer, preventing potential sign extension issues
        // if 'unsigned char' were promoted to a signed type.
        // The multiplication result will naturally wrap around due to 'val' being uint32_t,
        // mimicking Python's 0xffffffff masking behavior.
        val = ((val ^ (uint32_t)data[i]) * 0x1000193);
    }
    return val;
}