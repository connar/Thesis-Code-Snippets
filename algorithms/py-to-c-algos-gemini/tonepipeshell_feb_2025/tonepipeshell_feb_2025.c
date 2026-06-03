#include <stdint.h> // For uint32_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t out_hash = 0;
    const uint32_t seed = 0x14096BU; // Explicitly unsigned 32-bit constant
    const uint32_t mask = 0xffffffffU; // Explicitly unsigned 32-bit mask

    for (size_t i = 0; i < len; ++i) {
        // Cast the current byte to uint32_t to prevent sign extension
        // and ensure all arithmetic operations are performed with 32-bit unsigned integers.
        // The result of the multiplication and addition will naturally wrap around
        // due to uint32_t arithmetic. The explicit mask mimics Python's behavior.
        out_hash = ((uint32_t)data[i] + (seed * out_hash)) & mask;
    }
    return out_hash;
}