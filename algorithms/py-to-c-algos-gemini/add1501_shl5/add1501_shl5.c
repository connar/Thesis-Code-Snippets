#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0x1505;
    size_t i;

    for (i = 0; i < len; ++i) {
        // Cast the current byte to uint32_t for arithmetic operations
        // to avoid any potential sign extension issues and ensure 32-bit operations.
        uint32_t ch = (uint32_t)data[i];

        // val += (val << 5)
        val = val + (val << 5);
        // Python explicitly masks to 32-bit after this operation.
        // While uint32_t naturally wraps, this explicit mask mimics Python's behavior.
        val &= 0xFFFFFFFF;

        // val += ch
        val = val + ch;
        // Python explicitly masks to 32-bit after this operation.
        // While uint32_t naturally wraps, this explicit mask mimics Python's behavior.
        val &= 0xFFFFFFFF;
    }
    return val;
}