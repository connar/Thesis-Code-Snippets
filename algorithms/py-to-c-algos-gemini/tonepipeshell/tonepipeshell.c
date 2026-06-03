#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t out_hash = 0;
    const uint32_t seed = 0xC85E31;

    for (size_t i = 0; i < len; ++i) {
        // Cast data[i] to uint32_t to ensure the addition is performed with 32-bit unsigned integers
        // and to explicitly avoid any potential sign extension issues, as per requirements.
        // The multiplication `seed * out_hash` naturally wraps around 2^32 due to uint32_t arithmetic.
        // The final `& 0xffffffff` explicitly masks the result to 32 bits, mimicking Python's behavior.
        out_hash = ((uint32_t)data[i] + seed * out_hash) & 0xffffffff;
    }

    return out_hash;
}