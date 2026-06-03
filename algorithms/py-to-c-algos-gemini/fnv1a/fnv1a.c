#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0x811c9dc5U; // FNV offset basis

    for (size_t i = 0; i < len; ++i) {
        // data[i] is unsigned char, which is promoted to unsigned int before XORing.
        // The result of (data[i] ^ val) is uint32_t.
        // The multiplication 0x1000193U * (uint32_t result) is performed using uint32_t arithmetic,
        // which naturally wraps around modulo 2^32.
        // The explicit mask & 0xffffffffU ensures strict adherence to the Python behavior
        // of masking the result to 32 bits, even though uint32_t arithmetic already provides this.
        val = (0x1000193U * (data[i] ^ val)) & 0xffffffffU;
    }

    return val;
}