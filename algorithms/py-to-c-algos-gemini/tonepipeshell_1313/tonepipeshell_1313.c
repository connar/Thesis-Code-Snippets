#include <stddef.h>
#include <stdint.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t out_hash = 0;
    for (size_t i = 0; i < len; ++i) {
        // Cast data[i] to uint32_t to ensure unsigned arithmetic and avoid potential sign extension issues,
        // as per requirement 3, even though unsigned char itself doesn't have sign extension issues.
        // The multiplication 1313 * out_hash will be performed using uint32_t arithmetic,
        // which naturally wraps around.
        // The final & 0xffffffff explicitly mimics Python's 32-bit truncation behavior.
        out_hash = ((uint32_t)data[i] + (uint32_t)1313 * out_hash) & 0xffffffff;
    }
    return out_hash;
}