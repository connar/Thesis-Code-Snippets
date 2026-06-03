#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t hash_value = 0;
    for (size_t i = 0; i < len; ++i) {
        // The operations are performed using uint32_t arithmetic,
        // which naturally handles the 32-bit wrapping behavior
        // equivalent to Python's '& 0xffffffff' mask.
        // data[i] is cast to uint32_t to ensure unsigned integer promotion
        // and avoid potential sign extension issues as per requirement 3.
        hash_value = ((hash_value << 16) + (hash_value << 6) + (uint32_t)data[i] - hash_value);
    }
    return hash_value;
}