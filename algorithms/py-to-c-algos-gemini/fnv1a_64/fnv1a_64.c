#include <stdint.h> // For uint64_t
#include <stddef.h> // For size_t

uint64_t hash(const unsigned char* data, size_t len) {
    // FNV1a 64-bit offset basis
    uint64_t val = 0xcbf29ce484222325ULL;
    // FNV1a 64-bit prime
    const uint64_t FNV_PRIME = 0x100000001b3ULL;

    for (size_t i = 0; i < len; ++i) {
        // XOR the current byte with the hash value.
        // Cast data[i] to uint64_t to ensure proper promotion and avoid sign extension issues,
        // although for unsigned char, implicit promotion would also be safe.
        val ^= (uint64_t)data[i];
        
        // Multiply by the FNV prime.
        // For uint64_t, multiplication naturally wraps around at 2^64,
        // mimicking the Python behavior of masking with 0xffffffffffffffff.
        val *= FNV_PRIME;
    }

    return val;
}