#include <stddef.h> // For size_t
#include <stdint.h> // For uint64_t

uint64_t hash(const unsigned char* data, size_t len) {
    uint64_t val = 0xcbf29ce484222325ULL;
    uint64_t FNV_prime = 0x100000001b3ULL;

    for (size_t i = 0; i < len; ++i) {
        // Multiply by the FNV prime
        val *= FNV_prime;
        // XOR with the current byte, casting to unsigned int as per requirement
        // The unsigned int will then be promoted to uint64_t for the XOR operation
        val ^= ((unsigned int)data[i]);
        // For uint64_t, arithmetic naturally wraps around at 2^64,
        // mimicking the Python behavior of masking with 0xffffffffffffffff.
    }

    return val;
}