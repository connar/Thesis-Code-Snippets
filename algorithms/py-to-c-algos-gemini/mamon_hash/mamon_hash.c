#include <stdint.h> // For uint32_t, size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t hash_value = 0x42;

    for (size_t i = 0; i < len; ++i) {
        // Cast the current byte to uint32_t before addition.
        // This ensures zero-extension and that the addition is performed
        // using 32-bit unsigned arithmetic, mimicking Python's behavior
        // where 'b' is treated as a positive integer.
        hash_value = (hash_value * 33) + (uint32_t)data[i];
        
        // The uint32_t type naturally handles overflow by wrapping around
        // modulo 2^32, which is equivalent to Python's '& 0xFFFFFFFF'
        // for keeping the value within 32 bits.
    }

    return hash_value;
}