#include <stdint.h> // For uint32_t, size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t out = 0x2326;
    for (size_t i = 0; i < len; ++i) {
        // Promote the current byte to uint32_t to ensure correct arithmetic
        // and avoid potential sign extension issues if 'char' were used.
        uint32_t c_val = data[i]; 
        
        // The core hashing logic, mimicking Python's 32-bit wrapping
        // by explicitly masking with 0xffffffff.
        out = (out + c_val + ((out >> 1) | (out << 7))) & 0xffffffff;
    }
    return out;
}