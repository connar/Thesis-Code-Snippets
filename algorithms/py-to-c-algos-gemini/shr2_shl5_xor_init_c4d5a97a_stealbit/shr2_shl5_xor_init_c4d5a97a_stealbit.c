#include <stdint.h> // For uint32_t, uint8_t, size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t func_hash = 0xc4d5a97a;

    for (size_t i = 0; i < len; ++i) {
        uint8_t b = data[i];
        // The core calculation from Python:
        // func_hash ^= ((func_hash >> 2) + ((func_hash << 5) + b)) & 0xFFFFFFFF
        //
        // In C, uint32_t arithmetic naturally wraps around, mimicking the 0xFFFFFFFF mask.
        // However, to strictly adhere to the Python code's explicit masking and the
        // requirement to "mask with 0xFFFFFFFF", we include it.
        // Cast 'b' to uint32_t to ensure unsigned 32-bit arithmetic for the addition,
        // preventing potential sign extension issues.
        func_hash ^= (((func_hash >> 2) + ((func_hash << 5) + (uint32_t)b)) & 0xFFFFFFFF);
    }

    return func_hash;
}