#include <stdint.h> // For uint32_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0;

    for (size_t i = 0; i < len; ++i) {
        // Python's 'c' in 'for c in data' iterates over characters,
        // and 'c' itself represents the integer ordinal value of that character.
        // In C, data[i] directly provides this byte value as an unsigned char.
        // We cast it to uint32_t to ensure all arithmetic operations are performed
        // using 32-bit unsigned integers, mimicking Python's behavior with integers.
        uint32_t c_val = (uint32_t)data[i];

        uint32_t v1 = c_val + val;
        // The Python code explicitly masks with 0xffffffff to ensure 32-bit truncation.
        // While uint32_t arithmetic naturally wraps around at 2^32,
        // this explicit mask is included for strict adherence to the Python algorithm's steps.
        uint32_t v2 = (1025 * v1) & 0xffffffff;
        uint32_t v3 = v2 >> 6;
        val = v2 ^ v3;
    }

    val = (val + val * 8) & 0xffffffff;
    uint32_t r1 = val >> 11;
    uint32_t r2 = val ^ r1;
    uint32_t result = (r2 * 32769) & 0xffffffff;

    return result;
}