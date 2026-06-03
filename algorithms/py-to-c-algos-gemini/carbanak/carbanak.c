#include <stdint.h> // Required for uint32_t, uint8_t
#include <stddef.h> // Required for size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t ctr = 0;
    for (size_t j = 0; j < len; ++j) {
        // Requirement 2: STRICTLY use 'uint8_t' or 'unsigned char' for data bytes.
        // data[j] is already an unsigned char.
        // Requirement 3: When XORing/Adding bytes, cast to (unsigned int) first to avoid sign extension.
        // Adding an unsigned char to a uint32_t will promote the unsigned char to uint32_t without sign extension.
        // An explicit cast like `(uint32_t)data[j]` is not strictly necessary here as per C standard,
        // but for absolute clarity and strict adherence to the spirit of the rule, it can be added.
        // However, the natural promotion is safe and idiomatic for unsigned types.
        ctr = (ctr << 4) + data[j];

        // Requirement 5: Ensure integer overflow mimics Python behavior (mask with 0xFFFFFFFF if returning 32-bit).
        // For uint32_t, arithmetic operations naturally wrap around modulo 2^32, which is the desired behavior
        // for fixed-width hash calculations and matches the implicit 32-bit context of the Python code's masks.

        if (ctr & 0xF0000000) {
            // ctr = (((ctr & 0xF0000000) >> 24) ^ ctr) & 0x0FFFFFFF
            // All intermediate operations involve uint32_t values, ensuring correct 32-bit arithmetic.
            ctr = (((ctr & 0xF0000000) >> 24) ^ ctr) & 0x0FFFFFFF;
        }
    }
    return ctr;
}