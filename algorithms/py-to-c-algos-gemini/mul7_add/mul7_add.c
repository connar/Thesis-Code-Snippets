#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t val = 0x0;

    for (size_t i = 0; i < len; ++i) {
        // Python: val = (val * 0x7) & 0xFFFFFFFF
        // Explicitly mask with 0xFFFFFFFFU to mimic Python's explicit 32-bit truncation.
        // Use 7U to ensure the literal 7 is treated as unsigned.
        val = (val * 7U) & 0xFFFFFFFFU;

        // Python: val = (val + (i & 0xFF)) & 0xFFFFFFFF
        // data[i] is an unsigned char (8-bit). Cast to uint32_t before addition
        // to ensure the operation is performed with 32-bit unsigned integers,
        // then mask to mimic Python's explicit 32-bit truncation.
        val = (val + (uint32_t)data[i]) & 0xFFFFFFFFU;
    }

    return val;
}