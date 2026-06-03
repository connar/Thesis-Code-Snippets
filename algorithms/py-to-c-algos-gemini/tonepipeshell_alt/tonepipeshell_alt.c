#include <stdint.h> // Required for uint32_t, uint64_t, size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t out_hash = 0;
    const uint32_t multiplier = 0x4E44CB31; // The seed constant from the Python code

    for (size_t i = 0; i < len; ++i) {
        // Get the current byte value. Cast to uint32_t to avoid sign extension
        // and ensure it participates in arithmetic as an unsigned 32-bit integer.
        uint32_t current_byte_val = (uint32_t)data[i];

        // The Python code performs multiplication with arbitrary precision
        // before masking. To mimic this, we use uint64_t for intermediate
        // calculations to prevent premature 32-bit overflow.
        uint64_t intermediate_product = (uint64_t)multiplier * out_hash;
        uint64_t intermediate_sum = current_byte_val + intermediate_product;

        // Apply the 0xffffffff mask explicitly, as in the Python code,
        // to ensure the result wraps to 32 bits after the full calculation.
        out_hash = (uint32_t)(intermediate_sum & 0xffffffff);
    }

    return out_hash;
}