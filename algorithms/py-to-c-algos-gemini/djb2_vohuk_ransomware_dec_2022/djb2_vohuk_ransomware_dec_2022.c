#include <stdint.h>
#include <stddef.h>

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t h = 0x1505;

    for (size_t i = 0; i < len; ++i) {
        // Promote the byte to uint32_t for consistent arithmetic,
        // avoiding potential sign extension issues with `unsigned char` in expressions.
        uint32_t b = (uint32_t)data[i];

        // Python's conditional logic: `if ((b - 0x41) & 0xFFFFFFFF) < 0x20:`
        // This checks if `b` is an uppercase ASCII letter ('A' through 'Z')
        // and converts it to lowercase by adding 0x20.
        // For `uint32_t b`, `b - 0x41` will wrap around if `b < 0x41`,
        // making the comparison `(b - 0x41) < 0x20` correctly identify
        // values in the range [0x41, 0x5A] (A-Z).
        if ((b - 0x41) < 0x20) {
            b += 0x20; // Convert to lowercase
        }

        // Python's main hash calculation: `hash += b + ((0x20 * hash) & 0xFFFFFFFF)`
        // The `& 0xFFFFFFFF` in Python explicitly forces 32-bit unsigned integer behavior.
        // In C, for `uint32_t` variables, arithmetic operations (multiplication and addition)
        // naturally wrap around modulo 2^32, which is equivalent to masking with 0xFFFFFFFF.

        // Calculate the `(0x20 * hash)` term.
        // `0x20U` ensures the multiplication is performed using `uint32_t` types.
        uint32_t product_term = (0x20U * h);

        // Add `b` and `product_term` to `h`.
        // All operands are `uint32_t`, so additions will naturally wrap around.
        h = h + b + product_term;
    }

    return h;
}