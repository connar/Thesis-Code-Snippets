#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t h = 0x78f1e5bf;
    for (size_t i = 0; i < len; ++i) {
        // Cast data[i] to uint32_t to ensure operations are performed at 32-bit width
        // and avoid potential sign extension issues if 'char' was used or if
        // 'unsigned char' was promoted to a signed int type.
        uint32_t c_val = (uint32_t)data[i];

        // Python: h = (((c ^ h) & 0xffffffff) * 0x5bd1e995) & 0xffffffff
        // In C with uint32_t, the bitwise AND with 0xffffffff is implicit
        // due to the 32-bit unsigned integer arithmetic wrapping around.
        h = (c_val ^ h) * 0x5bd1e995;

        // Python: h = (h ^ ((h >> 15) & 0xffffffff)) & 0xffffffff
        // Similarly, for uint32_t, right shift (>>) is logical and
        // subsequent operations naturally wrap.
        h = h ^ (h >> 15);
    }
    return h;
}