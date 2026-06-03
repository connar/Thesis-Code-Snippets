#include <stddef.h> // For size_t
#include <stdint.h> // For uint64_t, uint8_t

uint64_t hash(const unsigned char* data, size_t len) {
    uint64_t hsh = 0;
    for (size_t i = 0; i < len; ++i) {
        // Cast data[i] to unsigned int first to avoid any potential sign extension issues
        // during promotion, as per requirement 3.
        // The constant 0x1003f is explicitly made a uint64_t literal (0x1003fULL)
        // to ensure the multiplication 0x1003f * hsh is performed using 64-bit arithmetic.
        // The result of the multiplication will be uint64_t.
        // The (unsigned int)data[i] will then be promoted to uint64_t for the addition.
        // The final result of the addition will be uint64_t, naturally handling 64-bit overflow.
        hsh = (uint64_t)((unsigned int)data[i] + 0x1003fULL * hsh);
    }
    // The Python code explicitly masks the final result with 0xffffffffffffffff.
    // For a uint64_t variable, this mask is technically redundant as 64-bit unsigned
    // integer arithmetic naturally wraps around at 2^64. However, to strictly mimic
    // the Python's final explicit truncation step, we include it.
    return hsh & 0xffffffffffffffffULL;
}