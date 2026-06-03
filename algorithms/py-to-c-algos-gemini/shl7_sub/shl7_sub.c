#include <stdint.h> // For uint32_t, uint8_t
#include <stddef.h> // For size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t eax = 0;
    uint32_t edi;

    for (size_t i = 0; i < len; ++i) {
        // Python: edi = 0xffffffff & (eax << 7)
        // In C, for uint32_t, left shift naturally wraps and discards higher bits.
        edi = eax << 7;

        // Python: eax = 0xffffffff & (edi - eax)
        // In C, for uint32_t, subtraction naturally wraps around modulo 2^32.
        eax = edi - eax;

        // Python: eax = eax + (0xff & i)
        // Cast data[i] to uint32_t as per requirement 3 to ensure correct type promotion
        // and avoid any potential sign extension issues, even though unsigned char is always positive.
        eax = eax + (uint32_t)data[i];
    }

    // Final operations after the loop, mirroring the Python code
    // Python: edi = 0xffffffff & (eax << 7)
    edi = eax << 7;

    // Python: eax = 0xffffffff & (edi - eax)
    eax = edi - eax;

    return eax;
}