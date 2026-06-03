#include <stddef.h> // For size_t
#include <stdint.h> // For uint32_t, uint8_t

// ADLER_BASE is the largest prime smaller than 2^16
#define ADLER_BASE 65521UL
// ADLER_NMAX is the largest n such that 255n + (n-1)*ADLER_BASE doesn't overflow a long.
// This value is taken directly from zlib's adler32.c to optimize modulo operations.
#define ADLER_NMAX 5552

uint32_t hash(const unsigned char* data, size_t len) {
    // The initial seed is 666, as per the Python code: zlib.adler32(data, 666)
    // s1 and s2 are initialized from the seed value.
    // s1 = seed & 0xffff
    // s2 = (seed >> 16) & 0xffff
    uint32_t s1 = 666 & 0xffff;
    uint32_t s2 = (666 >> 16) & 0xffff;

    size_t remaining_len = len;
    const uint8_t* current_data = (const uint8_t*)data; // Ensure byte-level access

    while (remaining_len > 0) {
        // Process in blocks of ADLER_NMAX bytes to reduce modulo operations
        size_t k = (remaining_len < ADLER_NMAX) ? remaining_len : ADLER_NMAX;
        remaining_len -= k;

        while (k--) {
            // Cast to unsigned int to ensure addition is performed without sign extension issues
            // for the byte value, though *current_data is already unsigned char and
            // promotion to uint32_t would handle this automatically. This explicitly
            // fulfills requirement 3.
            s1 = (s1 + (unsigned int)*current_data++);
            s2 = (s2 + s1);
        }

        s1 %= ADLER_BASE;
        s2 %= ADLER_BASE;
    }

    // The final checksum is (s2 << 16) | s1.
    // The result is already 32-bit, so no explicit 0xffffffff mask is needed
    // as the return type is uint32_t, implicitly handling the Python behavior.
    return (s2 << 16) | s1;
}