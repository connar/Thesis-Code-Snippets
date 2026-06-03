#include <stdint.h> // For uint32_t, uint8_t, size_t

uint32_t hash(const unsigned char* data, size_t len) {
    uint32_t v15 = 0x5B2D;
    uint32_t hash_val = 0;
    size_t API_buffer_count = 0;

    // Process 4-byte chunks
    // Equivalent to Python's `if len(data) >= 4:` block
    if (len >= 4) {
        size_t count = len >> 2; // Number of 4-byte chunks

        while (count != 0) {
            // Read 4 bytes as a little-endian 32-bit integer
            // Cast data[idx] to uint32_t before shifting to prevent sign extension
            uint32_t temp_buffer_val =
                ((uint32_t)data[API_buffer_count + 3] << 24) |
                ((uint32_t)data[API_buffer_count + 2] << 16) |
                ((uint32_t)data[API_buffer_count + 1] << 8) |
                ((uint32_t)data[API_buffer_count]);

            // Python's `(0x5BD1E995 * temp_buffer_val) & 0xFFFFFFFF`
            // In C, uint32_t multiplication naturally wraps at 2^32,
            // effectively performing the `& 0xFFFFFFFF` mask.
            uint32_t temp = 0x5BD1E995U * temp_buffer_val;
            API_buffer_count += 4;

            // Python's `((0x5BD1E995 * (temp ^ (temp >> 0x18))) & 0xFFFFFFFF) ^ ((0x5BD1E995 * v15) & 0xFFFFFFFF)`
            v15 = (0x5BD1E995U * (temp ^ (temp >> 24))) ^ (0x5BD1E995U * v15);
            count--;
        }
    }

    // Handle remaining bytes (0 to 3)
    // Equivalent to Python's `v18 = string_length_2 - 1` block
    size_t remaining_bytes = len % 4;

    if (remaining_bytes == 1) {
        hash_val ^= (uint32_t)data[API_buffer_count];
    } else if (remaining_bytes == 2) {
        hash_val ^= ((uint32_t)data[API_buffer_count + 1] << 8);
        hash_val ^= (uint32_t)data[API_buffer_count];
    } else if (remaining_bytes == 3) {
        hash_val ^= ((uint32_t)data[API_buffer_count + 2] << 16);
        hash_val ^= ((uint32_t)data[API_buffer_count + 1] << 8);
        hash_val ^= (uint32_t)data[API_buffer_count];
    }

    // Finalization steps
    uint32_t v20, edi, eax, ecx, edx;

    // Python's `(0x5BD1E995 * hash_val) & 0xFFFFFFFF`
    v20 = 0x5BD1E995U * hash_val;
    // Python's `(0x5BD1E995 * len(data)) & 0xFFFFFFFF`
    // Cast `len` to `uint32_t` to ensure 32-bit multiplication and wrapping.
    edi = 0x5BD1E995U * (uint32_t)len;

    eax = v20 >> 24; // 0x18 is 24
    eax ^= v20;

    ecx = 0x5BD1E995U * eax;
    eax = 0x5BD1E995U * v15;

    ecx ^= eax;

    eax = edi;
    eax >>= 24; // 0x18 is 24
    eax ^= edi;

    edx = 0x5BD1E995U * ecx;
    eax = 0x5BD1E995U * eax;
    edx ^= eax;
    eax = edx;

    eax >>= 13; // 0xD is 13
    eax ^= edx;

    ecx = 0x5BD1E995U * eax;
    eax = ecx;
    eax >>= 15; // 0xF is 15
    eax ^= ecx;

    return eax;
}